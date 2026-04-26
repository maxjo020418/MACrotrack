#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

extern "C" {
  #include "esp_wifi.h"
}

#include "driver/spi_master.h"

#if __has_include("secrets.h")
  #include "secrets.h"
#endif

#ifndef WIFI_SSID
  #define WIFI_SSID ""
#endif

#ifndef WIFI_PASS
  #define WIFI_PASS ""
#endif

#ifndef DEVICE_ID
  #define DEVICE_ID "sender-001"
#endif

#ifndef API_TOKEN
  #define API_TOKEN ""
#endif

#ifndef UPLOAD_URL
  #define UPLOAD_URL "http://127.0.0.1:8080/api/sniff/batch"
#endif

#ifndef UPLOAD_ENABLED
  #define UPLOAD_ENABLED 0
#endif

#ifndef HTTP_TLS_INSECURE
  #define HTTP_TLS_INSECURE 0
#endif

#ifndef DEBUG_PRINT_RECORDS
  #define DEBUG_PRINT_RECORDS 1
#endif

// shared SPI bus
static constexpr int PIN_SPI_SCLK = 18;
static constexpr int PIN_SPI_MISO = 19;
static constexpr int PIN_SPI_MOSI = 23;

// one CS output per sniffer
static constexpr int PIN_CS_SNIFFER1 = 25;
static constexpr int PIN_CS_SNIFFER2 = 26;

// one READY input per sniffer
static constexpr int PIN_RDY_SNIFFER1 = 32;
static constexpr int PIN_RDY_SNIFFER2 = 33;

static constexpr spi_host_device_t SPI_HOST_DEVICE = SPI3_HOST;
static constexpr uint32_t RECORD_MAGIC = 0x534E4946UL;  // "SNIF" numeric magic
static constexpr uint32_t STATUS_MAGIC = 0x53544154UL;  // "STAT" numeric magic
static constexpr uint16_t PROTOCOL_VERSION = 1;
static constexpr uint32_t BATCH_MAGIC = 0x534E5042UL;  // "SNPB" numeric magic
static constexpr uint16_t BATCH_VERSION = 1;
static constexpr size_t RECORD_HEADER_BYTES = 24;
static constexpr size_t MAX_FRAME_BYTES = 512;
static constexpr size_t SPI_TRANSFER_BYTES = RECORD_HEADER_BYTES + MAX_FRAME_BYTES;
static constexpr uint32_t SPI_CLOCK_HZ = 10000000;  // 10Mhz
static constexpr uint32_t READY_TIMEOUT_MS = 500;
static constexpr uint32_t READY_REARM_TIMEOUT_MS = 250;
static constexpr uint32_t STATUS_PRINT_INTERVAL_MS = 2000;
static constexpr uint32_t UPLOAD_STATUS_INTERVAL_MS = 5000;
static constexpr size_t UPLOAD_QUEUE_CAPACITY = 64;
static constexpr size_t MAX_HTTP_BATCH_BYTES = 8192;
static constexpr uint32_t MAX_BATCH_RECORDS = 32;
static constexpr uint32_t FLUSH_INTERVAL_MS = 1000;
static constexpr uint32_t WIFI_CONNECT_TIMEOUT_MS = 15000;
static constexpr uint32_t WIFI_RECONNECT_INTERVAL_MS = 5000;
static constexpr uint16_t HTTP_TIMEOUT_MS = 8000;

static constexpr uint16_t FLAG_TRUNCATED = 1 << 0;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t header_len;
  uint32_t seq;
  uint32_t ts_us;
  int8_t rssi;
  uint8_t channel;
  uint16_t frame_len;
  uint16_t flags;
  uint16_t crc16;
} sniff_record_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t header_len;
  uint32_t packets_captured;
  uint32_t records_queued;
  uint32_t records_dropped;
  uint32_t spi_send_failures;
  uint16_t queue_depth;
  uint16_t max_queue_depth;
  uint32_t status_packets;
  uint32_t wifi_init_error;
  uint8_t wifi_ready;
  uint8_t reserved[3];
} status_packet_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;        // 0x534E5042 = "SNPB"
  uint16_t version;      // 1
  uint16_t header_len;   // sizeof(batch_header_t)
  uint32_t batch_seq;
  uint32_t record_count;
  uint32_t payload_len;  // bytes after this header
  uint32_t uptime_ms;
  uint32_t flags;
} batch_header_t;

typedef struct __attribute__((packed)) {
  uint16_t source_id;    // sender-local sniffer ID, e.g. 1 for sniffer1
  uint16_t record_len;   // sniff_record_t + frame_len
} upload_record_prefix_t;

static_assert(sizeof(sniff_record_t) == RECORD_HEADER_BYTES, "unexpected record header size");

struct SnifferLink {
  const char* name;
  uint16_t sourceId;
  int csPin;
  int readyPin;
  bool enabled;
  spi_device_handle_t device;
  uint32_t recordsReceived;
  uint32_t crcErrors;
  uint32_t badPackets;
  uint32_t spiErrors;
  uint32_t readyTimeouts;
  uint32_t lastStatusPrintMs;
};

static SnifferLink sniffers[] = {
  {"sniffer1", 1, PIN_CS_SNIFFER1, PIN_RDY_SNIFFER1, true, nullptr, 0, 0, 0, 0, 0, 0},
  {"sniffer2", 2, PIN_CS_SNIFFER2, PIN_RDY_SNIFFER2, false, nullptr, 0, 0, 0, 0, 0, 0},
};

DRAM_ATTR static uint8_t txBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));
DRAM_ATTR static uint8_t rxBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));

struct UploadRecord {
  uint16_t sourceId;
  uint16_t recordLen;
  uint32_t queuedMs;
  sniff_record_t header;
  uint8_t frame[MAX_FRAME_BYTES];
};

static SemaphoreHandle_t uploadQueueMutex = nullptr;
static UploadRecord uploadQueue[UPLOAD_QUEUE_CAPACITY];
static size_t uploadQueueHead = 0;
static size_t uploadQueueCount = 0;
static uint16_t uploadQueueMaxDepth = 0;

DRAM_ATTR static uint8_t uploadBatchBuf[MAX_HTTP_BATCH_BYTES] __attribute__((aligned(4)));

static uint32_t uploadRecordsQueued = 0;
static uint32_t uploadRecordsDropped = 0;
static uint32_t uploadRecordsBatched = 0;
static uint32_t uploadBatchesBuilt = 0;
static uint32_t uploadDryRunBatches = 0;
static uint32_t httpAttempts = 0;
static uint32_t httpSuccesses = 0;
static uint32_t httpFailures = 0;
static uint32_t uploadBytesSent = 0;
static uint32_t uploadBytesDryRun = 0;
static uint32_t uploadBatchSeq = 1;
static uint32_t lastUploadStatusMs = 0;

static uint16_t get16(const uint8_t* buf, size_t offset) {
  return static_cast<uint16_t>(buf[offset]) |
         (static_cast<uint16_t>(buf[offset + 1]) << 8);
}

static uint32_t get32(const uint8_t* buf, size_t offset) {
  return static_cast<uint32_t>(buf[offset]) |
         (static_cast<uint32_t>(buf[offset + 1]) << 8) |
         (static_cast<uint32_t>(buf[offset + 2]) << 16) |
         (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

static uint16_t crc16CcittFalse(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; ++i) {
    crc ^= static_cast<uint16_t>(data[i]) << 8;
    for (uint8_t bit = 0; bit < 8; ++bit) {
      if ((crc & 0x8000) != 0) {
        crc = static_cast<uint16_t>((crc << 1) ^ 0x1021);
      } else {
        crc = static_cast<uint16_t>(crc << 1);
      }
    }
  }
  return crc;
}

static bool takeUploadMutex(TickType_t ticks = portMAX_DELAY) {
  return uploadQueueMutex != nullptr && xSemaphoreTake(uploadQueueMutex, ticks) == pdTRUE;
}

static void giveUploadMutex() {
  if (uploadQueueMutex != nullptr) {
    xSemaphoreGive(uploadQueueMutex);
  }
}

static size_t serializedRecordBytes(const UploadRecord& record) {
  return sizeof(upload_record_prefix_t) + record.recordLen;
}

static void enqueueUploadRecord(const SnifferLink& sniffer, const sniff_record_t& record, const uint8_t* frame) {
  if (record.frame_len > MAX_FRAME_BYTES || uploadQueueMutex == nullptr) {
    return;
  }

  if (!takeUploadMutex()) {
    return;
  }

  if (uploadQueueCount == UPLOAD_QUEUE_CAPACITY) {
    uploadQueueHead = (uploadQueueHead + 1) % UPLOAD_QUEUE_CAPACITY;
    --uploadQueueCount;
    ++uploadRecordsDropped;
  }

  const size_t writeIndex = (uploadQueueHead + uploadQueueCount) % UPLOAD_QUEUE_CAPACITY;
  UploadRecord& queued = uploadQueue[writeIndex];
  queued.sourceId = sniffer.sourceId;
  queued.recordLen = static_cast<uint16_t>(sizeof(sniff_record_t) + record.frame_len);
  queued.queuedMs = millis();
  queued.header = record;
  memcpy(queued.frame, frame, record.frame_len);

  ++uploadQueueCount;
  ++uploadRecordsQueued;
  if (uploadQueueCount > uploadQueueMaxDepth) {
    uploadQueueMaxDepth = static_cast<uint16_t>(uploadQueueCount);
  }

  giveUploadMutex();
}

static bool getUploadQueueSnapshot(size_t* depth, uint32_t* oldestAgeMs) {
  if (!takeUploadMutex(pdMS_TO_TICKS(10))) {
    return false;
  }

  const size_t count = uploadQueueCount;
  *depth = count;
  if (count == 0) {
    *oldestAgeMs = 0;
  } else {
    *oldestAgeMs = millis() - uploadQueue[uploadQueueHead].queuedMs;
  }

  giveUploadMutex();
  return true;
}

static bool shouldFlushUploadQueue() {
  size_t depth = 0;
  uint32_t oldestAgeMs = 0;
  if (!getUploadQueueSnapshot(&depth, &oldestAgeMs)) {
    return false;
  }

  return depth >= MAX_BATCH_RECORDS || (depth > 0 && oldestAgeMs >= FLUSH_INTERVAL_MS);
}

static bool buildUploadBatch(size_t* batchBytes, uint32_t* batchSeq, uint32_t* recordCount) {
  *batchBytes = 0;
  *batchSeq = 0;
  *recordCount = 0;

  if (!takeUploadMutex(pdMS_TO_TICKS(100))) {
    return false;
  }

  if (uploadQueueCount == 0) {
    giveUploadMutex();
    return false;
  }

  batch_header_t header = {};
  header.magic = BATCH_MAGIC;
  header.version = BATCH_VERSION;
  header.header_len = sizeof(batch_header_t);
  header.batch_seq = uploadBatchSeq++;
  header.uptime_ms = millis();

  size_t offset = sizeof(batch_header_t);
  uint32_t records = 0;

  while (uploadQueueCount > 0 && records < MAX_BATCH_RECORDS) {
    const UploadRecord& record = uploadQueue[uploadQueueHead];
    const size_t bytesNeeded = serializedRecordBytes(record);
    if ((offset + bytesNeeded) > MAX_HTTP_BATCH_BYTES) {
      break;
    }

    upload_record_prefix_t prefix = {};
    prefix.source_id = record.sourceId;
    prefix.record_len = record.recordLen;
    memcpy(uploadBatchBuf + offset, &prefix, sizeof(prefix));
    offset += sizeof(prefix);
    memcpy(uploadBatchBuf + offset, &record.header, sizeof(record.header));
    offset += sizeof(record.header);
    memcpy(uploadBatchBuf + offset, record.frame, record.header.frame_len);
    offset += record.header.frame_len;

    uploadQueueHead = (uploadQueueHead + 1) % UPLOAD_QUEUE_CAPACITY;
    --uploadQueueCount;
    ++records;
  }

  if (records == 0) {
    giveUploadMutex();
    return false;
  }

  header.record_count = records;
  header.payload_len = static_cast<uint32_t>(offset - sizeof(batch_header_t));
  memcpy(uploadBatchBuf, &header, sizeof(header));

  ++uploadBatchesBuilt;
  uploadRecordsBatched += records;

  *batchBytes = offset;
  *batchSeq = header.batch_seq;
  *recordCount = records;

  giveUploadMutex();
  return true;
}

static bool waitReadyLevel(const SnifferLink& sniffer, uint8_t level, uint32_t timeoutMs) {
  const uint32_t started = millis();
  while (digitalRead(sniffer.readyPin) != level) {
    if ((millis() - started) >= timeoutMs) {
      return false;
    }
    delayMicroseconds(50);
  }
  return true;
}

static bool waitForSlaveRearm(SnifferLink& sniffer) {
  if (!waitReadyLevel(sniffer, LOW, READY_REARM_TIMEOUT_MS)) {
    ++sniffer.readyTimeouts;
    Serial.printf("%s READY did not drop after transfer\n", sniffer.name);
    return false;
  }

  if (!waitReadyLevel(sniffer, HIGH, READY_TIMEOUT_MS)) {
    ++sniffer.readyTimeouts;
    Serial.printf("%s timeout waiting for READY on GPIO%d\n", sniffer.name, sniffer.readyPin);
    return false;
  }

  return true;
}

static const char* mgmtSubtypeName(uint8_t subtype) {
  switch (subtype) {
    case 0:
      return "assoc_req";
    case 1:
      return "assoc_resp";
    case 2:
      return "reassoc_req";
    case 3:
      return "reassoc_resp";
    case 4:
      return "probe_req";
    case 5:
      return "probe_resp";
    case 8:
      return "beacon";
    case 9:
      return "atim";
    case 10:
      return "disassoc";
    case 11:
      return "auth";
    case 12:
      return "deauth";
    case 13:
      return "action";
    default:
      return "mgmt";
  }
}

static void formatMac(const uint8_t* mac, char* out, size_t outLen) {
  snprintf(out,
           outLen,
           "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0],
           mac[1],
           mac[2],
           mac[3],
           mac[4],
           mac[5]);
}

static size_t ieOffsetForSubtype(uint8_t subtype) {
  switch (subtype) {
    case 0:   // association request: capability + listen interval
      return 28;
    case 1:   // association response: capability + status + AID
      return 30;
    case 2:   // reassociation request: association request fixed fields + current AP
      return 34;
    case 3:   // reassociation response
      return 30;
    case 4:   // probe request
      return 24;
    case 5:   // probe response: timestamp + beacon interval + capability
    case 8:   // beacon: timestamp + beacon interval + capability
      return 36;
    default:
      return 0;
  }
}

static void extractSsid(const uint8_t* frame, size_t frameLen, uint8_t subtype, char* out, size_t outLen) {
  out[0] = '\0';
  const size_t ieOffset = ieOffsetForSubtype(subtype);
  if (ieOffset == 0 || ieOffset >= frameLen) {
    return;
  }

  size_t pos = ieOffset;
  while ((pos + 2) <= frameLen) {
    const uint8_t id = frame[pos];
    const uint8_t len = frame[pos + 1];
    pos += 2;
    if ((pos + len) > frameLen) {
      return;
    }

    if (id == 0) {
      const size_t copyLen = min(static_cast<size_t>(len), outLen - 1);
      for (size_t i = 0; i < copyLen; ++i) {
        const uint8_t c = frame[pos + i];
        out[i] = (c >= 32 && c <= 126) ? static_cast<char>(c) : '.';
      }
      out[copyLen] = '\0';
      return;
    }

    pos += len;
  }
}

static void printRecord(SnifferLink& sniffer, const sniff_record_t& record, const uint8_t* frame) {
  const uint16_t frameControl = get16(frame, 0);
  const uint8_t frameType = static_cast<uint8_t>((frameControl >> 2) & 0x03);
  const uint8_t subtype = static_cast<uint8_t>((frameControl >> 4) & 0x0F);

  char addr1[18] = "--:--:--:--:--:--";
  char addr2[18] = "--:--:--:--:--:--";
  char addr3[18] = "--:--:--:--:--:--";
  if (record.frame_len >= 24) {
    formatMac(frame + 4, addr1, sizeof(addr1));
    formatMac(frame + 10, addr2, sizeof(addr2));
    formatMac(frame + 16, addr3, sizeof(addr3));
  }

  char ssid[33] = "";
  extractSsid(frame, record.frame_len, subtype, ssid, sizeof(ssid));

  Serial.printf("%s seq=%lu ts=%lu ch=%u rssi=%d type=%u/%s len=%u%s src=%s dst=%s bssid=%s",
                sniffer.name,
                record.seq,
                record.ts_us,
                record.channel,
                record.rssi,
                frameType,
                mgmtSubtypeName(subtype),
                record.frame_len,
                (record.flags & FLAG_TRUNCATED) != 0 ? " truncated" : "",
                addr2,
                addr1,
                addr3);

  if (ssid[0] != '\0') {
    Serial.printf(" ssid=\"%s\"", ssid);
  }

  Serial.println();
}

static void handleRecord(SnifferLink& sniffer) {
  sniff_record_t record = {};
  memcpy(&record, rxBuf, sizeof(record));

  if (record.version != PROTOCOL_VERSION ||
      record.header_len != sizeof(sniff_record_t) ||
      record.frame_len > MAX_FRAME_BYTES ||
      (sizeof(sniff_record_t) + record.frame_len) > SPI_TRANSFER_BYTES) {
    ++sniffer.badPackets;
    Serial.printf("%s bad SNIF header: version=%u header_len=%u frame_len=%u\n",
                  sniffer.name,
                  record.version,
                  record.header_len,
                  record.frame_len);
    return;
  }

  const uint8_t* frame = rxBuf + sizeof(sniff_record_t);
  const uint16_t crc = crc16CcittFalse(frame, record.frame_len);
  if (crc != record.crc16) {
    ++sniffer.crcErrors;
    Serial.printf("%s CRC error seq=%lu got=0x%04X expected=0x%04X len=%u\n",
                  sniffer.name,
                  record.seq,
                  crc,
                  record.crc16,
                  record.frame_len);
    return;
  }

  ++sniffer.recordsReceived;
  enqueueUploadRecord(sniffer, record, frame);

#if DEBUG_PRINT_RECORDS
  printRecord(sniffer, record, frame);
#endif
}

static void handleStatus(SnifferLink& sniffer) {
  status_packet_t status = {};
  memcpy(&status, rxBuf, min(sizeof(status), sizeof(rxBuf)));

  const uint32_t now = millis();
  if ((now - sniffer.lastStatusPrintMs) < STATUS_PRINT_INTERVAL_MS) {
    return;
  }
  sniffer.lastStatusPrintMs = now;

  Serial.printf("%s status: wifi=%s wifi_err=%lu captured=%lu queued=%lu dropped=%lu depth=%u max_depth=%u spi_fail=%lu records_rx=%lu crc_err=%lu bad=%lu\n",
                sniffer.name,
                status.wifi_ready != 0 ? "ok" : "not_ready",
                status.wifi_init_error,
                status.packets_captured,
                status.records_queued,
                status.records_dropped,
                status.queue_depth,
                status.max_queue_depth,
                status.spi_send_failures,
                sniffer.recordsReceived,
                sniffer.crcErrors,
                sniffer.badPackets);
}

static void handlePacket(SnifferLink& sniffer) {
  const uint32_t magic = get32(rxBuf, 0);
  if (magic == RECORD_MAGIC) {
    handleRecord(sniffer);
    return;
  }

  if (magic == STATUS_MAGIC) {
    handleStatus(sniffer);
    return;
  }

  ++sniffer.badPackets;
  Serial.printf("%s bad SPI packet magic=0x%08lX\n", sniffer.name, magic);
}

static bool pollSniffer(SnifferLink& sniffer) {
  if (!waitReadyLevel(sniffer, HIGH, READY_TIMEOUT_MS)) {
    ++sniffer.readyTimeouts;
    Serial.printf("%s not ready on GPIO%d\n", sniffer.name, sniffer.readyPin);
    return false;
  }

  memset(txBuf, 0, sizeof(txBuf));
  memset(rxBuf, 0, sizeof(rxBuf));

  spi_transaction_t transaction = {};
  transaction.length = SPI_TRANSFER_BYTES * 8;
  transaction.tx_buffer = txBuf;
  transaction.rx_buffer = rxBuf;

  const esp_err_t err = spi_device_transmit(sniffer.device, &transaction);
  if (err != ESP_OK) {
    ++sniffer.spiErrors;
    Serial.printf("%s spi_device_transmit failed: %d\n", sniffer.name, static_cast<int>(err));
    return false;
  }

  waitForSlaveRearm(sniffer);
  handlePacket(sniffer);
  return true;
}

static bool uploadUrlIsHttps() {
  return strncmp(UPLOAD_URL, "https://", 8) == 0;
}

static bool uploadConfigLooksUsable() {
  return strlen(WIFI_SSID) > 0 &&
         strlen(UPLOAD_URL) > 0 &&
         strcmp(UPLOAD_URL, "https://example.com/api/sniff/batch") != 0;
}

static bool ensureWifiConnected() {
#if UPLOAD_ENABLED
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  static uint32_t lastAttemptMs = 0;
  const uint32_t now = millis();
  if ((now - lastAttemptMs) < WIFI_RECONNECT_INTERVAL_MS) {
    return false;
  }
  lastAttemptMs = now;

  if (!uploadConfigLooksUsable()) {
    Serial.println("upload config missing WIFI_SSID or UPLOAD_URL");
    return false;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  const uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - started) < WIFI_CONNECT_TIMEOUT_MS) {
    delay(250);
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("WiFi connected for upload: ip=%s rssi=%d\n",
                  WiFi.localIP().toString().c_str(),
                  WiFi.RSSI());
    return true;
  }

  Serial.println("WiFi upload connect timed out");
  return false;
#else
  return false;
#endif
}

static bool postBatch(const uint8_t* data, size_t len, uint32_t batchSeq, uint32_t recordCount) {
#if !UPLOAD_ENABLED
  ++uploadDryRunBatches;
  uploadBytesDryRun += static_cast<uint32_t>(len);
  Serial.printf("upload dry-run: batch=%lu records=%lu bytes=%u queued=%lu dropped=%lu\n",
                batchSeq,
                recordCount,
                static_cast<unsigned>(len),
                uploadRecordsQueued,
                uploadRecordsDropped);
  return true;
#else
  ++httpAttempts;

  if (!ensureWifiConnected()) {
    ++httpFailures;
    return false;
  }

  HTTPClient http;
  int responseCode = -1;
  bool began = false;

  if (uploadUrlIsHttps()) {
    WiFiClientSecure client;
#if HTTP_TLS_INSECURE
    client.setInsecure();
#endif
    began = http.begin(client, UPLOAD_URL);
    if (began) {
      http.setTimeout(HTTP_TIMEOUT_MS);
      http.addHeader("Content-Type", "application/octet-stream");
      if (strlen(API_TOKEN) > 0) {
        String bearer = "Bearer ";
        bearer += API_TOKEN;
        http.addHeader("Authorization", bearer);
      }
      http.addHeader("X-Device-Id", DEVICE_ID);
      http.addHeader("X-Batch-Version", String(BATCH_VERSION));
      http.addHeader("X-Batch-Seq", String(batchSeq));
      http.addHeader("X-Record-Count", String(recordCount));
      responseCode = http.POST(const_cast<uint8_t*>(data), len);
      http.end();
    }
  } else {
    WiFiClient client;
    began = http.begin(client, UPLOAD_URL);
    if (began) {
      http.setTimeout(HTTP_TIMEOUT_MS);
      http.addHeader("Content-Type", "application/octet-stream");
      if (strlen(API_TOKEN) > 0) {
        String bearer = "Bearer ";
        bearer += API_TOKEN;
        http.addHeader("Authorization", bearer);
      }
      http.addHeader("X-Device-Id", DEVICE_ID);
      http.addHeader("X-Batch-Version", String(BATCH_VERSION));
      http.addHeader("X-Batch-Seq", String(batchSeq));
      http.addHeader("X-Record-Count", String(recordCount));
      responseCode = http.POST(const_cast<uint8_t*>(data), len);
      http.end();
    }
  }

  if (!began) {
    ++httpFailures;
    Serial.println("HTTP begin failed");
    return false;
  }

  if (responseCode >= 200 && responseCode < 300) {
    ++httpSuccesses;
    uploadBytesSent += static_cast<uint32_t>(len);
    return true;
  }

  ++httpFailures;
  Serial.printf("HTTP upload failed: code=%d batch=%lu records=%lu bytes=%u\n",
                responseCode,
                batchSeq,
                recordCount,
                static_cast<unsigned>(len));
  return false;
#endif
}

static void uploadTask(void*) {
  while (true) {
    if (!shouldFlushUploadQueue()) {
      delay(50);
      continue;
    }

    size_t batchBytes = 0;
    uint32_t batchSeq = 0;
    uint32_t recordCount = 0;
    if (buildUploadBatch(&batchBytes, &batchSeq, &recordCount)) {
      postBatch(uploadBatchBuf, batchBytes, batchSeq, recordCount);
    }
  }
}

static void printUploadStatus() {
  const uint32_t now = millis();
  if ((now - lastUploadStatusMs) < UPLOAD_STATUS_INTERVAL_MS) {
    return;
  }
  lastUploadStatusMs = now;

  size_t depth = 0;
  uint32_t oldestAgeMs = 0;
  getUploadQueueSnapshot(&depth, &oldestAgeMs);

  Serial.printf("upload status: enabled=%u queue=%u oldest_ms=%lu queued=%lu dropped=%lu batched=%lu batches=%lu dry_batches=%lu http_ok=%lu http_fail=%lu bytes_sent=%lu dry_bytes=%lu\n",
                static_cast<unsigned>(UPLOAD_ENABLED),
                static_cast<unsigned>(depth),
                oldestAgeMs,
                uploadRecordsQueued,
                uploadRecordsDropped,
                uploadRecordsBatched,
                uploadBatchesBuilt,
                uploadDryRunBatches,
                httpSuccesses,
                httpFailures,
                uploadBytesSent,
                uploadBytesDryRun);
}

static bool initSpiMasterBus() {
  spi_bus_config_t busConfig = {};
  busConfig.mosi_io_num = PIN_SPI_MOSI;
  busConfig.miso_io_num = PIN_SPI_MISO;
  busConfig.sclk_io_num = PIN_SPI_SCLK;
  busConfig.quadwp_io_num = -1;
  busConfig.quadhd_io_num = -1;
  busConfig.max_transfer_sz = SPI_TRANSFER_BYTES;

#if defined(SPI_DMA_CH_AUTO)
  const esp_err_t err = spi_bus_initialize(SPI_HOST_DEVICE, &busConfig, SPI_DMA_CH_AUTO);
#else
  const esp_err_t err = spi_bus_initialize(SPI_HOST_DEVICE, &busConfig, 1);
#endif
  if (err != ESP_OK) {
    Serial.printf("spi_bus_initialize failed: %d\n", static_cast<int>(err));
    return false;
  }

  return true;
}

static bool addSnifferDevice(SnifferLink& sniffer) {
  spi_device_interface_config_t deviceConfig = {};
  deviceConfig.clock_speed_hz = static_cast<int>(SPI_CLOCK_HZ);
  deviceConfig.mode = SPI_MODE0;
  deviceConfig.spics_io_num = sniffer.csPin;
  deviceConfig.queue_size = 1;

  const esp_err_t err = spi_bus_add_device(SPI_HOST_DEVICE, &deviceConfig, &sniffer.device);
  if (err != ESP_OK) {
    Serial.printf("%s spi_bus_add_device failed: %d\n", sniffer.name, static_cast<int>(err));
    return false;
  }

  return true;
}

void setup() {
  Serial.begin(115200);
  delay(800);

#if !UPLOAD_ENABLED
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
#endif

  uploadQueueMutex = xSemaphoreCreateMutex();
  if (uploadQueueMutex == nullptr) {
    Serial.println("upload queue mutex init failed");
    while (true) {
      delay(1000);
    }
  }

  pinMode(PIN_CS_SNIFFER1, OUTPUT);
  pinMode(PIN_CS_SNIFFER2, OUTPUT);
  digitalWrite(PIN_CS_SNIFFER1, HIGH);
  digitalWrite(PIN_CS_SNIFFER2, HIGH);

  pinMode(PIN_RDY_SNIFFER1, INPUT_PULLDOWN);
  pinMode(PIN_RDY_SNIFFER2, INPUT_PULLDOWN);

  if (!initSpiMasterBus()) {
    Serial.println("SPI master init failed. Test halted.");
    while (true) {
      delay(1000);
    }
  }

  Serial.println("ESP32 sender SPI poller starting.");
  Serial.printf("SPI clock=%lu Hz transfer=%u bytes max_frame=%u bytes\n",
                SPI_CLOCK_HZ,
                static_cast<unsigned>(SPI_TRANSFER_BYTES),
                static_cast<unsigned>(MAX_FRAME_BYTES));
  Serial.printf("Uploader: enabled=%u url=%s device=%s queue=%u batch_max=%u records_per_batch=%lu debug_print=%u\n",
                static_cast<unsigned>(UPLOAD_ENABLED),
                UPLOAD_URL,
                DEVICE_ID,
                static_cast<unsigned>(UPLOAD_QUEUE_CAPACITY),
                static_cast<unsigned>(MAX_HTTP_BATCH_BYTES),
                MAX_BATCH_RECORDS,
                static_cast<unsigned>(DEBUG_PRINT_RECORDS));

  for (SnifferLink& sniffer : sniffers) {
    if (!sniffer.enabled) {
      continue;
    }

    if (!addSnifferDevice(sniffer)) {
      sniffer.enabled = false;
    }
  }

  BaseType_t taskOk = xTaskCreatePinnedToCore(uploadTask,
                                              "httpUpload",
                                              12288,
                                              nullptr,
                                              1,
                                              nullptr,
                                              0);
  if (taskOk != pdPASS) {
    Serial.println("upload task start failed");
  }
}

void loop() {
  for (SnifferLink& sniffer : sniffers) {
    if (!sniffer.enabled || sniffer.device == nullptr) {
      continue;
    }

    pollSniffer(sniffer);
  }

  printUploadStatus();
  delay(1);
}
