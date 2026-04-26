#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <stdarg.h>

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

enum class LogLevel : uint8_t {
  Info,
  Warn,
  Error,
};

static const char* logLevelName(LogLevel level) {
  switch (level) {
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
    default:
      return "INFO";
  }
}

static void logEvent(LogLevel level, const char* event, const char* format = nullptr, ...) {
  Serial.printf("%s event=%s", logLevelName(level), event);

  if (format != nullptr && format[0] != '\0') {
    char details[256];
    va_list args;
    va_start(args, format);
    vsnprintf(details, sizeof(details), format, args);
    va_end(args);

    Serial.print(' ');
    Serial.print(details);
  }

  Serial.println();
}

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
static constexpr uint32_t SENDER_STATUS_MAGIC = 0x48544C48UL;  // "HLTH" numeric magic
static constexpr uint16_t SENDER_STATUS_VERSION = 1;
static constexpr uint32_t BATCH_FLAG_HAS_SENDER_STATUS = 1 << 0;
static constexpr size_t STATUS_DEVICE_ID_BYTES = 32;
static constexpr size_t MAX_BATCH_SNIFFER_STATUS = 2;
static constexpr size_t RECORD_HEADER_BYTES = 24;
static constexpr size_t MAX_FRAME_BYTES = 512;
static constexpr size_t SPI_TRANSFER_BYTES = RECORD_HEADER_BYTES + MAX_FRAME_BYTES;
static constexpr uint32_t SPI_CLOCK_HZ = 10000000;  // 10Mhz
static constexpr uint32_t READY_TIMEOUT_MS = 500;
static constexpr uint32_t READY_REARM_TIMEOUT_MS = 250;
static constexpr uint32_t DEVICE_STATUS_INTERVAL_MS = 1000;
static constexpr size_t UPLOAD_QUEUE_CAPACITY = 384;
static constexpr size_t UPLOAD_FRAME_QUEUE_BYTES = 65536;
static constexpr size_t MAX_HTTP_BATCH_BYTES = 24576;
static constexpr uint32_t MAX_BATCH_RECORDS = 64;
static constexpr uint32_t FLUSH_INTERVAL_MS = 1000;
static constexpr uint32_t UPLOAD_RETRY_INTERVAL_MS = 1000;
static constexpr uint32_t WIFI_CONNECT_TIMEOUT_MS = 15000;
static constexpr uint32_t WIFI_RECONNECT_INTERVAL_MS = 5000;
static constexpr uint16_t HTTP_TIMEOUT_MS = 8000;

static constexpr uint16_t FLAG_TRUNCATED = 1 << 0;

static bool uploadWifiEverConnected = false;
static uint8_t lastWifiDisconnectReason = 0;

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
  uint16_t source_id;
  uint8_t enabled;
  uint8_t status_seen;
  uint32_t status_age_ms;
  uint32_t sender_records_received;
  uint32_t sender_crc_errors;
  uint32_t sender_bad_packets;
  uint32_t sender_spi_errors;
  uint32_t sender_ready_timeouts;
  status_packet_t last_status;
} batch_sniffer_status_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;        // 0x48544C48 = "HLTH"
  uint16_t version;      // 1
  uint16_t struct_len;   // sizeof(sender_status_t)
  uint32_t uptime_ms;
  char device_id[STATUS_DEVICE_ID_BYTES];
  uint32_t heap_size;
  uint32_t heap_free;
  uint32_t heap_min_free;
  uint32_t heap_max_alloc;
  uint32_t upload_queue_depth;
  uint32_t upload_queue_capacity;
  uint32_t upload_queue_max_depth;
  uint32_t upload_queue_oldest_ms;
  uint32_t upload_records_queued;
  uint32_t upload_records_dropped;
  uint32_t upload_records_batched;
  uint32_t upload_batches_built;
  uint32_t upload_dry_run_batches;
  uint32_t upload_http_attempts;
  uint32_t upload_http_successes;
  uint32_t upload_http_failures;
  uint32_t upload_bytes_sent;
  uint32_t upload_bytes_dry_run;
  uint32_t upload_retry_batch_seq;
  uint32_t upload_retry_records;
  uint32_t upload_retry_bytes;
  uint32_t upload_retry_attempts;
  uint32_t upload_retry_failures;
  int32_t upload_retry_last_code;
  uint32_t sender_records_received;
  uint32_t sender_crc_errors;
  uint32_t sender_bad_packets;
  uint32_t sender_spi_errors;
  uint32_t sender_ready_timeouts;
  uint8_t upload_enabled;
  uint8_t wifi_connected;
  int8_t wifi_rssi;
  uint8_t upload_retry_pending;
  uint8_t sniffer_count;
  uint8_t reserved[3];
  batch_sniffer_status_t sniffers[MAX_BATCH_SNIFFER_STATUS];
} sender_status_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;        // 0x534E5042 = "SNPB"
  uint16_t version;      // 1
  uint16_t header_len;   // sizeof(batch_header_t)
  uint32_t batch_seq;
  uint32_t record_count;
  uint32_t payload_len;  // status_len + record bytes after this header
  uint32_t uptime_ms;
  uint32_t flags;
  uint32_t status_len;   // bytes of sender_status_t before records
} batch_header_t;

typedef struct __attribute__((packed)) {
  uint16_t source_id;    // sender-local sniffer ID, e.g. 1 for sniffer1
  uint16_t record_len;   // sniff_record_t + frame_len
} upload_record_prefix_t;

static_assert(sizeof(sniff_record_t) == RECORD_HEADER_BYTES, "unexpected record header size");
static_assert(sizeof(sender_status_t) < MAX_HTTP_BATCH_BYTES, "sender status does not fit upload batch");
static_assert(sizeof(batch_header_t) +
                sizeof(sender_status_t) +
                sizeof(upload_record_prefix_t) +
                sizeof(sniff_record_t) +
                MAX_FRAME_BYTES <= MAX_HTTP_BATCH_BYTES,
              "upload batch cannot fit sender status and one max-sized record");

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
  bool statusSeen;
  status_packet_t lastStatus;
  uint32_t lastStatusMs;
};

static SnifferLink sniffers[] = {
  {"sniffer1", 1, PIN_CS_SNIFFER1, PIN_RDY_SNIFFER1, true, nullptr, 0, 0, 0, 0, 0, false, {}, 0},
  {"sniffer2", 2, PIN_CS_SNIFFER2, PIN_RDY_SNIFFER2, false, nullptr, 0, 0, 0, 0, 0, false, {}, 0},
};

DRAM_ATTR static uint8_t txBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));
DRAM_ATTR static uint8_t rxBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));

struct UploadRecord {
  uint16_t sourceId;
  uint16_t recordLen;
  uint32_t queuedMs;
  uint32_t frameOffset;
  sniff_record_t header;
};

static SemaphoreHandle_t uploadQueueMutex = nullptr;
static UploadRecord* uploadQueue = nullptr;
static uint8_t* uploadFrameQueue = nullptr;
static size_t uploadQueueHead = 0;
static size_t uploadQueueCount = 0;
static size_t uploadFrameHead = 0;
static size_t uploadFrameTail = 0;
static uint32_t uploadFrameBytes = 0;
static uint32_t uploadFrameMaxBytes = 0;
static uint16_t uploadQueueMaxDepth = 0;

static uint8_t* uploadBatchBuf = nullptr;

static HTTPClient uploadHttp;
static WiFiClient uploadPlainClient;
static WiFiClientSecure uploadSecureClient;
static bool uploadHttpBegun = false;
static bool uploadHttpSecure = false;
static bool uploadHttpResetRequested = false;

static uint32_t uploadRecordsQueued = 0;
static uint32_t uploadRecordsDropped = 0;
static uint32_t uploadRecordsBatched = 0;
static uint32_t uploadBatchesBuilt = 0;
static uint32_t uploadDryRunBatches = 0;
static uint32_t httpAttempts = 0;
static uint32_t httpSuccesses = 0;
static uint32_t httpFailures = 0;
static uint32_t httpClientBegins = 0;
static uint32_t httpClientReuses = 0;
static uint32_t httpLastMs = 0;
static uint32_t httpMaxMs = 0;
static uint32_t uploadBytesSent = 0;
static uint32_t uploadBytesDryRun = 0;
static uint32_t uploadBatchSeq = 1;

static bool uploadRetryPending = false;
static size_t uploadRetryBytes = 0;
static uint32_t uploadRetryBatchSeq = 0;
static uint32_t uploadRetryRecordCount = 0;
static uint32_t uploadRetryAttempts = 0;
static uint32_t uploadRetryFailures = 0;
static uint32_t uploadRetryLastAttemptMs = 0;
static int uploadRetryLastCode = 0;

struct UploadQueueSnapshot {
  size_t depth;
  uint16_t maxDepth;
  uint32_t oldestAgeMs;
  uint32_t recordsQueued;
  uint32_t recordsDropped;
  uint32_t recordsBatched;
  uint32_t batchesBuilt;
  uint32_t frameBytes;
  uint32_t frameMaxBytes;
  uint32_t dryRunBatches;
  uint32_t httpAttempts;
  uint32_t httpSuccesses;
  uint32_t httpFailures;
  uint32_t httpClientBegins;
  uint32_t httpClientReuses;
  uint32_t httpLastMs;
  uint32_t httpMaxMs;
  uint32_t bytesSent;
  uint32_t dryRunBytes;
};

struct SenderCounterSnapshot {
  uint32_t recordsReceived;
  uint32_t crcErrors;
  uint32_t badPackets;
  uint32_t spiErrors;
  uint32_t readyTimeouts;
};

struct MemorySnapshot {
  uint32_t heapSize;
  uint32_t freeHeap;
  uint32_t minFreeHeap;
  uint32_t maxAllocHeap;
  uint8_t heapUsedPct;
};

static uint32_t lastDeviceStatusMs = 0;
static SenderCounterSnapshot lastStatusCounters = {};
static uint32_t lastStatusUploadDropped = 0;
static bool queueWarnActive = false;
static bool queueCriticalActive = false;
static bool heapWarnActive = false;
static bool heapCriticalActive = false;

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

static bool initUploadBuffers() {
  uploadQueue = static_cast<UploadRecord*>(malloc(sizeof(UploadRecord) * UPLOAD_QUEUE_CAPACITY));
  uploadFrameQueue = static_cast<uint8_t*>(malloc(UPLOAD_FRAME_QUEUE_BYTES));
  uploadBatchBuf = static_cast<uint8_t*>(malloc(MAX_HTTP_BATCH_BYTES));

  if (uploadQueue == nullptr || uploadFrameQueue == nullptr || uploadBatchBuf == nullptr) {
    logEvent(LogLevel::Error,
             "upload_buffer_alloc_failed",
             "queue_bytes=%u frame_bytes=%u batch_bytes=%u heap_free=%lu max_alloc=%lu",
             static_cast<unsigned>(sizeof(UploadRecord) * UPLOAD_QUEUE_CAPACITY),
             static_cast<unsigned>(UPLOAD_FRAME_QUEUE_BYTES),
             static_cast<unsigned>(MAX_HTTP_BATCH_BYTES),
             static_cast<unsigned long>(ESP.getFreeHeap()),
             static_cast<unsigned long>(ESP.getMaxAllocHeap()));
    return false;
  }

  return true;
}

static bool findFrameQueueSpace(size_t len, size_t* offset) {
  if (offset == nullptr || len > UPLOAD_FRAME_QUEUE_BYTES) {
    return false;
  }

  if (uploadQueueCount == 0) {
    uploadFrameHead = 0;
    uploadFrameTail = 0;
    *offset = 0;
    return true;
  }

  if (len == 0) {
    *offset = uploadFrameTail;
    return true;
  }

  if (uploadFrameTail == uploadFrameHead) {
    return false;
  }

  if (uploadFrameTail > uploadFrameHead) {
    const size_t endSpace = UPLOAD_FRAME_QUEUE_BYTES - uploadFrameTail;
    if (endSpace >= len) {
      *offset = uploadFrameTail;
      return true;
    }
    if (uploadFrameHead > len) {
      *offset = 0;
      return true;
    }
    return false;
  }

  if ((uploadFrameHead - uploadFrameTail) > len) {
    *offset = uploadFrameTail;
    return true;
  }

  return false;
}

static void commitFrameQueueWrite(size_t offset, size_t len) {
  if (len == 0) {
    return;
  }

  uploadFrameTail = offset + len;
  if (uploadFrameTail >= UPLOAD_FRAME_QUEUE_BYTES) {
    uploadFrameTail = 0;
  }

  uploadFrameBytes += static_cast<uint32_t>(len);
  if (uploadFrameBytes > uploadFrameMaxBytes) {
    uploadFrameMaxBytes = uploadFrameBytes;
  }
}

static bool discardOldestUploadRecord(bool countAsDropped) {
  if (uploadQueueCount == 0) {
    return false;
  }

  const UploadRecord& record = uploadQueue[uploadQueueHead];
  const uint32_t frameLen = record.header.frame_len;
  uploadFrameBytes = uploadFrameBytes > frameLen ? uploadFrameBytes - frameLen : 0;

  uploadQueueHead = (uploadQueueHead + 1) % UPLOAD_QUEUE_CAPACITY;
  --uploadQueueCount;
  if (countAsDropped) {
    ++uploadRecordsDropped;
  }

  if (uploadQueueCount == 0) {
    uploadFrameHead = 0;
    uploadFrameTail = 0;
    uploadFrameBytes = 0;
  } else {
    uploadFrameHead = uploadQueue[uploadQueueHead].frameOffset;
  }

  return true;
}

static void enqueueUploadRecord(const SnifferLink& sniffer, const sniff_record_t& record, const uint8_t* frame) {
  if (record.frame_len > MAX_FRAME_BYTES ||
      record.frame_len > UPLOAD_FRAME_QUEUE_BYTES ||
      uploadQueue == nullptr ||
      uploadFrameQueue == nullptr ||
      uploadQueueMutex == nullptr) {
    return;
  }

  if (!takeUploadMutex()) {
    return;
  }

  size_t frameOffset = 0;
  while (uploadQueueCount == UPLOAD_QUEUE_CAPACITY ||
         !findFrameQueueSpace(record.frame_len, &frameOffset)) {
    if (!discardOldestUploadRecord(true)) {
      giveUploadMutex();
      return;
    }
  }

  memcpy(uploadFrameQueue + frameOffset, frame, record.frame_len);
  commitFrameQueueWrite(frameOffset, record.frame_len);

  const size_t writeIndex = (uploadQueueHead + uploadQueueCount) % UPLOAD_QUEUE_CAPACITY;
  UploadRecord& queued = uploadQueue[writeIndex];
  queued.sourceId = sniffer.sourceId;
  queued.recordLen = static_cast<uint16_t>(sizeof(sniff_record_t) + record.frame_len);
  queued.queuedMs = millis();
  queued.frameOffset = static_cast<uint32_t>(frameOffset);
  queued.header = record;

  ++uploadQueueCount;
  ++uploadRecordsQueued;
  if (uploadQueueCount > uploadQueueMaxDepth) {
    uploadQueueMaxDepth = static_cast<uint16_t>(uploadQueueCount);
  }

  giveUploadMutex();
}

static bool getUploadQueueSnapshot(UploadQueueSnapshot* snapshot, TickType_t ticks = pdMS_TO_TICKS(10)) {
  if (snapshot == nullptr || !takeUploadMutex(ticks)) {
    return false;
  }

  const size_t count = uploadQueueCount;
  snapshot->depth = count;
  snapshot->maxDepth = uploadQueueMaxDepth;
  if (count == 0) {
    snapshot->oldestAgeMs = 0;
  } else {
    snapshot->oldestAgeMs = millis() - uploadQueue[uploadQueueHead].queuedMs;
  }
  snapshot->recordsQueued = uploadRecordsQueued;
  snapshot->recordsDropped = uploadRecordsDropped;
  snapshot->recordsBatched = uploadRecordsBatched;
  snapshot->batchesBuilt = uploadBatchesBuilt;
  snapshot->frameBytes = uploadFrameBytes;
  snapshot->frameMaxBytes = uploadFrameMaxBytes;

  giveUploadMutex();

  snapshot->dryRunBatches = uploadDryRunBatches;
  snapshot->httpAttempts = httpAttempts;
  snapshot->httpSuccesses = httpSuccesses;
  snapshot->httpFailures = httpFailures;
  snapshot->httpClientBegins = httpClientBegins;
  snapshot->httpClientReuses = httpClientReuses;
  snapshot->httpLastMs = httpLastMs;
  snapshot->httpMaxMs = httpMaxMs;
  snapshot->bytesSent = uploadBytesSent;
  snapshot->dryRunBytes = uploadBytesDryRun;
  return true;
}

static bool shouldFlushUploadQueue() {
  UploadQueueSnapshot snapshot = {};
  if (!getUploadQueueSnapshot(&snapshot)) {
    return false;
  }

  return snapshot.depth >= MAX_BATCH_RECORDS ||
         (snapshot.depth > 0 && snapshot.oldestAgeMs >= FLUSH_INTERVAL_MS);
}

static SenderCounterSnapshot getSenderCounterSnapshot() {
  SenderCounterSnapshot snapshot = {};
  for (const SnifferLink& sniffer : sniffers) {
    snapshot.recordsReceived += sniffer.recordsReceived;
    snapshot.crcErrors += sniffer.crcErrors;
    snapshot.badPackets += sniffer.badPackets;
    snapshot.spiErrors += sniffer.spiErrors;
    snapshot.readyTimeouts += sniffer.readyTimeouts;
  }
  return snapshot;
}

static MemorySnapshot getMemorySnapshot() {
  MemorySnapshot snapshot = {};
  snapshot.heapSize = ESP.getHeapSize();
  snapshot.freeHeap = ESP.getFreeHeap();
  snapshot.minFreeHeap = ESP.getMinFreeHeap();
  snapshot.maxAllocHeap = ESP.getMaxAllocHeap();
  if (snapshot.heapSize > 0 && snapshot.freeHeap <= snapshot.heapSize) {
    snapshot.heapUsedPct = static_cast<uint8_t>(100 - ((snapshot.freeHeap * 100UL) / snapshot.heapSize));
  }
  return snapshot;
}

static void fillSenderStatus(sender_status_t* status,
                             const UploadQueueSnapshot& queue,
                             uint32_t now) {
  if (status == nullptr) {
    return;
  }

  memset(status, 0, sizeof(*status));

  const MemorySnapshot memory = getMemorySnapshot();
  const SenderCounterSnapshot counters = getSenderCounterSnapshot();
  const bool wifiConnected = WiFi.status() == WL_CONNECTED;

  status->magic = SENDER_STATUS_MAGIC;
  status->version = SENDER_STATUS_VERSION;
  status->struct_len = static_cast<uint16_t>(sizeof(sender_status_t));
  status->uptime_ms = now;
  strncpy(status->device_id, DEVICE_ID, sizeof(status->device_id) - 1);
  status->heap_size = memory.heapSize;
  status->heap_free = memory.freeHeap;
  status->heap_min_free = memory.minFreeHeap;
  status->heap_max_alloc = memory.maxAllocHeap;
  status->upload_queue_depth = static_cast<uint32_t>(queue.depth);
  status->upload_queue_capacity = static_cast<uint32_t>(UPLOAD_QUEUE_CAPACITY);
  status->upload_queue_max_depth = queue.maxDepth;
  status->upload_queue_oldest_ms = queue.oldestAgeMs;
  status->upload_records_queued = queue.recordsQueued;
  status->upload_records_dropped = queue.recordsDropped;
  status->upload_records_batched = queue.recordsBatched;
  status->upload_batches_built = queue.batchesBuilt;
  status->upload_dry_run_batches = queue.dryRunBatches;
  status->upload_http_attempts = queue.httpAttempts;
  status->upload_http_successes = queue.httpSuccesses;
  status->upload_http_failures = queue.httpFailures;
  status->upload_bytes_sent = queue.bytesSent;
  status->upload_bytes_dry_run = queue.dryRunBytes;
  status->upload_retry_batch_seq = uploadRetryBatchSeq;
  status->upload_retry_records = uploadRetryRecordCount;
  status->upload_retry_bytes = static_cast<uint32_t>(uploadRetryBytes);
  status->upload_retry_attempts = uploadRetryAttempts;
  status->upload_retry_failures = uploadRetryFailures;
  status->upload_retry_last_code = uploadRetryLastCode;
  status->sender_records_received = counters.recordsReceived;
  status->sender_crc_errors = counters.crcErrors;
  status->sender_bad_packets = counters.badPackets;
  status->sender_spi_errors = counters.spiErrors;
  status->sender_ready_timeouts = counters.readyTimeouts;
  status->upload_enabled = UPLOAD_ENABLED ? 1 : 0;
  status->wifi_connected = wifiConnected ? 1 : 0;
  status->wifi_rssi = wifiConnected ? static_cast<int8_t>(WiFi.RSSI()) : 0;
  status->upload_retry_pending = uploadRetryPending ? 1 : 0;

  uint8_t statusIndex = 0;
  for (const SnifferLink& sniffer : sniffers) {
    if (statusIndex >= MAX_BATCH_SNIFFER_STATUS) {
      break;
    }

    batch_sniffer_status_t& target = status->sniffers[statusIndex++];
    target.source_id = sniffer.sourceId;
    target.enabled = sniffer.enabled ? 1 : 0;
    target.status_seen = sniffer.statusSeen ? 1 : 0;
    target.status_age_ms = sniffer.statusSeen ? now - sniffer.lastStatusMs : 0xFFFFFFFFUL;
    target.sender_records_received = sniffer.recordsReceived;
    target.sender_crc_errors = sniffer.crcErrors;
    target.sender_bad_packets = sniffer.badPackets;
    target.sender_spi_errors = sniffer.spiErrors;
    target.sender_ready_timeouts = sniffer.readyTimeouts;
    if (sniffer.statusSeen) {
      target.last_status = sniffer.lastStatus;
    }
  }
  status->sniffer_count = statusIndex;
}

static void updatePressureWarnings(const UploadQueueSnapshot& queue,
                                   const MemorySnapshot& memory,
                                   uint32_t droppedDelta) {
  const size_t queueWarnDepth = (UPLOAD_QUEUE_CAPACITY * 3) / 4;
  const size_t queueCriticalDepth = (UPLOAD_QUEUE_CAPACITY * 9) / 10;
  const uint32_t frameWarnBytes = (UPLOAD_FRAME_QUEUE_BYTES * 3) / 4;
  const uint32_t frameCriticalBytes = (UPLOAD_FRAME_QUEUE_BYTES * 9) / 10;

  if ((queue.depth >= queueCriticalDepth || queue.frameBytes >= frameCriticalBytes) && !queueCriticalActive) {
    logEvent(LogLevel::Warn,
             "upload_queue_critical",
             "depth=%u capacity=%u frame_bytes=%lu frame_capacity=%u oldest_ms=%lu dropped=%lu",
             static_cast<unsigned>(queue.depth),
             static_cast<unsigned>(UPLOAD_QUEUE_CAPACITY),
             static_cast<unsigned long>(queue.frameBytes),
             static_cast<unsigned>(UPLOAD_FRAME_QUEUE_BYTES),
             static_cast<unsigned long>(queue.oldestAgeMs),
             static_cast<unsigned long>(queue.recordsDropped));
    queueCriticalActive = true;
    queueWarnActive = true;
  } else if ((queue.depth >= queueWarnDepth || queue.frameBytes >= frameWarnBytes) && !queueWarnActive) {
    logEvent(LogLevel::Warn,
             "upload_queue_high",
             "depth=%u capacity=%u frame_bytes=%lu frame_capacity=%u oldest_ms=%lu dropped=%lu",
             static_cast<unsigned>(queue.depth),
             static_cast<unsigned>(UPLOAD_QUEUE_CAPACITY),
             static_cast<unsigned long>(queue.frameBytes),
             static_cast<unsigned>(UPLOAD_FRAME_QUEUE_BYTES),
             static_cast<unsigned long>(queue.oldestAgeMs),
             static_cast<unsigned long>(queue.recordsDropped));
    queueWarnActive = true;
  } else if (queue.depth < queueWarnDepth && queue.frameBytes < frameWarnBytes) {
    queueWarnActive = false;
    queueCriticalActive = false;
  }

  if (droppedDelta > 0) {
    logEvent(LogLevel::Warn,
             "upload_records_dropped",
             "count_1s=%lu total=%lu depth=%u frame_bytes=%lu",
             static_cast<unsigned long>(droppedDelta),
             static_cast<unsigned long>(queue.recordsDropped),
             static_cast<unsigned>(queue.depth),
             static_cast<unsigned long>(queue.frameBytes));
  }

  static constexpr uint32_t HEAP_WARN_BYTES = 32768;
  static constexpr uint32_t HEAP_CRITICAL_BYTES = 16384;
  if (memory.freeHeap < HEAP_CRITICAL_BYTES && !heapCriticalActive) {
    logEvent(LogLevel::Error,
             "heap_critical",
             "free=%lu min_free=%lu max_alloc=%lu used_pct=%u",
             static_cast<unsigned long>(memory.freeHeap),
             static_cast<unsigned long>(memory.minFreeHeap),
             static_cast<unsigned long>(memory.maxAllocHeap),
             static_cast<unsigned>(memory.heapUsedPct));
    heapCriticalActive = true;
    heapWarnActive = true;
  } else if (memory.freeHeap < HEAP_WARN_BYTES && !heapWarnActive) {
    logEvent(LogLevel::Warn,
             "heap_low",
             "free=%lu min_free=%lu max_alloc=%lu used_pct=%u",
             static_cast<unsigned long>(memory.freeHeap),
             static_cast<unsigned long>(memory.minFreeHeap),
             static_cast<unsigned long>(memory.maxAllocHeap),
             static_cast<unsigned>(memory.heapUsedPct));
    heapWarnActive = true;
  } else if (memory.freeHeap >= (HEAP_WARN_BYTES + 8192)) {
    heapWarnActive = false;
    heapCriticalActive = false;
  }
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

  const uint32_t now = millis();
  UploadQueueSnapshot queueSnapshot = {};
  queueSnapshot.depth = uploadQueueCount;
  queueSnapshot.maxDepth = uploadQueueMaxDepth;
  queueSnapshot.oldestAgeMs = now - uploadQueue[uploadQueueHead].queuedMs;
  queueSnapshot.recordsQueued = uploadRecordsQueued;
  queueSnapshot.recordsDropped = uploadRecordsDropped;
  queueSnapshot.recordsBatched = uploadRecordsBatched;
  queueSnapshot.batchesBuilt = uploadBatchesBuilt;
  queueSnapshot.frameBytes = uploadFrameBytes;
  queueSnapshot.frameMaxBytes = uploadFrameMaxBytes;
  queueSnapshot.dryRunBatches = uploadDryRunBatches;
  queueSnapshot.httpAttempts = httpAttempts;
  queueSnapshot.httpSuccesses = httpSuccesses;
  queueSnapshot.httpFailures = httpFailures;
  queueSnapshot.httpClientBegins = httpClientBegins;
  queueSnapshot.httpClientReuses = httpClientReuses;
  queueSnapshot.httpLastMs = httpLastMs;
  queueSnapshot.httpMaxMs = httpMaxMs;
  queueSnapshot.bytesSent = uploadBytesSent;
  queueSnapshot.dryRunBytes = uploadBytesDryRun;

  sender_status_t senderStatus = {};
  fillSenderStatus(&senderStatus, queueSnapshot, now);

  batch_header_t header = {};
  header.magic = BATCH_MAGIC;
  header.version = BATCH_VERSION;
  header.header_len = static_cast<uint16_t>(sizeof(batch_header_t));
  header.batch_seq = uploadBatchSeq++;
  header.uptime_ms = now;
  header.flags = BATCH_FLAG_HAS_SENDER_STATUS;
  header.status_len = sizeof(senderStatus);

  size_t offset = sizeof(batch_header_t);
  memcpy(uploadBatchBuf + offset, &senderStatus, sizeof(senderStatus));
  offset += sizeof(senderStatus);

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
    memcpy(uploadBatchBuf + offset, uploadFrameQueue + record.frameOffset, record.header.frame_len);
    offset += record.header.frame_len;

    discardOldestUploadRecord(false);
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
    logEvent(LogLevel::Warn, "ready_rearm_timeout", "source=%s phase=drop", sniffer.name);
    return false;
  }

  if (!waitReadyLevel(sniffer, HIGH, READY_TIMEOUT_MS)) {
    ++sniffer.readyTimeouts;
    logEvent(LogLevel::Warn,
             "ready_rearm_timeout",
             "source=%s phase=rise gpio=%d",
             sniffer.name,
             sniffer.readyPin);
    return false;
  }

  return true;
}

static void handleRecord(SnifferLink& sniffer) {
  sniff_record_t record = {};
  memcpy(&record, rxBuf, sizeof(record));

  if (record.version != PROTOCOL_VERSION ||
      record.header_len != sizeof(sniff_record_t) ||
      record.frame_len > MAX_FRAME_BYTES ||
      (sizeof(sniff_record_t) + record.frame_len) > SPI_TRANSFER_BYTES) {
    ++sniffer.badPackets;
    logEvent(LogLevel::Warn,
             "bad_snif_header",
             "source=%s version=%u header_len=%u frame_len=%u",
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
    logEvent(LogLevel::Warn,
             "crc_error",
             "source=%s seq=%lu got=0x%04X expected=0x%04X len=%u",
             sniffer.name,
             static_cast<unsigned long>(record.seq),
             crc,
             record.crc16,
             record.frame_len);
    return;
  }

  ++sniffer.recordsReceived;
  enqueueUploadRecord(sniffer, record, frame);
}

static void handleStatus(SnifferLink& sniffer) {
  status_packet_t status = {};
  memcpy(&status, rxBuf, min(sizeof(status), sizeof(rxBuf)));

  sniffer.statusSeen = true;
  sniffer.lastStatus = status;
  sniffer.lastStatusMs = millis();
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
  logEvent(LogLevel::Warn,
           "bad_spi_packet",
           "source=%s magic=0x%08lX",
           sniffer.name,
           static_cast<unsigned long>(magic));
}

static bool pollSniffer(SnifferLink& sniffer) {
  if (!waitReadyLevel(sniffer, HIGH, READY_TIMEOUT_MS)) {
    ++sniffer.readyTimeouts;
    logEvent(LogLevel::Warn,
             "ready_timeout",
             "source=%s gpio=%d",
             sniffer.name,
             sniffer.readyPin);
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
    logEvent(LogLevel::Error,
             "spi_transmit_failed",
             "source=%s err=%d",
             sniffer.name,
             static_cast<int>(err));
    return false;
  }

  waitForSlaveRearm(sniffer);
  handlePacket(sniffer);
  return true;
}

static bool uploadUrlIsHttps() {
  return strncmp(UPLOAD_URL, "https://", 8) == 0;
}

static void closeUploadHttpClient() {
  if (uploadHttpBegun) {
    uploadHttp.setReuse(false);
    uploadHttp.end();
  }

  uploadPlainClient.stop();
  uploadSecureClient.stop();
  uploadHttpBegun = false;
  uploadHttpSecure = false;
  uploadHttpResetRequested = false;
}

static void updateHttpTiming(uint32_t uploadMs) {
  httpLastMs = uploadMs;
  if (uploadMs > httpMaxMs) {
    httpMaxMs = uploadMs;
  }
}

static bool beginUploadHttpClient(bool* reused) {
  if (reused != nullptr) {
    *reused = false;
  }

  if (uploadHttpResetRequested) {
    closeUploadHttpClient();
  }

  const bool https = uploadUrlIsHttps();
  if (uploadHttpBegun) {
    if (uploadHttpSecure != https) {
      closeUploadHttpClient();
    } else {
      if (reused != nullptr && uploadHttp.connected()) {
        *reused = true;
      }
      return true;
    }
  }

  bool began = false;
  if (https) {
#if HTTP_TLS_INSECURE
    uploadSecureClient.setInsecure();
#endif
    began = uploadHttp.begin(uploadSecureClient, UPLOAD_URL);
  } else {
    began = uploadHttp.begin(uploadPlainClient, UPLOAD_URL);
  }

  if (!began) {
    closeUploadHttpClient();
    return false;
  }

  uploadHttpBegun = true;
  uploadHttpSecure = https;
  ++httpClientBegins;
  uploadHttp.setReuse(true);
  uploadHttp.setTimeout(HTTP_TIMEOUT_MS);
  uploadHttp.setConnectTimeout(HTTP_TIMEOUT_MS);
  return true;
}

static void addUploadHttpHeaders(uint32_t batchSeq, uint32_t recordCount) {
  uploadHttp.addHeader("Content-Type", "application/octet-stream");
  if (strlen(API_TOKEN) > 0) {
    String bearer = "Bearer ";
    bearer += API_TOKEN;
    uploadHttp.addHeader("Authorization", bearer);
  }
  uploadHttp.addHeader("X-Device-Id", DEVICE_ID);
  uploadHttp.addHeader("X-Batch-Version", String(BATCH_VERSION));
  uploadHttp.addHeader("X-Batch-Seq", String(batchSeq));
  uploadHttp.addHeader("X-Record-Count", String(recordCount));
}

static void drainUploadHttpResponseBody() {
  if (!uploadHttp.connected()) {
    return;
  }

  const int responseBytes = uploadHttp.getSize();
  if (responseBytes > 0) {
    uploadHttp.getString();
  }
}

static const char* wlStatusName(wl_status_t status) {
  switch (status) {
    case WL_IDLE_STATUS:
      return "IDLE";
    case WL_NO_SSID_AVAIL:
      return "NO_SSID_AVAIL";
    case WL_SCAN_COMPLETED:
      return "SCAN_COMPLETED";
    case WL_CONNECTED:
      return "CONNECTED";
    case WL_CONNECT_FAILED:
      return "CONNECT_FAILED";
    case WL_CONNECTION_LOST:
      return "CONNECTION_LOST";
    case WL_DISCONNECTED:
      return "DISCONNECTED";
    default:
      return "UNKNOWN";
  }
}

static const char* authModeName(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:
      return "OPEN";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA_WPA2_PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK:
      return "WPA3_PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK:
      return "WPA2_WPA3_PSK";
    default:
      return "UNKNOWN";
  }
}

static const char* disconnectReasonName(uint8_t reason) {
  switch (reason) {
    case WIFI_REASON_AUTH_EXPIRE:
      return "AUTH_EXPIRE";
    case WIFI_REASON_AUTH_LEAVE:
      return "AUTH_LEAVE";
    case WIFI_REASON_ASSOC_EXPIRE:
      return "ASSOC_EXPIRE";
    case WIFI_REASON_ASSOC_TOOMANY:
      return "ASSOC_TOOMANY";
    case WIFI_REASON_NOT_AUTHED:
      return "NOT_AUTHED";
    case WIFI_REASON_NOT_ASSOCED:
      return "NOT_ASSOCED";
    case WIFI_REASON_ASSOC_LEAVE:
      return "ASSOC_LEAVE";
    case WIFI_REASON_ASSOC_NOT_AUTHED:
      return "ASSOC_NOT_AUTHED";
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
      return "4WAY_HANDSHAKE_TIMEOUT";
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
      return "HANDSHAKE_TIMEOUT";
    case WIFI_REASON_AUTH_FAIL:
      return "AUTH_FAIL";
    case WIFI_REASON_ASSOC_FAIL:
      return "ASSOC_FAIL";
    case WIFI_REASON_NO_AP_FOUND:
      return "NO_AP_FOUND";
    case WIFI_REASON_CONNECTION_FAIL:
      return "CONNECTION_FAIL";
    case WIFI_REASON_BEACON_TIMEOUT:
      return "BEACON_TIMEOUT";
    default:
      return "UNKNOWN";
  }
}

static String hostFromUrl(const char* url) {
  String host(url);
  const int scheme = host.indexOf("://");
  if (scheme >= 0) {
    host.remove(0, scheme + 3);
  }

  const int slash = host.indexOf('/');
  if (slash >= 0) {
    host.remove(slash);
  }

  const int port = host.indexOf(':');
  if (port >= 0) {
    host.remove(port);
  }

  return host;
}

static void scanForConfiguredSsid() {
  logEvent(LogLevel::Info, "wifi_scan_start", "target_ssid=\"%s\"", WIFI_SSID);
  const int count = WiFi.scanNetworks(false, true);
  if (count < 0) {
    logEvent(LogLevel::Warn, "wifi_scan_failed", "code=%d", count);
    return;
  }

  int matches = 0;
  logEvent(LogLevel::Info, "wifi_scan_result", "count=%d", count);
  for (int i = 0; i < count; ++i) {
    const bool match = WiFi.SSID(i) == WIFI_SSID;
    if (match) {
      ++matches;
    }

    Serial.printf("INFO event=wifi_network index=%d match=%u ssid=\"%s\" rssi=%d channel=%d auth=%s bssid=%s\n",
                  i,
                  match ? 1 : 0,
                  WiFi.SSID(i).c_str(),
                  WiFi.RSSI(i),
                  WiFi.channel(i),
                  authModeName(WiFi.encryptionType(i)),
                  WiFi.BSSIDstr(i).c_str());
  }

  if (matches == 0) {
    logEvent(LogLevel::Warn,
             "wifi_ssid_not_seen",
             "ssid=\"%s\" note=\"ESP32 classic WiFi is 2.4GHz only\"",
             WIFI_SSID);
  } else {
    logEvent(LogLevel::Info, "wifi_ssid_seen", "ssid=\"%s\" matches=%d", WIFI_SSID, matches);
  }

  WiFi.scanDelete();
}

static void runUploadDnsDiagnostic() {
  const String host = hostFromUrl(UPLOAD_URL);
  if (host.length() == 0) {
    logEvent(LogLevel::Warn, "dns_test_skipped", "reason=empty_host url=%s", UPLOAD_URL);
    return;
  }

  IPAddress ip;
  const int ok = WiFi.hostByName(host.c_str(), ip);
  if (ok == 1) {
    logEvent(LogLevel::Info, "dns_ok", "host=%s ip=%s", host.c_str(), ip.toString().c_str());
  } else {
    logEvent(LogLevel::Warn, "dns_failed", "host=%s result=%d", host.c_str(), ok);
  }
}

static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      logEvent(LogLevel::Info, "wifi_event_connected");
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      uploadWifiEverConnected = true;
      logEvent(LogLevel::Info, "wifi_event_got_ip", "ip=%s", WiFi.localIP().toString().c_str());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      lastWifiDisconnectReason = info.wifi_sta_disconnected.reason;
      uploadHttpResetRequested = true;
      logEvent(LogLevel::Warn,
               "wifi_event_disconnected",
               "reason=%u reason_name=%s",
               static_cast<unsigned>(lastWifiDisconnectReason),
               disconnectReasonName(lastWifiDisconnectReason));
      break;
    default:
      break;
  }
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

  closeUploadHttpClient();

  static uint32_t lastAttemptMs = 0;
  const uint32_t now = millis();
  if ((now - lastAttemptMs) < WIFI_RECONNECT_INTERVAL_MS) {
    return false;
  }
  lastAttemptMs = now;

  if (!uploadConfigLooksUsable()) {
    logEvent(LogLevel::Warn, "upload_config_missing");
    return false;
  }

  lastWifiDisconnectReason = 0;
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);
  scanForConfiguredSsid();

  WiFi.begin(WIFI_SSID, WIFI_PASS);

  logEvent(LogLevel::Info,
           "wifi_connect_start",
           "ssid=\"%s\" timeout_ms=%lu",
           WIFI_SSID,
           static_cast<unsigned long>(WIFI_CONNECT_TIMEOUT_MS));

  const uint32_t started = millis();
  uint32_t lastWaitLogMs = 0;
  while (WiFi.status() != WL_CONNECTED && (millis() - started) < WIFI_CONNECT_TIMEOUT_MS) {
    const uint32_t waitNow = millis();
    if ((waitNow - lastWaitLogMs) >= 1000) {
      lastWaitLogMs = waitNow;
      logEvent(LogLevel::Info,
               "wifi_connect_wait",
               "elapsed_ms=%lu status=%s last_reason=%u last_reason_name=%s",
               static_cast<unsigned long>(waitNow - started),
               wlStatusName(WiFi.status()),
               static_cast<unsigned>(lastWifiDisconnectReason),
               disconnectReasonName(lastWifiDisconnectReason));
    }
    delay(100);
  }

  if (WiFi.status() == WL_CONNECTED) {
    uploadWifiEverConnected = true;
    logEvent(LogLevel::Info,
             "wifi_connected",
             "ssid=\"%s\" ip=%s gateway=%s subnet=%s dns=%s rssi=%d channel=%u bssid=%s",
             WiFi.SSID().c_str(),
             WiFi.localIP().toString().c_str(),
             WiFi.gatewayIP().toString().c_str(),
             WiFi.subnetMask().toString().c_str(),
             WiFi.dnsIP().toString().c_str(),
             WiFi.RSSI(),
             WiFi.channel(),
             WiFi.BSSIDstr().c_str());
    runUploadDnsDiagnostic();
    return true;
  }

  logEvent(LogLevel::Warn,
           "wifi_connect_timeout",
           "ssid=\"%s\" status=%s last_reason=%u last_reason_name=%s",
           WIFI_SSID,
           wlStatusName(WiFi.status()),
           static_cast<unsigned>(lastWifiDisconnectReason),
           disconnectReasonName(lastWifiDisconnectReason));
  return false;
#else
  return false;
#endif
}

static bool postBatch(const uint8_t* data,
                      size_t len,
                      uint32_t batchSeq,
                      uint32_t recordCount,
                      int* responseCodeOut = nullptr) {
  if (responseCodeOut != nullptr) {
    *responseCodeOut = 0;
  }

#if !UPLOAD_ENABLED
  ++uploadDryRunBatches;
  uploadBytesDryRun += static_cast<uint32_t>(len);
  if (responseCodeOut != nullptr) {
    *responseCodeOut = 200;
  }
  return true;
#else
  ++httpAttempts;

  if (!ensureWifiConnected()) {
    ++httpFailures;
    if (responseCodeOut != nullptr) {
      *responseCodeOut = 0;
    }
    if (uploadWifiEverConnected) {
      logEvent(LogLevel::Warn,
               "upload_batch_failed",
               "reason=wifi_unavailable code=0 batch=%lu records=%lu bytes=%u",
               static_cast<unsigned long>(batchSeq),
               static_cast<unsigned long>(recordCount),
               static_cast<unsigned>(len));
    }
    return false;
  }

  int responseCode = -1;
  bool reused = false;
  const uint32_t uploadStartedMs = millis();
  const bool began = beginUploadHttpClient(&reused);

  if (!began) {
    const uint32_t uploadMs = millis() - uploadStartedMs;
    updateHttpTiming(uploadMs);
    ++httpFailures;
    if (responseCodeOut != nullptr) {
      *responseCodeOut = responseCode;
    }
    logEvent(LogLevel::Warn,
             "upload_batch_failed",
             "reason=http_begin_failed code=%d error=\"%s\" batch=%lu records=%lu bytes=%u upload_ms=%lu",
             responseCode,
             responseCode < 0 ? HTTPClient::errorToString(responseCode).c_str() : "",
             static_cast<unsigned long>(batchSeq),
             static_cast<unsigned long>(recordCount),
             static_cast<unsigned>(len),
             static_cast<unsigned long>(uploadMs));
    return false;
  }

  if (reused) {
    ++httpClientReuses;
  }

  addUploadHttpHeaders(batchSeq, recordCount);
  responseCode = uploadHttp.POST(const_cast<uint8_t*>(data), len);
  if (responseCode > 0) {
    drainUploadHttpResponseBody();
  }

  const uint32_t uploadMs = millis() - uploadStartedMs;
  updateHttpTiming(uploadMs);

  if (responseCode >= 200 && responseCode < 300) {
    ++httpSuccesses;
    uploadBytesSent += static_cast<uint32_t>(len);
    if (responseCodeOut != nullptr) {
      *responseCodeOut = responseCode;
    }
    return true;
  }

  ++httpFailures;
  if (responseCodeOut != nullptr) {
    *responseCodeOut = responseCode;
  }
  if (responseCode < 0) {
    closeUploadHttpClient();
  }
  logEvent(LogLevel::Warn,
           "upload_batch_failed",
           "reason=http_status code=%d error=\"%s\" batch=%lu records=%lu bytes=%u upload_ms=%lu reused=%u",
           responseCode,
           responseCode < 0 ? HTTPClient::errorToString(responseCode).c_str() : "",
           static_cast<unsigned long>(batchSeq),
           static_cast<unsigned long>(recordCount),
           static_cast<unsigned>(len),
           static_cast<unsigned long>(uploadMs),
           static_cast<unsigned>(reused ? 1 : 0));
  return false;
#endif
}

static void setPendingUploadBatch(size_t batchBytes, uint32_t batchSeq, uint32_t recordCount) {
  uploadRetryPending = true;
  uploadRetryBytes = batchBytes;
  uploadRetryBatchSeq = batchSeq;
  uploadRetryRecordCount = recordCount;
  uploadRetryAttempts = 0;
  uploadRetryFailures = 0;
  uploadRetryLastAttemptMs = 0;
  uploadRetryLastCode = 0;
}

static void clearPendingUploadBatch() {
  uploadRetryPending = false;
  uploadRetryBytes = 0;
  uploadRetryBatchSeq = 0;
  uploadRetryRecordCount = 0;
  uploadRetryAttempts = 0;
  uploadRetryFailures = 0;
  uploadRetryLastAttemptMs = 0;
  uploadRetryLastCode = 0;
}

static bool attemptPendingUploadBatch() {
  if (!uploadRetryPending) {
    return true;
  }

  uploadRetryLastAttemptMs = millis();
  ++uploadRetryAttempts;

  int responseCode = 0;
  const bool uploaded = postBatch(uploadBatchBuf,
                                  uploadRetryBytes,
                                  uploadRetryBatchSeq,
                                  uploadRetryRecordCount,
                                  &responseCode);
  uploadRetryLastCode = responseCode;

  if (!uploaded) {
    ++uploadRetryFailures;
    return false;
  }

  if (uploadRetryFailures > 0) {
    logEvent(LogLevel::Info,
             "upload_batch_recovered",
             "batch=%lu records=%lu bytes=%u attempts=%lu failures=%lu code=%d upload_ms=%lu",
             static_cast<unsigned long>(uploadRetryBatchSeq),
             static_cast<unsigned long>(uploadRetryRecordCount),
             static_cast<unsigned>(uploadRetryBytes),
             static_cast<unsigned long>(uploadRetryAttempts),
             static_cast<unsigned long>(uploadRetryFailures),
             responseCode,
             static_cast<unsigned long>(httpLastMs));
  }

  clearPendingUploadBatch();
  return true;
}

static void uploadTask(void*) {
  while (true) {
    if (uploadRetryPending) {
      const uint32_t now = millis();
      if (uploadRetryLastAttemptMs != 0 &&
          (now - uploadRetryLastAttemptMs) < UPLOAD_RETRY_INTERVAL_MS) {
        delay(50);
        continue;
      }

      attemptPendingUploadBatch();
      continue;
    }

    if (!shouldFlushUploadQueue()) {
      delay(50);
      continue;
    }

    size_t batchBytes = 0;
    uint32_t batchSeq = 0;
    uint32_t recordCount = 0;
    if (buildUploadBatch(&batchBytes, &batchSeq, &recordCount)) {
      setPendingUploadBatch(batchBytes, batchSeq, recordCount);
      attemptPendingUploadBatch();
    }
  }
}

static void printDeviceStatus() {
  const uint32_t now = millis();
  if ((now - lastDeviceStatusMs) < DEVICE_STATUS_INTERVAL_MS) {
    return;
  }

  const uint32_t elapsedMs = lastDeviceStatusMs == 0 ? now : now - lastDeviceStatusMs;
  lastDeviceStatusMs = now;

#if UPLOAD_ENABLED
  if (!uploadWifiEverConnected) {
    UploadQueueSnapshot quietQueue = {};
    if (getUploadQueueSnapshot(&quietQueue)) {
      lastStatusUploadDropped = quietQueue.recordsDropped;
    }
    lastStatusCounters = getSenderCounterSnapshot();
    return;
  }
#endif

  UploadQueueSnapshot queue = {};
  if (!getUploadQueueSnapshot(&queue)) {
    logEvent(LogLevel::Warn, "upload_queue_snapshot_failed");
    return;
  }

  const MemorySnapshot memory = getMemorySnapshot();
  const SenderCounterSnapshot counters = getSenderCounterSnapshot();

  const uint32_t rxDelta = counters.recordsReceived - lastStatusCounters.recordsReceived;
  const uint32_t crcDelta = counters.crcErrors - lastStatusCounters.crcErrors;
  const uint32_t badDelta = counters.badPackets - lastStatusCounters.badPackets;
  const uint32_t spiErrorDelta = counters.spiErrors - lastStatusCounters.spiErrors;
  const uint32_t readyTimeoutDelta = counters.readyTimeouts - lastStatusCounters.readyTimeouts;
  const uint32_t droppedDelta = queue.recordsDropped - lastStatusUploadDropped;

  updatePressureWarnings(queue, memory, droppedDelta);

  Serial.printf("INFO event=device_status uptime_ms=%lu elapsed_ms=%lu upload_enabled=%u heap_free=%lu heap_min_free=%lu heap_max_alloc=%lu heap_used_pct=%u upload_depth=%u upload_capacity=%u upload_frame_bytes=%lu upload_frame_capacity=%u upload_frame_max=%lu upload_oldest_ms=%lu upload_max_depth=%u upload_queued=%lu upload_dropped=%lu upload_dropped_1s=%lu upload_batched=%lu upload_batches=%lu upload_dry_batches=%lu http_attempt=%lu http_ok=%lu http_fail=%lu http_connects=%lu http_reuse=%lu http_last_ms=%lu http_max_ms=%lu retry_pending=%u retry_batch=%lu retry_records=%lu retry_bytes=%u retry_attempts=%lu retry_failures=%lu retry_code=%d bytes_sent=%lu dry_bytes=%lu rx_1s=%lu rx_total=%lu crc_1s=%lu bad_1s=%lu spi_err_1s=%lu ready_timeout_1s=%lu\n",
                static_cast<unsigned long>(now),
                static_cast<unsigned long>(elapsedMs),
                static_cast<unsigned>(UPLOAD_ENABLED),
                static_cast<unsigned long>(memory.freeHeap),
                static_cast<unsigned long>(memory.minFreeHeap),
                static_cast<unsigned long>(memory.maxAllocHeap),
                static_cast<unsigned>(memory.heapUsedPct),
                static_cast<unsigned>(queue.depth),
                static_cast<unsigned>(UPLOAD_QUEUE_CAPACITY),
                static_cast<unsigned long>(queue.frameBytes),
                static_cast<unsigned>(UPLOAD_FRAME_QUEUE_BYTES),
                static_cast<unsigned long>(queue.frameMaxBytes),
                static_cast<unsigned long>(queue.oldestAgeMs),
                static_cast<unsigned>(queue.maxDepth),
                static_cast<unsigned long>(queue.recordsQueued),
                static_cast<unsigned long>(queue.recordsDropped),
                static_cast<unsigned long>(droppedDelta),
                static_cast<unsigned long>(queue.recordsBatched),
                static_cast<unsigned long>(queue.batchesBuilt),
                static_cast<unsigned long>(queue.dryRunBatches),
                static_cast<unsigned long>(queue.httpAttempts),
                static_cast<unsigned long>(queue.httpSuccesses),
                static_cast<unsigned long>(queue.httpFailures),
                static_cast<unsigned long>(queue.httpClientBegins),
                static_cast<unsigned long>(queue.httpClientReuses),
                static_cast<unsigned long>(queue.httpLastMs),
                static_cast<unsigned long>(queue.httpMaxMs),
                static_cast<unsigned>(uploadRetryPending ? 1 : 0),
                static_cast<unsigned long>(uploadRetryBatchSeq),
                static_cast<unsigned long>(uploadRetryRecordCount),
                static_cast<unsigned>(uploadRetryBytes),
                static_cast<unsigned long>(uploadRetryAttempts),
                static_cast<unsigned long>(uploadRetryFailures),
                uploadRetryLastCode,
                static_cast<unsigned long>(queue.bytesSent),
                static_cast<unsigned long>(queue.dryRunBytes),
                static_cast<unsigned long>(rxDelta),
                static_cast<unsigned long>(counters.recordsReceived),
                static_cast<unsigned long>(crcDelta),
                static_cast<unsigned long>(badDelta),
                static_cast<unsigned long>(spiErrorDelta),
                static_cast<unsigned long>(readyTimeoutDelta));

  for (const SnifferLink& sniffer : sniffers) {
    if (!sniffer.enabled) {
      continue;
    }

    if (!sniffer.statusSeen) {
      Serial.printf("INFO event=sniffer_status source=%s status_seen=0 sender_rx=%lu sender_crc=%lu sender_bad=%lu sender_spi_err=%lu sender_ready_timeout=%lu\n",
                    sniffer.name,
                    static_cast<unsigned long>(sniffer.recordsReceived),
                    static_cast<unsigned long>(sniffer.crcErrors),
                    static_cast<unsigned long>(sniffer.badPackets),
                    static_cast<unsigned long>(sniffer.spiErrors),
                    static_cast<unsigned long>(sniffer.readyTimeouts));
      continue;
    }

    const uint32_t statusAgeMs = now - sniffer.lastStatusMs;
    const status_packet_t& status = sniffer.lastStatus;
    Serial.printf("INFO event=sniffer_status source=%s age_ms=%lu wifi=%u captured=%lu queued=%lu dropped=%lu depth=%u max_depth=%u spi_send_failures=%lu sender_rx=%lu sender_crc=%lu sender_bad=%lu sender_spi_err=%lu sender_ready_timeout=%lu\n",
                  sniffer.name,
                  static_cast<unsigned long>(statusAgeMs),
                  static_cast<unsigned>(status.wifi_ready),
                  static_cast<unsigned long>(status.packets_captured),
                  static_cast<unsigned long>(status.records_queued),
                  static_cast<unsigned long>(status.records_dropped),
                  static_cast<unsigned>(status.queue_depth),
                  static_cast<unsigned>(status.max_queue_depth),
                  static_cast<unsigned long>(status.spi_send_failures),
                  static_cast<unsigned long>(sniffer.recordsReceived),
                  static_cast<unsigned long>(sniffer.crcErrors),
                  static_cast<unsigned long>(sniffer.badPackets),
                  static_cast<unsigned long>(sniffer.spiErrors),
                  static_cast<unsigned long>(sniffer.readyTimeouts));
  }

  lastStatusCounters = counters;
  lastStatusUploadDropped = queue.recordsDropped;
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
    logEvent(LogLevel::Error, "spi_bus_initialize_failed", "err=%d", static_cast<int>(err));
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
    logEvent(LogLevel::Error,
             "spi_bus_add_device_failed",
             "source=%s err=%d",
             sniffer.name,
             static_cast<int>(err));
    return false;
  }

  return true;
}

void setup() {
  Serial.begin(115200);
  delay(800);

#if UPLOAD_ENABLED
  WiFi.onEvent(onWiFiEvent);
#endif

#if !UPLOAD_ENABLED
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
#endif

  if (!initUploadBuffers()) {
    while (true) {
      delay(1000);
    }
  }

  uploadQueueMutex = xSemaphoreCreateMutex();
  if (uploadQueueMutex == nullptr) {
    logEvent(LogLevel::Error, "upload_queue_mutex_init_failed");
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
    logEvent(LogLevel::Error, "spi_master_init_failed");
    while (true) {
      delay(1000);
    }
  }

  logEvent(LogLevel::Info,
           "sender_starting",
           "spi_clock=%lu transfer_bytes=%u max_frame=%u",
           static_cast<unsigned long>(SPI_CLOCK_HZ),
           static_cast<unsigned>(SPI_TRANSFER_BYTES),
           static_cast<unsigned>(MAX_FRAME_BYTES));
  logEvent(LogLevel::Info,
           "uploader_config",
           "enabled=%u url=%s device=%s tls_insecure=%u queue=%u frame_queue_bytes=%u batch_max=%u records_per_batch=%lu status_len=%u",
           static_cast<unsigned>(UPLOAD_ENABLED),
           UPLOAD_URL,
           DEVICE_ID,
           static_cast<unsigned>(HTTP_TLS_INSECURE),
           static_cast<unsigned>(UPLOAD_QUEUE_CAPACITY),
           static_cast<unsigned>(UPLOAD_FRAME_QUEUE_BYTES),
           static_cast<unsigned>(MAX_HTTP_BATCH_BYTES),
           static_cast<unsigned long>(MAX_BATCH_RECORDS),
           static_cast<unsigned>(sizeof(sender_status_t)));

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
    logEvent(LogLevel::Error, "upload_task_start_failed");
  }
}

void loop() {
  for (SnifferLink& sniffer : sniffers) {
    if (!sniffer.enabled || sniffer.device == nullptr) {
      continue;
    }

    pollSniffer(sniffer);
  }

  printDeviceStatus();
  delay(1);
}
