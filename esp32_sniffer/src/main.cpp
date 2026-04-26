#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>

extern "C" {
  #include "esp_wifi.h"
}

#include "driver/spi_slave.h"

static constexpr int PIN_SPI_SCLK = 18;
static constexpr int PIN_SPI_MISO = 19;
static constexpr int PIN_SPI_MOSI = 23;

// local CS input from this sniffer's dedicated sender CS line
static constexpr int PIN_SPI_CS = 27;

// local READY output to sender
static constexpr int PIN_READY = 33;

static constexpr spi_host_device_t SPI_HOST_DEVICE = SPI3_HOST;
static constexpr uint32_t RECORD_MAGIC = 0x534E4946UL;  // "SNIF" numeric magic
static constexpr uint32_t STATUS_MAGIC = 0x53544154UL;  // "STAT" numeric magic
static constexpr uint16_t PROTOCOL_VERSION = 1;
static constexpr size_t RECORD_HEADER_BYTES = 24;
static constexpr size_t MAX_FRAME_BYTES = 512;
static constexpr size_t SPI_TRANSFER_BYTES = RECORD_HEADER_BYTES + MAX_FRAME_BYTES;
static constexpr size_t RING_CAPACITY = 32;
static constexpr uint32_t READY_LOW_HOLD_US = 500;
static constexpr uint32_t CHANNEL_HOP_MS = 500;
static constexpr TickType_t SPI_WAIT_TICKS = pdMS_TO_TICKS(20);

static constexpr uint16_t FLAG_TRUNCATED = 1 << 0;

static constexpr uint8_t TARGET_CHANNELS[] = {1, 6, 11};

typedef struct __attribute__((packed)) {
  uint32_t magic;       // 0x534E4946 = "SNIF"
  uint16_t version;     // 1
  uint16_t header_len;  // sizeof(record header)
  uint32_t seq;         // per-sniffer sequence
  uint32_t ts_us;       // low 32 bits of local rx timestamp
  int8_t rssi;
  uint8_t channel;
  uint16_t frame_len;   // raw 802.11 frame bytes that follow
  uint16_t flags;       // bit 0: frame truncated to MAX_FRAME_BYTES
  uint16_t crc16;       // CRC-16/CCITT-FALSE over payload only
} sniff_record_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;             // 0x53544154 = "STAT"
  uint16_t version;
  uint16_t header_len;
  uint32_t packets_captured;  // management frames seen by the callback
  uint32_t records_queued;    // total records accepted into the queue
  uint32_t records_dropped;   // oldest records dropped when full
  uint32_t spi_send_failures; // local SPI driver failures only
  uint16_t queue_depth;
  uint16_t max_queue_depth;
  uint32_t status_packets;
  uint32_t wifi_init_error;
  uint8_t wifi_ready;
  uint8_t reserved[3];
} status_packet_t;

static_assert(sizeof(sniff_record_t) == RECORD_HEADER_BYTES, "unexpected record header size");
static_assert(sizeof(status_packet_t) <= SPI_TRANSFER_BYTES, "status packet does not fit SPI transfer");

struct QueuedRecord {
  sniff_record_t header;
  uint8_t frame[MAX_FRAME_BYTES];
};

DRAM_ATTR static uint8_t rxBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));
DRAM_ATTR static uint8_t txBuf[SPI_TRANSFER_BYTES] __attribute__((aligned(4)));

static portMUX_TYPE queueMux = portMUX_INITIALIZER_UNLOCKED;
static QueuedRecord ring[RING_CAPACITY];
static size_t ringHead = 0;
static size_t ringCount = 0;

static uint32_t nextSeq = 1;
static uint32_t packetsCaptured = 0;
static uint32_t recordsQueued = 0;
static uint32_t recordsDropped = 0;
static uint32_t spiSendFailures = 0;
static uint16_t maxQueueDepth = 0;
static uint32_t statusPackets = 0;
static uint32_t wifiInitError = 0;
static bool wifiReady = false;

static uint8_t currentChannelIndex = 0;
static uint32_t lastHopMs = 0;

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

static void fillStatusPacket() {
  status_packet_t status = {};

  portENTER_CRITICAL(&queueMux);
  ++statusPackets;
  status.magic = STATUS_MAGIC;
  status.version = PROTOCOL_VERSION;
  status.header_len = sizeof(status_packet_t);
  status.packets_captured = packetsCaptured;
  status.records_queued = recordsQueued;
  status.records_dropped = recordsDropped;
  status.spi_send_failures = spiSendFailures;
  status.queue_depth = static_cast<uint16_t>(ringCount);
  status.max_queue_depth = maxQueueDepth;
  status.status_packets = statusPackets;
  status.wifi_init_error = wifiInitError;
  status.wifi_ready = wifiReady ? 1 : 0;
  portEXIT_CRITICAL(&queueMux);

  memset(txBuf, 0, sizeof(txBuf));
  memcpy(txBuf, &status, sizeof(status));
}

static bool popRecordIntoTxBuffer() {
  portENTER_CRITICAL(&queueMux);
  if (ringCount == 0) {
    portEXIT_CRITICAL(&queueMux);
    return false;
  }

  QueuedRecord record = ring[ringHead];
  ringHead = (ringHead + 1) % RING_CAPACITY;
  --ringCount;
  portEXIT_CRITICAL(&queueMux);

  memset(txBuf, 0, sizeof(txBuf));
  memcpy(txBuf, &record.header, sizeof(record.header));
  memcpy(txBuf + sizeof(record.header), record.frame, record.header.frame_len);
  return true;
}

static void prepareNextTxPacket() {
  if (!popRecordIntoTxBuffer()) {
    fillStatusPacket();
  }
}

static void enqueueManagementFrame(const wifi_promiscuous_pkt_t* pkt) {
  const uint16_t rxLen = static_cast<uint16_t>(pkt->rx_ctrl.sig_len);
  if (rxLen < 24) {
    return;
  }

  const uint16_t copyLen = min<uint16_t>(rxLen, MAX_FRAME_BYTES);
  QueuedRecord record = {};
  record.header.magic = RECORD_MAGIC;
  record.header.version = PROTOCOL_VERSION;
  record.header.header_len = sizeof(sniff_record_t);
  record.header.seq = nextSeq++;
  record.header.ts_us = static_cast<uint32_t>(pkt->rx_ctrl.timestamp);
  record.header.rssi = pkt->rx_ctrl.rssi;
  record.header.channel = pkt->rx_ctrl.channel;
  record.header.frame_len = copyLen;
  record.header.flags = rxLen > MAX_FRAME_BYTES ? FLAG_TRUNCATED : 0;
  memcpy(record.frame, pkt->payload, copyLen);
  record.header.crc16 = crc16CcittFalse(record.frame, copyLen);

  portENTER_CRITICAL(&queueMux);
  ++packetsCaptured;

  if (ringCount == RING_CAPACITY) {
    ringHead = (ringHead + 1) % RING_CAPACITY;
    --ringCount;
    ++recordsDropped;
  }

  const size_t writeIndex = (ringHead + ringCount) % RING_CAPACITY;
  ring[writeIndex] = record;
  ++ringCount;
  ++recordsQueued;
  if (ringCount > maxQueueDepth) {
    maxQueueDepth = static_cast<uint16_t>(ringCount);
  }
  portEXIT_CRITICAL(&queueMux);
}

static void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || buf == nullptr) {
    return;
  }

  const wifi_promiscuous_pkt_t* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  enqueueManagementFrame(pkt);
}

static void maybeHopChannel() {
  if (!wifiReady) {
    return;
  }

  const uint32_t now = millis();
  if ((now - lastHopMs) < CHANNEL_HOP_MS) {
    return;
  }

  currentChannelIndex = (currentChannelIndex + 1) % (sizeof(TARGET_CHANNELS) / sizeof(TARGET_CHANNELS[0]));
  esp_wifi_set_channel(TARGET_CHANNELS[currentChannelIndex], WIFI_SECOND_CHAN_NONE);
  lastHopMs = now;
}

static esp_err_t initWifiSniffer() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_err_t err = esp_wifi_set_promiscuous_filter(&filter);
  if (err != ESP_OK) {
    Serial.printf("esp_wifi_set_promiscuous_filter failed: %d\n", static_cast<int>(err));
    return err;
  }

  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);

  err = esp_wifi_set_promiscuous(true);
  if (err != ESP_OK) {
    Serial.printf("esp_wifi_set_promiscuous failed: %d\n", static_cast<int>(err));
    return err;
  }

  err = esp_wifi_set_channel(TARGET_CHANNELS[currentChannelIndex], WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK) {
    Serial.printf("esp_wifi_set_channel failed: %d\n", static_cast<int>(err));
    return err;
  }

  lastHopMs = millis();
  return ESP_OK;
}

static bool initSpiSlave() {
  spi_bus_config_t busConfig = {};
  busConfig.mosi_io_num = PIN_SPI_MOSI;
  busConfig.miso_io_num = PIN_SPI_MISO;
  busConfig.sclk_io_num = PIN_SPI_SCLK;
  busConfig.quadwp_io_num = -1;
  busConfig.quadhd_io_num = -1;
  busConfig.max_transfer_sz = SPI_TRANSFER_BYTES;

  spi_slave_interface_config_t slaveConfig = {};
  slaveConfig.mode = SPI_MODE0;
  slaveConfig.spics_io_num = PIN_SPI_CS;
  slaveConfig.queue_size = 1;
  slaveConfig.flags = 0;

#if defined(SPI_DMA_CH_AUTO)
  const esp_err_t err = spi_slave_initialize(SPI_HOST_DEVICE, &busConfig, &slaveConfig, SPI_DMA_CH_AUTO);
#else
  const esp_err_t err = spi_slave_initialize(SPI_HOST_DEVICE, &busConfig, &slaveConfig, 1);
#endif
  if (err != ESP_OK) {
    Serial.printf("spi_slave_initialize failed: %d\n", static_cast<int>(err));
    return false;
  }

  return true;
}

void setup() {
  Serial.begin(115200);
  delay(800);

  pinMode(PIN_READY, OUTPUT);
  digitalWrite(PIN_READY, LOW);

  if (!initSpiSlave()) {
    Serial.println("SPI slave init failed. Check pin choices and board target.");
    while (true) {
      digitalWrite(PIN_READY, LOW);
      delay(1000);
    }
  }

  const esp_err_t wifiErr = initWifiSniffer();
  if (wifiErr != ESP_OK) {
    portENTER_CRITICAL(&queueMux);
    wifiReady = false;
    wifiInitError = static_cast<uint32_t>(wifiErr);
    portEXIT_CRITICAL(&queueMux);
    Serial.printf("WiFi promiscuous sniffer init failed: %d. SPI status packets will still be served.\n",
                  static_cast<int>(wifiErr));
  } else {
    portENTER_CRITICAL(&queueMux);
    wifiReady = true;
    wifiInitError = 0;
    portEXIT_CRITICAL(&queueMux);
  }

  prepareNextTxPacket();

  Serial.println("ESP32 WiFi management sniffer ready.");
  Serial.printf("SPI transfer=%u bytes, max_frame=%u bytes, queue=%u records\n",
                static_cast<unsigned>(SPI_TRANSFER_BYTES),
                static_cast<unsigned>(MAX_FRAME_BYTES),
                static_cast<unsigned>(RING_CAPACITY));
}

void loop() {
  spi_slave_transaction_t transaction = {};
  transaction.length = SPI_TRANSFER_BYTES * 8;
  transaction.tx_buffer = txBuf;
  transaction.rx_buffer = rxBuf;

  esp_err_t err = spi_slave_queue_trans(SPI_HOST_DEVICE, &transaction, portMAX_DELAY);
  if (err != ESP_OK) {
    portENTER_CRITICAL(&queueMux);
    ++spiSendFailures;
    portEXIT_CRITICAL(&queueMux);
    Serial.printf("spi_slave_queue_trans failed: %d\n", static_cast<int>(err));
    delay(100);
    return;
  }

  digitalWrite(PIN_READY, HIGH);

  spi_slave_transaction_t* completed = nullptr;
  while (true) {
    err = spi_slave_get_trans_result(SPI_HOST_DEVICE, &completed, SPI_WAIT_TICKS);
    maybeHopChannel();

    if (err == ESP_ERR_TIMEOUT) {
      continue;
    }
    break;
  }

  digitalWrite(PIN_READY, LOW);
  delayMicroseconds(READY_LOW_HOLD_US);

  if (err != ESP_OK || completed == nullptr) {
    portENTER_CRITICAL(&queueMux);
    ++spiSendFailures;
    portEXIT_CRITICAL(&queueMux);
    Serial.printf("spi_slave_get_trans_result failed: %d\n", static_cast<int>(err));
    prepareNextTxPacket();
    return;
  }

  prepareNextTxPacket();

  static uint32_t lastStatsMs = 0;
  const uint32_t now = millis();
  if ((now - lastStatsMs) >= 5000) {
    portENTER_CRITICAL(&queueMux);
    const uint32_t captured = packetsCaptured;
    const uint32_t queued = recordsQueued;
    const uint32_t dropped = recordsDropped;
    const uint16_t depth = static_cast<uint16_t>(ringCount);
    const uint16_t maxDepth = maxQueueDepth;
    const uint32_t spiFails = spiSendFailures;
    portEXIT_CRITICAL(&queueMux);

    Serial.printf("sniffer stats: captured=%lu queued=%lu dropped=%lu depth=%u max_depth=%u spi_fail=%lu ch=%u\n",
                  captured,
                  queued,
                  dropped,
                  depth,
                  maxDepth,
                  spiFails,
                  TARGET_CHANNELS[currentChannelIndex]);
    lastStatsMs = now;
  }
}
