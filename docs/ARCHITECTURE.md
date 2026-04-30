# MACrotrack Architecture

MACrotrack is split across two ESP32 firmware projects:

- `esp32_sniffer`: captures WiFi management frames and serves them over SPI as a slave.
- `esp32_sender`: acts as the SPI master, receives sniffer records, batches them, and optionally uploads them to an HTTP endpoint.

For the planned packet collection database behind the temporary `sniff-collector`
server, see `docs/SNIFF_COLLECTOR_DB_PLAN.md`.

The current implementation is designed around one sender and one sniffer, but the SPI bus layout and sender data model already leave room for multiple sniffers.

## Data Flow

```text
WiFi air traffic
    |
    v
esp32_sniffer promiscuous callback
    |
    v
SNIF record queue, 32 records, drop oldest when full
    |
    v
SPI slave packet, one record or one STAT packet per poll
    |
    v
esp32_sender SPI poller
    |
    v
CRC validation + optional serial print
    |
    v
sender upload queue, 64 records, drop oldest when full
    |
    v
binary HTTP batch builder
    |
    v
HTTP POST to upstream endpoint, when enabled
```

## Sniffer Behavior

The sniffer enables ESP32 WiFi promiscuous mode and filters for management frames only.

```cpp
filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
```

The callback also rejects any non-management frame:

```cpp
if (type != WIFI_PKT_MGMT || buf == nullptr) {
  return;
}
```

Captured records include the raw frame bytes from `pkt->payload`, up to `MAX_FRAME_BYTES`.

```text
802.11 management header
fixed management fields, depending on subtype
tagged IEs, when present
```

The code does not assume the WiFi FCS trailer is present. Treat `frame_len` as the number of usable MAC-frame bytes provided by ESP32 promiscuous mode.

Current capture constants:

```cpp
MAX_FRAME_BYTES = 512
RING_CAPACITY = 32
CHANNEL_HOP_MS = 500
TARGET_CHANNELS = {1, 6, 11}
```

If a frame is longer than `512` bytes, the sniffer truncates it and sets `FLAG_TRUNCATED`.

## Sniffer Record Format

Each captured frame is wrapped in a packed `SNIF` record header:

```cpp
typedef struct __attribute__((packed)) {
  uint32_t magic;       // 0x534E4946 = "SNIF"
  uint16_t version;     // 1
  uint16_t header_len;  // sizeof(record header), currently 24
  uint32_t seq;         // per-sniffer sequence
  uint32_t ts_us;       // low 32 bits of local rx timestamp
  int8_t rssi;
  uint8_t channel;
  uint16_t frame_len;   // raw 802.11 frame bytes that follow
  uint16_t flags;       // bit 0: truncated
  uint16_t crc16;       // CRC-16/CCITT-FALSE over frame bytes only
} sniff_record_t;
```

The SPI payload for a record is:

```text
sniff_record_t
frame_len bytes of raw 802.11 management frame
zero padding to fixed SPI transfer size
```

The `crc16` is for SPI transport integrity. It is not the WiFi FCS.

## Sniffer Status Packets

When the sniffer has no queued records, it sends a `STAT` packet instead:

```cpp
typedef struct __attribute__((packed)) {
  uint32_t magic;             // 0x53544154 = "STAT"
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
```

Useful status fields:

- `packets_captured`: management frames observed by the WiFi callback.
- `records_queued`: records accepted into the sniffer ring buffer.
- `records_dropped`: records dropped because the ring buffer was full.
- `queue_depth`: current sniffer queue depth.
- `max_queue_depth`: maximum depth since boot.
- `wifi_ready`: `1` when promiscuous WiFi capture initialized successfully.
- `wifi_init_error`: raw ESP error code if WiFi capture did not initialize.

## SPI Link

The sender is the SPI master. The sniffer is the SPI slave.

Current tested SPI settings:

```cpp
SPI_CLOCK_HZ = 10000000
SPI_TRANSFER_BYTES = 24 + 512 = 536
SPI mode = 0
bit order = MSB first
```

The sender polls continuously. The sniffer raises `READY` when a transaction is queued and ready to clock out.

For `sniffer1`:

```text
sender GPIO18 SCLK  -> sniffer GPIO18 SCLK
sender GPIO23 MOSI  -> sniffer GPIO23 MOSI
sender GPIO19 MISO  -> sniffer GPIO19 MISO
sender GPIO25 CS1   -> sniffer GPIO27 CS
sniffer GPIO33 RDY  -> sender GPIO32 RDY1
GND                 -> GND
```

The previous benchmark showed `10 MHz` was reliable on the current breadboard setup. `16 MHz` was not reliable.

## Sender Behavior

The sender:

1. Polls enabled sniffers over SPI.
2. Parses `SNIF` or `STAT` packets.
3. Validates `SNIF` packet CRC.
4. Optionally prints record summaries to serial.
5. Enqueues valid records into an HTTP upload queue.
6. Builds binary upload batches.
7. Uploads batches when enabled.

Debug print output includes:

- sniffer name
- sequence number
- timestamp
- channel
- RSSI
- management subtype
- frame length
- source, destination, and BSSID MAC addresses
- SSID, when a supported management subtype has an SSID IE

Only SSID is parsed for display right now. The full raw management frame, including IEs present in the ESP32 payload, is retained in the queued upload data.

## Upload Queue and Batch Format

The sender keeps a second queue for upload:

```cpp
UPLOAD_QUEUE_CAPACITY = 64
MAX_HTTP_BATCH_BYTES = 8192
MAX_BATCH_RECORDS = 32
FLUSH_INTERVAL_MS = 1000
```

The upload queue also drops oldest when full.

The HTTP body is binary:

```text
batch_header_t
upload_record_prefix_t + sniff_record_t + raw frame bytes
upload_record_prefix_t + sniff_record_t + raw frame bytes
...
```

Batch header:

```cpp
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
```

Record prefix:

```cpp
typedef struct __attribute__((packed)) {
  uint16_t source_id;    // 1 = sniffer1, 2 = sniffer2
  uint16_t record_len;   // sizeof(sniff_record_t) + frame_len
} upload_record_prefix_t;
```

The `sniff_record_t` inside the batch is unchanged from the SPI record format.

## HTTP Upload

When upload is enabled, the sender posts batches to:

```text
UPLOAD_URL
```

Request headers:

```text
Content-Type: application/octet-stream
Authorization: Bearer <API_TOKEN>
X-Device-Id: <DEVICE_ID>
X-Batch-Version: 1
X-Batch-Seq: <batch_seq>
X-Record-Count: <record_count>
```

Any `2xx` response is treated as success. Other responses are counted as upload failures.

In the current first implementation, failed batches are not retried. This keeps the SPI path simple and avoids blocking forever when the endpoint is down. A later version can add retry/backoff or local spooling.

## Multi-Sniffer Notes

The sender has a `sniffers[]` table with `source_id`, CS pin, READY pin, and enable flag.

Before adding multiple ESP32 slaves to one MISO line, confirm bus behavior carefully. ESP32 SPI slave can be problematic on shared MISO because inactive slaves may not fully tri-state MISO in all configurations. For more than one sniffer, use a tri-state buffer such as `74HC125` or `74LVC125` with each slave's MISO enabled only by its CS line.

## Known Limits

- Current maximum captured frame bytes: `512`.
- Current sniffer ring: `32` records, about 17 KB plus overhead.
- Current sender upload queue: `64` records, about 35 KB plus overhead.
- Current SPI transfer: fixed `536` bytes per poll.
- Current HTTP upload batch: up to `8192` bytes or `32` records.
- The sender upload task runs separately from SPI polling, but HTTP still consumes RAM and WiFi resources.
- HTTPS should use certificate validation for production. `HTTP_TLS_INSECURE=1` is development-only.
