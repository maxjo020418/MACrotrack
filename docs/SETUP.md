# MACrotrack Setup

This document lists the constants and local files that need to be configured before uploading the firmware.

## Project Layout

```text
esp32_sniffer/
  src/main.cpp              WiFi management-frame capture + SPI slave

esp32_sender/
  src/main.cpp              SPI master + upload queue + HTTP uploader
  include/secrets.example.h tracked template
  include/secrets.h         local secrets, ignored by git
```

Build commands:

```bash
cd /home/maxjo/Work/MACrotrack/esp32_sniffer
/home/maxjo/.platformio/penv/bin/pio run

cd /home/maxjo/Work/MACrotrack/esp32_sender
/home/maxjo/.platformio/penv/bin/pio run
```

Upload commands:

```bash
cd /home/maxjo/Work/MACrotrack/esp32_sniffer
/home/maxjo/.platformio/penv/bin/pio run -t upload

cd /home/maxjo/Work/MACrotrack/esp32_sender
/home/maxjo/.platformio/penv/bin/pio run -t upload
```

Monitor sender:

```bash
cd /home/maxjo/Work/MACrotrack/esp32_sender
/home/maxjo/.platformio/penv/bin/pio device monitor -p /dev/ttyUSB0 -b 115200 --raw
```

Only one process can use `/dev/ttyUSB0` at a time. Close the serial monitor before uploading.

## Wiring

For the current single-sniffer setup:

```text
sender GPIO18 SCLK  -> sniffer GPIO18 SCLK
sender GPIO23 MOSI  -> sniffer GPIO23 MOSI
sender GPIO19 MISO  -> sniffer GPIO19 MISO
sender GPIO25 CS1   -> sniffer GPIO27 CS
sniffer GPIO33 RDY  -> sender GPIO32 RDY1
GND                 -> GND
```

Both PlatformIO configs currently use:

```ini
upload_port = /dev/ttyUSB0
monitor_port = /dev/ttyUSB0
monitor_speed = 115200
```

If both ESP32s are connected at once, give each project the correct upload and monitor port.

## Sender Secrets

The sender supports a GitHub-safe local secrets header.

Create it from the template:

```bash
cp /home/maxjo/Work/MACrotrack/esp32_sender/include/secrets.example.h \
   /home/maxjo/Work/MACrotrack/esp32_sender/include/secrets.h
```

Edit:

```cpp
#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASS "your-wifi-password"

#define DEVICE_ID "sender-001"
#define API_TOKEN "replace-with-device-token"
#define UPLOAD_URL "https://example.com/api/sniff/batch"

#define UPLOAD_ENABLED 0
#define HTTP_TLS_INSECURE 0
#define DEBUG_PRINT_RECORDS 1
```

`include/secrets.h` is ignored by git in `esp32_sender/.gitignore`.

Recommended development values before the server exists:

```cpp
#define UPLOAD_ENABLED 0
#define DEBUG_PRINT_RECORDS 1
```

Recommended values when testing a real endpoint:

```cpp
#define UPLOAD_ENABLED 1
#define DEBUG_PRINT_RECORDS 0
```

Use `HTTP_TLS_INSECURE=1` only for temporary development HTTPS endpoints with no trusted certificate. Do not ship that setting.

## Sender Constants

These are in `esp32_sender/src/main.cpp`.

SPI and record sizing:

```cpp
MAX_FRAME_BYTES = 512
SPI_TRANSFER_BYTES = 24 + 512
SPI_CLOCK_HZ = 10000000
```

Upload queue and batching:

```cpp
UPLOAD_QUEUE_CAPACITY = 64
MAX_HTTP_BATCH_BYTES = 8192
MAX_BATCH_RECORDS = 32
FLUSH_INTERVAL_MS = 1000
```

Network behavior:

```cpp
WIFI_CONNECT_TIMEOUT_MS = 15000
WIFI_RECONNECT_INTERVAL_MS = 5000
HTTP_TIMEOUT_MS = 8000
```

Status printing:

```cpp
STATUS_PRINT_INTERVAL_MS = 2000
UPLOAD_STATUS_INTERVAL_MS = 5000
```

Multi-sniffer table:

```cpp
static SnifferLink sniffers[] = {
  {"sniffer1", 1, PIN_CS_SNIFFER1, PIN_RDY_SNIFFER1, true, ...},
  {"sniffer2", 2, PIN_CS_SNIFFER2, PIN_RDY_SNIFFER2, false, ...},
};
```

To enable a second sniffer, add wiring for its CS/READY pair and change its `enabled` field to `true`. For multiple ESP32 SPI slaves, use external tri-state buffering on shared MISO unless you have verified the slaves tri-state correctly.

## Sniffer Constants

These are in `esp32_sniffer/src/main.cpp`.

SPI and capture sizing:

```cpp
MAX_FRAME_BYTES = 512
SPI_TRANSFER_BYTES = 24 + 512
RING_CAPACITY = 32
```

Channel hopping:

```cpp
TARGET_CHANNELS = {1, 6, 11}
CHANNEL_HOP_MS = 500
```

READY timing:

```cpp
READY_LOW_HOLD_US = 500
SPI_WAIT_TICKS = 20 ms
```

The sniffer captures management frames only:

```cpp
WIFI_PROMIS_FILTER_MASK_MGMT
```

It drops oldest records when the sniffer ring buffer is full and increments `records_dropped`.

## HTTP Endpoint Contract

The sender sends:

```text
POST <UPLOAD_URL>
Content-Type: application/octet-stream
Authorization: Bearer <API_TOKEN>
X-Device-Id: <DEVICE_ID>
X-Batch-Version: 1
X-Batch-Seq: <batch_seq>
X-Record-Count: <record_count>
```

Any `2xx` response is treated as success.

The binary body is:

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
  uint16_t header_len;
  uint32_t batch_seq;
  uint32_t record_count;
  uint32_t payload_len;
  uint32_t uptime_ms;
  uint32_t flags;
} batch_header_t;
```

Per-record prefix:

```cpp
typedef struct __attribute__((packed)) {
  uint16_t source_id;
  uint16_t record_len;
} upload_record_prefix_t;
```

Then the original `sniff_record_t` follows, followed by `frame_len` raw bytes.

## GitHub-Safe Secrets

The current recommended approach is:

1. Commit `include/secrets.example.h`.
2. Do not commit `include/secrets.h`.
3. Each developer or device owner creates their own local `include/secrets.h`.

This is the closest simple equivalent to `.env` for Arduino/PlatformIO firmware because the values become compile-time constants.

Before pushing to GitHub, verify:

```bash
git status --short
```

`esp32_sender/include/secrets.h` should not appear.

## Is There a `.env` Method?

There is no native runtime `.env` loader in ESP32 Arduino firmware like there is in many server-side apps. Firmware is compiled before upload, so secrets usually enter through one of these approaches.

### Option A: Ignored `secrets.h`

This is what the project currently uses.

Pros:

- Simple.
- Works with PlatformIO and Arduino.
- Easy to document.
- Does not require extra build scripts.

Cons:

- Values are still compiled into firmware.
- Changing secrets requires rebuilding and re-uploading.

### Option B: PlatformIO Environment Variables

PlatformIO can pass build flags from your shell environment or an extra script. Example concept:

```bash
export MACROTRACK_WIFI_SSID="..."
export MACROTRACK_WIFI_PASS="..."
export MACROTRACK_API_TOKEN="..."
```

Then an `extra_scripts` Python script can generate an ignored header before compile.

Pros:

- Feels closer to `.env`.
- Keeps secrets out of source files.
- Good for CI/CD.

Cons:

- More moving parts.
- Quoting strings safely in `build_flags` is error-prone.
- Generated headers still compile secrets into firmware.

If you want this later, add a script that reads environment variables and writes `esp32_sender/include/secrets.generated.h`, then include that generated header from `main.cpp`.

### Option C: NVS/Preferences Provisioning

Store WiFi and API credentials in ESP32 NVS using the `Preferences` library. Provision them over serial, BLE, a temporary setup AP, or a local configuration endpoint.

Pros:

- Best long-term device workflow.
- Change credentials without rebuilding firmware.
- GitHub never sees secrets.

Cons:

- More firmware work.
- Need a provisioning UI or command protocol.
- Need a way to reset or rotate credentials.

### Option D: LittleFS/SPIFFS Config File

Upload a local JSON config file to flash filesystem and read it at runtime.

Pros:

- Runtime config file resembles `.env`.
- Can update config separately from firmware.

Cons:

- More flash/filesystem handling.
- Still need to keep local config files out of git.
- Less convenient than NVS for small key/value secrets.

## Recommendation

For now, keep the current `secrets.h` approach while the endpoint is still evolving.

When this becomes a deployed device, move to NVS provisioning:

```text
firmware image contains no WiFi password or API token
device is provisioned once after flashing
server can rotate/revoke per-device tokens
```

For CI builds, use Option B and generate the ignored secrets header from environment variables.
