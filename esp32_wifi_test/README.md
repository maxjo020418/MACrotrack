# ESP32 WiFi Test

Standalone PlatformIO project for testing ESP32 WiFi, DNS, and HTTP connectivity without running the SPI sender/sniffer pipeline.

## Setup

Copy the example secrets file and edit it:

```bash
cp include/secrets.example.h include/secrets.h
```

ESP32 classic WiFi is 2.4 GHz only. If the scan does not show your SSID, check that the network is not 5 GHz-only.

## PSK Network

Use this for normal WPA/WPA2 password WiFi:

```cpp
#define WIFI_SSID "your-2.4ghz-ssid"
#define WIFI_PASS "your-password"
#define WIFI_ENTERPRISE_ENABLED 0
#define TEST_URL "http://1.1.1.1"
```

## WPA2-Enterprise

Use this for username/password enterprise WiFi:

```cpp
#define WIFI_SSID "enterprise-ssid"
#define WIFI_ENTERPRISE_ENABLED 1
#define WIFI_ENTERPRISE_METHOD WIFI_ENTERPRISE_METHOD_TTLS
#define EAP_TTLS_PHASE2_METHOD ESP_EAP_TTLS_PHASE2_MSCHAPV2
#define EAP_IDENTITY ""
#define EAP_USERNAME "your-enterprise-id"
#define EAP_PASSWORD "your-enterprise-password"
#define TEST_URL "http://1.1.1.1"
```

Supported TTLS phase 2 values in the current Arduino/ESP-IDF stack:

```cpp
ESP_EAP_TTLS_PHASE2_EAP
ESP_EAP_TTLS_PHASE2_MSCHAPV2
ESP_EAP_TTLS_PHASE2_MSCHAP
ESP_EAP_TTLS_PHASE2_PAP
ESP_EAP_TTLS_PHASE2_CHAP
```

TTLS/GTC is not exposed by this stack. Setting `WIFI_ENTERPRISE_TTLS_PHASE2_GTC` will log an unsupported-mode error.

## Run

```bash
cd /home/maxjo/Work/MACrotrack/esp32_wifi_test
/home/maxjo/.platformio/penv/bin/pio run -t upload
/home/maxjo/.platformio/penv/bin/pio device monitor
```

## Log Guide

Healthy WiFi connection:

```text
INFO event=wifi_ssid_seen ...
INFO event=wifi_event_connected
INFO event=wifi_event_got_ip ip=...
INFO event=wifi_connected ... rssi=... channel=...
```

Healthy DNS:

```text
INFO event=dns_ok host=... ip=...
```

HTTP result codes:

```text
INFO event=http_result ... code=301
INFO event=http_result ... code=404
```

Positive `code` values are real HTTP responses. Negative values are ESP32 `HTTPClient` failures before a valid HTTP response was received.

Common WiFi failure hints:

```text
WARN event=wifi_ssid_not_seen
ERROR event=wifi_connect_timeout ... last_reason_name=NO_AP_FOUND
ERROR event=wifi_connect_timeout ... last_reason_name=AUTH_FAIL
ERROR event=enterprise_phase2_unsupported
```

`NO_AP_FOUND` usually means wrong SSID, weak signal, or 5 GHz-only network. `AUTH_FAIL` or handshake timeouts usually point to wrong credentials or incompatible security settings.
