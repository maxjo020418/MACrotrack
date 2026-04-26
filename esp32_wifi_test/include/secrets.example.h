#pragma once

// Copy this file to include/secrets.h and edit for your network.
// ESP32 classic WiFi supports 2.4 GHz networks only.

#define WIFI_SSID "your-2.4ghz-ssid"
#define WIFI_PASS "your-password"

// Set to 1 for WPA2-Enterprise instead of PSK.
#define WIFI_ENTERPRISE_ENABLED 0

// Enterprise mode options. This test project supports PEAP and TTLS.
// For TTLS phase 2, this Arduino/ESP-IDF stack exposes:
//   ESP_EAP_TTLS_PHASE2_EAP
//   ESP_EAP_TTLS_PHASE2_MSCHAPV2
//   ESP_EAP_TTLS_PHASE2_MSCHAP
//   ESP_EAP_TTLS_PHASE2_PAP
//   ESP_EAP_TTLS_PHASE2_CHAP
// TTLS/GTC is not exposed by this stack. Setting WIFI_ENTERPRISE_TTLS_PHASE2_GTC
// will log a clear unsupported-mode error.
#define WIFI_ENTERPRISE_METHOD WIFI_ENTERPRISE_METHOD_TTLS
#define EAP_TTLS_PHASE2_METHOD ESP_EAP_TTLS_PHASE2_MSCHAPV2

// Outer identity can be anonymous on some networks. If left empty, the test
// code uses EAP_USERNAME as the identity.
#define EAP_IDENTITY ""
#define EAP_USERNAME "your-enterprise-id"
#define EAP_PASSWORD "your-enterprise-password"

// Optional HTTP/HTTPS endpoint to test after WiFi connects.
// Leave empty to test WiFi only.
#define TEST_URL "http://192.168.1.100:8080/"

// For HTTPS tests only. Set to 1 if you want connectivity testing without
// installing a root CA certificate.
#define HTTP_TLS_INSECURE 1

#define CONNECT_TIMEOUT_MS 20000
#define RETRY_DELAY_MS 5000
#define HTTP_TIMEOUT_MS 8000
#define HTTP_TEST_INTERVAL_MS 10000
