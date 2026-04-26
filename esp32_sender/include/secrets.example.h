#pragma once

// Copy this file to include/secrets.h and edit the values for your deployment.
// include/secrets.h is intentionally ignored by git.

#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASS "your-wifi-password"

#define DEVICE_ID "sender-001"
#define API_TOKEN "replace-with-device-token"
#define UPLOAD_URL "https://example.com/api/sniff/batch"

// Keep disabled until the endpoint exists. When disabled, batches are built and
// drained locally with dry-run counters, but no WiFi/HTTP upload is attempted.
#define UPLOAD_ENABLED 0

// Development only. Set to 1 to skip TLS certificate verification for HTTPS.
// Do not use this for production.
#define HTTP_TLS_INSECURE 0

// Keep serial per-record prints while debugging. Disable once upload is active.
#define DEBUG_PRINT_RECORDS 1
