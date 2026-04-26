#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <stdarg.h>
#include "esp_wpa2.h"

#define WIFI_ENTERPRISE_METHOD_PEAP 1
#define WIFI_ENTERPRISE_METHOD_TTLS 2
#define WIFI_ENTERPRISE_TTLS_PHASE2_GTC 255

extern "C" {
  #include "esp_wifi.h"
}

#if __has_include("secrets.h")
  #include "secrets.h"
#endif

#ifndef WIFI_SSID
  #define WIFI_SSID ""
#endif

#ifndef WIFI_PASS
  #define WIFI_PASS ""
#endif

#ifndef WIFI_ENTERPRISE_ENABLED
  #define WIFI_ENTERPRISE_ENABLED 0
#endif

#ifndef WIFI_ENTERPRISE_METHOD
  #define WIFI_ENTERPRISE_METHOD WIFI_ENTERPRISE_METHOD_TTLS
#endif

#ifndef EAP_IDENTITY
  #define EAP_IDENTITY ""
#endif

#ifndef EAP_USERNAME
  #define EAP_USERNAME ""
#endif

#ifndef EAP_PASSWORD
  #define EAP_PASSWORD ""
#endif

#ifndef EAP_TTLS_PHASE2_METHOD
  #define EAP_TTLS_PHASE2_METHOD ESP_EAP_TTLS_PHASE2_MSCHAPV2
#endif

#ifndef TEST_URL
  #define TEST_URL ""
#endif

#ifndef HTTP_TLS_INSECURE
  #define HTTP_TLS_INSECURE 1
#endif

#ifndef CONNECT_TIMEOUT_MS
  #define CONNECT_TIMEOUT_MS 20000
#endif

#ifndef RETRY_DELAY_MS
  #define RETRY_DELAY_MS 5000
#endif

#ifndef HTTP_TIMEOUT_MS
  #define HTTP_TIMEOUT_MS 8000
#endif

#ifndef HTTP_TEST_INTERVAL_MS
  #define HTTP_TEST_INTERVAL_MS 10000
#endif

enum class LogLevel : uint8_t {
  Info,
  Warn,
  Error,
};

static uint32_t lastConnectAttemptMs = 0;
static uint32_t lastStatusMs = 0;
static uint32_t lastHttpTestMs = 0;
static uint8_t lastDisconnectReason = 0;

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

static const char* enterpriseMethodName(int method) {
  switch (method) {
    case WIFI_ENTERPRISE_METHOD_PEAP:
      return "PEAP";
    case WIFI_ENTERPRISE_METHOD_TTLS:
      return "TTLS";
    default:
      return "UNKNOWN";
  }
}

static const char* ttlsPhase2Name(int method) {
  switch (method) {
    case ESP_EAP_TTLS_PHASE2_EAP:
      return "EAP";
    case ESP_EAP_TTLS_PHASE2_MSCHAPV2:
      return "MSCHAPV2";
    case ESP_EAP_TTLS_PHASE2_MSCHAP:
      return "MSCHAP";
    case ESP_EAP_TTLS_PHASE2_PAP:
      return "PAP";
    case ESP_EAP_TTLS_PHASE2_CHAP:
      return "CHAP";
    case WIFI_ENTERPRISE_TTLS_PHASE2_GTC:
      return "GTC_UNSUPPORTED";
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

static bool urlIsHttps(const char* url) {
  return strncmp(url, "https://", 8) == 0;
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

static void runDnsTest() {
  if (strlen(TEST_URL) == 0) {
    return;
  }

  const String host = hostFromUrl(TEST_URL);
  if (host.length() == 0) {
    logEvent(LogLevel::Warn, "dns_test_skipped", "reason=empty_host url=%s", TEST_URL);
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

static void runHttpTest() {
  if (strlen(TEST_URL) == 0) {
    return;
  }

  HTTPClient http;
  int code = -1;
  bool began = false;

  if (urlIsHttps(TEST_URL)) {
    WiFiClientSecure client;
#if HTTP_TLS_INSECURE
    client.setInsecure();
#endif
    began = http.begin(client, TEST_URL);
    if (began) {
      http.setTimeout(HTTP_TIMEOUT_MS);
      code = http.GET();
      http.end();
    }
  } else {
    WiFiClient client;
    began = http.begin(client, TEST_URL);
    if (began) {
      http.setTimeout(HTTP_TIMEOUT_MS);
      code = http.GET();
      http.end();
    }
  }

  if (!began) {
    logEvent(LogLevel::Warn, "http_begin_failed", "url=%s code=%d", TEST_URL, code);
    return;
  }

  if (code > 0) {
    logEvent(LogLevel::Info, "http_result", "url=%s code=%d", TEST_URL, code);
  } else {
    logEvent(LogLevel::Warn,
             "http_failed",
             "url=%s code=%d error=\"%s\"",
             TEST_URL,
             code,
             HTTPClient::errorToString(code).c_str());
  }
}

static bool beginConfiguredWifi() {
#if WIFI_ENTERPRISE_ENABLED
  const char* identity = strlen(EAP_IDENTITY) > 0 ? EAP_IDENTITY : EAP_USERNAME;
  if (strlen(identity) == 0 || strlen(EAP_USERNAME) == 0 || strlen(EAP_PASSWORD) == 0) {
    logEvent(LogLevel::Error,
             "enterprise_config_missing",
             "identity_len=%u username_len=%u password_len=%u",
             static_cast<unsigned>(strlen(identity)),
             static_cast<unsigned>(strlen(EAP_USERNAME)),
             static_cast<unsigned>(strlen(EAP_PASSWORD)));
    return false;
  }

  if (WIFI_ENTERPRISE_METHOD == WIFI_ENTERPRISE_METHOD_TTLS) {
    if (EAP_TTLS_PHASE2_METHOD == WIFI_ENTERPRISE_TTLS_PHASE2_GTC) {
      logEvent(LogLevel::Error,
               "enterprise_phase2_unsupported",
               "method=TTLS phase2=GTC note=\"Arduino ESP32 exposes TTLS EAP/MSCHAPV2/MSCHAP/PAP/CHAP only\"");
      return false;
    }

    const esp_err_t phaseErr = esp_wifi_sta_wpa2_ent_set_ttls_phase2_method(
      static_cast<esp_eap_ttls_phase2_types>(EAP_TTLS_PHASE2_METHOD)
    );
    if (phaseErr != ESP_OK) {
      logEvent(LogLevel::Error,
               "enterprise_phase2_config_failed",
               "phase2=%s err=%d",
               ttlsPhase2Name(EAP_TTLS_PHASE2_METHOD),
               static_cast<int>(phaseErr));
      return false;
    }

    logEvent(LogLevel::Info,
             "enterprise_config",
             "method=TTLS phase2=%s identity=\"%s\" username=\"%s\" ca_cert=disabled",
             ttlsPhase2Name(EAP_TTLS_PHASE2_METHOD),
             identity,
             EAP_USERNAME);
    WiFi.begin(WIFI_SSID, WPA2_AUTH_TTLS, identity, EAP_USERNAME, EAP_PASSWORD);
    return true;
  }

  if (WIFI_ENTERPRISE_METHOD == WIFI_ENTERPRISE_METHOD_PEAP) {
    logEvent(LogLevel::Info,
             "enterprise_config",
             "method=PEAP identity=\"%s\" username=\"%s\" ca_cert=disabled",
             identity,
             EAP_USERNAME);
    WiFi.begin(WIFI_SSID, WPA2_AUTH_PEAP, identity, EAP_USERNAME, EAP_PASSWORD);
    return true;
  }

  logEvent(LogLevel::Error,
           "enterprise_method_unsupported",
           "method=%d method_name=%s",
           WIFI_ENTERPRISE_METHOD,
           enterpriseMethodName(WIFI_ENTERPRISE_METHOD));
  return false;
#else
  esp_wifi_sta_wpa2_ent_disable();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  return true;
#endif
}

static bool connectWifi() {
  if (strlen(WIFI_SSID) == 0) {
    logEvent(LogLevel::Error, "wifi_config_missing", "reason=empty_ssid");
    return false;
  }

  scanForConfiguredSsid();

  lastDisconnectReason = 0;
  WiFi.disconnect(true, true);
  delay(300);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  WiFi.persistent(false);

  logEvent(LogLevel::Info,
           "wifi_connect_start",
           "ssid=\"%s\" mode=%s enterprise_method=%s timeout_ms=%lu",
           WIFI_SSID,
           WIFI_ENTERPRISE_ENABLED ? "enterprise" : "psk",
           WIFI_ENTERPRISE_ENABLED ? enterpriseMethodName(WIFI_ENTERPRISE_METHOD) : "none",
           static_cast<unsigned long>(CONNECT_TIMEOUT_MS));
  if (!beginConfiguredWifi()) {
    return false;
  }

  const uint32_t started = millis();
  uint32_t lastWaitLogMs = 0;
  while (WiFi.status() != WL_CONNECTED && (millis() - started) < CONNECT_TIMEOUT_MS) {
    const uint32_t now = millis();
    if ((now - lastWaitLogMs) >= 1000) {
      lastWaitLogMs = now;
      logEvent(LogLevel::Info,
               "wifi_connect_wait",
               "elapsed_ms=%lu status=%s last_reason=%u last_reason_name=%s",
               static_cast<unsigned long>(now - started),
               wlStatusName(WiFi.status()),
               static_cast<unsigned>(lastDisconnectReason),
               disconnectReasonName(lastDisconnectReason));
    }
    delay(100);
  }

  if (WiFi.status() != WL_CONNECTED) {
    logEvent(LogLevel::Error,
             "wifi_connect_timeout",
             "ssid=\"%s\" status=%s last_reason=%u last_reason_name=%s",
             WIFI_SSID,
             wlStatusName(WiFi.status()),
             static_cast<unsigned>(lastDisconnectReason),
             disconnectReasonName(lastDisconnectReason));
    return false;
  }

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

  runDnsTest();
  runHttpTest();
  return true;
}

static void onWiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      logEvent(LogLevel::Info, "wifi_event_connected");
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      logEvent(LogLevel::Info, "wifi_event_got_ip", "ip=%s", WiFi.localIP().toString().c_str());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      lastDisconnectReason = info.wifi_sta_disconnected.reason;
      logEvent(LogLevel::Warn,
               "wifi_event_disconnected",
               "reason=%u reason_name=%s",
               static_cast<unsigned>(lastDisconnectReason),
               disconnectReasonName(lastDisconnectReason));
      break;
    default:
      break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(800);

  WiFi.onEvent(onWiFiEvent);
  logEvent(LogLevel::Info,
           "wifi_test_start",
           "ssid=\"%s\" mode=%s enterprise_method=%s ttls_phase2=%s test_url=%s tls_insecure=%u",
           WIFI_SSID,
           WIFI_ENTERPRISE_ENABLED ? "enterprise" : "psk",
           WIFI_ENTERPRISE_ENABLED ? enterpriseMethodName(WIFI_ENTERPRISE_METHOD) : "none",
           WIFI_ENTERPRISE_ENABLED ? ttlsPhase2Name(EAP_TTLS_PHASE2_METHOD) : "none",
           strlen(TEST_URL) > 0 ? TEST_URL : "<disabled>",
           static_cast<unsigned>(HTTP_TLS_INSECURE));
  connectWifi();
  lastConnectAttemptMs = millis();
  lastStatusMs = millis();
  lastHttpTestMs = millis();
}

void loop() {
  const uint32_t now = millis();

  if (WiFi.status() != WL_CONNECTED) {
    if ((now - lastConnectAttemptMs) >= RETRY_DELAY_MS) {
      lastConnectAttemptMs = now;
      connectWifi();
    }
    delay(100);
    return;
  }

  if ((now - lastStatusMs) >= 1000) {
    lastStatusMs = now;
    logEvent(LogLevel::Info,
             "wifi_status",
             "ip=%s rssi=%d channel=%u heap_free=%lu heap_min_free=%lu",
             WiFi.localIP().toString().c_str(),
             WiFi.RSSI(),
             WiFi.channel(),
             static_cast<unsigned long>(ESP.getFreeHeap()),
             static_cast<unsigned long>(ESP.getMinFreeHeap()));
  }

  if (strlen(TEST_URL) > 0 && (now - lastHttpTestMs) >= HTTP_TEST_INTERVAL_MS) {
    lastHttpTestMs = now;
    runDnsTest();
    runHttpTest();
  }

  delay(50);
}
