// ESP32-C3 GCM compatibility update
#include "gainsborough_trilock.h"
#include "esphome/components/esp32_ble/ble_uuid.h"
#include "esphome/components/esp32_ble_client/ble_client_base.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/components/network/util.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "mbedtls/base64.h"
#if __has_include("mbedtls/esp_config.h")
#include "mbedtls/esp_config.h"
#endif
#include "mbedtls/gcm.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_defs.h"
#include "esp_http_client.h"
#include "esp_random.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <utility>
#include <vector>

#ifdef USE_ESP32

#define GCM_ENCRYPT 1
#define GCM_DECRYPT 0

namespace esphome {
namespace gainsborough_trilock {

static const char *const TAG = "gainsborough_trilock";

namespace espbt = esphome::esp32_ble_tracker;

struct HttpResponseBuffer {
  std::string body;
};

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_DATA && evt->user_data != nullptr && evt->data != nullptr && evt->data_len > 0) {
    auto *response = static_cast<HttpResponseBuffer *>(evt->user_data);
    response->body.append(static_cast<const char *>(evt->data), evt->data_len);
  }
  return ESP_OK;
}

static std::string json_escape(const std::string &value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out += c;
        break;
    }
  }
  return out;
}

static bool http_request(const std::string &url, const char *method, const std::string *body,
                         const std::vector<std::pair<std::string, std::string>> &headers,
                         std::string *response_body, int *status_code) {
  HttpResponseBuffer response;
  esp_http_client_config_t config{};
  config.url = url.c_str();
  config.event_handler = http_event_handler;
  config.user_data = &response;
  config.timeout_ms = 10000;
  config.buffer_size = 4096;
  config.buffer_size_tx = 2048;
  config.crt_bundle_attach = esp_crt_bundle_attach;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == nullptr)
    return false;

  esp_http_client_set_method(client, strcmp(method, "POST") == 0 ? HTTP_METHOD_POST : HTTP_METHOD_GET);
  for (const auto &header : headers)
    esp_http_client_set_header(client, header.first.c_str(), header.second.c_str());

  if (body != nullptr) {
    esp_http_client_set_post_field(client, body->c_str(), body->size());
  }

  esp_err_t err = esp_http_client_perform(client);
  int code = esp_http_client_get_status_code(client);
  esp_http_client_cleanup(client);

  if (status_code != nullptr)
    *status_code = code;
  if (response_body != nullptr)
    *response_body = response.body;
  return err == ESP_OK && code >= 200 && code < 300;
}

static const char *json_get_string(cJSON *obj, const char *key) {
  cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
  return cJSON_IsString(item) ? item->valuestring : nullptr;
}

static bool json_get_int_(cJSON *obj, const char *key, int *value) {
  cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (!cJSON_IsNumber(item))
    return false;
  *value = item->valueint;
  return true;
}

static bool base64_encode_bytes_(const uint8_t *data, size_t len, std::string *out) {
  size_t required = 0;
  int ret = mbedtls_base64_encode(nullptr, 0, &required, data, len);
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    return false;
  std::vector<uint8_t> encoded(required + 1);
  ret = mbedtls_base64_encode(encoded.data(), encoded.size(), &required, data, len);
  if (ret != 0)
    return false;
  out->assign(reinterpret_cast<const char *>(encoded.data()), required);
  return true;
}

static std::string normalize_ble_mac(const std::string &mac) {
  std::string out;
  out.reserve(12);
  for (char c : mac) {
    if (std::isxdigit(static_cast<unsigned char>(c)))
      out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  return out;
}

static uint8_t reflect8(uint8_t v) {
  v = (uint8_t) ((v & 0xF0) >> 4) | (uint8_t) ((v & 0x0F) << 4);
  v = (uint8_t) ((v & 0xCC) >> 2) | (uint8_t) ((v & 0x33) << 2);
  v = (uint8_t) ((v & 0xAA) >> 1) | (uint8_t) ((v & 0x55) << 1);
  return v;
}

static uint32_t reflect32(uint32_t v) {
  v = ((v & 0xFFFF0000U) >> 16) | ((v & 0x0000FFFFU) << 16);
  v = ((v & 0xFF00FF00U) >> 8) | ((v & 0x00FF00FFU) << 8);
  v = ((v & 0xF0F0F0F0U) >> 4) | ((v & 0x0F0F0F0FU) << 4);
  v = ((v & 0xCCCCCCCCU) >> 2) | ((v & 0x33333333U) << 2);
  v = ((v & 0xAAAAAAAAU) >> 1) | ((v & 0x55555555U) << 1);
  return v;
}

static uint32_t calc_crc32(const uint8_t *data, size_t len) {
  uint32_t crc = 0x00000000;
  const uint32_t poly = 0x04C11DB7;
  for (size_t i = 0; i < len; i++) {
    uint8_t b = reflect8(data[i]);
    crc ^= ((uint32_t) b) << 24;
    for (int j = 0; j < 8; j++) {
      crc = (crc & 0x80000000U) ? (crc << 1) ^ poly : (crc << 1);
    }
  }
  crc = reflect32(crc);
  return crc ^ 0xFFFFFFFFU;
}

static size_t encode_request(uint8_t *buf, size_t buf_len, uint8_t desired_state, uint64_t token) {
  uint8_t inner[20];
  size_t n = 0;
  inner[n++] = (1 << 3) | 0;
  inner[n++] = desired_state & 0x7F;
  inner[n++] = (2 << 3) | 0;
  for (int i = 0; i < 8; i++) {
    if (token < 0x80) {
      inner[n++] = token & 0x7F;
      break;
    }
    inner[n++] = (token & 0x7F) | 0x80;
    token >>= 7;
  }

  uint8_t middle[30];
  size_t m = 0;
  middle[m++] = (2 << 3) | 2; // request (field 2)
  middle[m++] = (uint8_t) n;
  memcpy(middle + m, inner, n);
  m += n;

  size_t outer_n = 0;
  buf[outer_n++] = (1 << 3) | 2; // lockStateUpdate (field 1)
  buf[outer_n++] = (uint8_t) m;
  if (outer_n + m > buf_len)
    return 0;
  memcpy(buf + outer_n, middle, m);
  outer_n += m;
  return outer_n;
}

static bool decode_confirm(const uint8_t *data, size_t len, uint8_t *desired_state, uint8_t *reported_state, bool *door_closed, int *battery_percent, int depth = 0) {
  size_t i = 0;
  while (i < len) {
    if (i >= len) break;
    uint8_t tag = data[i++];
    uint8_t field = tag >> 3;
    uint8_t wire = tag & 7;

    if (wire == 0) { // Varint
      uint64_t val = 0;
      int shift = 0;
      do {
        if (i >= len) return false;
        val |= (uint64_t)(data[i] & 0x7F) << shift;
        shift += 7;
      } while (data[i++] & 0x80);
      ESP_LOGD(TAG, "  Depth %d: Field %u (Varint): Value %llu", depth, field, val);
      
      if (field == 1 && desired_state != nullptr) *desired_state = (uint8_t) val;
      if (field == 2 && reported_state != nullptr) *reported_state = (uint8_t) val;
      if (field == 3 && door_closed != nullptr) *door_closed = (val != 0);
      if (field == 4 && battery_percent != nullptr) *battery_percent = (int) val;
    } else if (wire == 1) { // 64-bit
      uint64_t val;
      if (i + 8 > len) return false;
      memcpy(&val, data + i, 8);
      i += 8;
      ESP_LOGD(TAG, "  Depth %d: Field %u (64-bit): Value %llu", depth, field, val);
    } else if (wire == 5) { // 32-bit
      uint32_t val;
      if (i + 4 > len) return false;
      memcpy(&val, data + i, 4);
      i += 4;
      ESP_LOGD(TAG, "  Depth %d: Field %u (32-bit): Value %u", depth, field, val);
    } else if (wire == 2) { // Length-delimited
      uint64_t slen = 0;
      int shift = 0;
      do {
        if (i >= len) return false;
        slen |= (uint64_t)(data[i] & 0x7F) << shift;
        shift += 7;
      } while (data[i++] & 0x80);
      
      ESP_LOGD(TAG, "  Depth %d: Field %u (Length-delimited): Length %llu", depth, field, slen);
      
      if (i + slen > len) return false;
      
      decode_confirm(data + i, (size_t) slen, desired_state, reported_state, door_closed, battery_percent, depth + 1);
      i += (size_t) slen;
    } else {
      ESP_LOGD(TAG, "  Depth %d: Field %u (Unknown wire %u)", depth, field, wire);
      return false;
    }
  }
  return true;
}

static bool read_varint_(const uint8_t *data, size_t len, size_t *pos, uint64_t *value) {
  uint64_t val = 0;
  int shift = 0;
  while (*pos < len && shift <= 63) {
    uint8_t b = data[(*pos)++];
    val |= (uint64_t) (b & 0x7F) << shift;
    if ((b & 0x80) == 0) {
      *value = val;
      return true;
    }
    shift += 7;
  }
  return false;
}

static int hex_nibble_(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool decode_nonce_string_(const std::string &nonce, uint8_t *out) {
  uint8_t decoded[32];
  size_t out_len = 0;
  int ret = mbedtls_base64_decode(decoded, sizeof(decoded), &out_len,
                                  reinterpret_cast<const uint8_t *>(nonce.data()),
                                  nonce.size());
  if (ret == 0 && out_len == 12) {
    memcpy(out, decoded, 12);
    return true;
  }

  uint8_t hex_decoded[12];
  size_t hex_len = 0;
  int high = -1;
  for (char c : nonce) {
    if (c == '.' || c == ':' || c == '-' || c == ' ' || c == '_')
      continue;
    int nibble = hex_nibble_(c);
    if (nibble < 0)
      return false;
    if (high < 0) {
      high = nibble;
    } else {
      if (hex_len >= sizeof(hex_decoded))
        return false;
      hex_decoded[hex_len++] = (uint8_t) ((high << 4) | nibble);
      high = -1;
    }
  }
  if (high >= 0 || hex_len != 12)
    return false;
  memcpy(out, hex_decoded, 12);
  return true;
}

static void scan_proto_telemetry_(const uint8_t *data, size_t len, int depth,
                                  bool *door_found, bool *door_closed,
                                  bool *battery_found, int *battery_percent,
                                  bool *battery_low_found, bool *battery_low) {
  if (depth > 6)
    return;

  size_t i = 0;
  bool local_door_found = false;
  bool local_door = false;
  bool local_battery_found = false;
  int local_battery = -1;
  bool local_battery_low_found = false;
  bool local_battery_low = false;
  int local_state = -1;

  while (i < len) {
    uint64_t tag = 0;
    if (!read_varint_(data, len, &i, &tag) || tag == 0)
      return;
    uint8_t field = tag >> 3;
    uint8_t wire = tag & 7;

    if (wire == 0) {
      uint64_t val = 0;
      if (!read_varint_(data, len, &i, &val))
        return;
      ESP_LOGD(TAG, "Sync scan depth=%d field=%u varint=%llu", depth, field, val);
      if (field == 1 && val <= 5)
        local_state = (int) val;
      if (field == 2 && val <= 1) {
        local_door_found = true;
        local_door = val != 0;
      }
      if (field == 3 && val <= 100) {
        local_battery_found = true;
        local_battery = (int) val;
      }
      if (field == 6 && val <= 1) {
        local_battery_low_found = true;
        local_battery_low = val != 0;
      }
    } else if (wire == 1) {
      if (i + 8 > len)
        return;
      i += 8;
    } else if (wire == 5) {
      if (i + 4 > len)
        return;
      i += 4;
    } else if (wire == 2) {
      uint64_t slen = 0;
      if (!read_varint_(data, len, &i, &slen) || i + slen > len)
        return;
      ESP_LOGD(TAG, "Sync scan depth=%d field=%u len=%llu", depth, field, slen);
      scan_proto_telemetry_(data + i, (size_t) slen, depth + 1, door_found, door_closed,
                            battery_found, battery_percent, battery_low_found, battery_low);
      i += (size_t) slen;
    } else {
      return;
    }
  }

  if (local_state >= 0 && local_door_found) {
    ESP_LOGI(TAG, "Sync telemetry candidate: state=%d doorClosed=%s", local_state,
             local_door ? "true" : "false");
    *door_found = true;
    *door_closed = local_door;
  }
  if (local_battery_found) {
    ESP_LOGI(TAG, "Sync telemetry candidate: batterySoC=%d%%", local_battery);
    *battery_found = true;
    *battery_percent = local_battery;
  }
  if (local_battery_low_found) {
    ESP_LOGI(TAG, "Sync telemetry candidate: batteryLow=%s", local_battery_low ? "true" : "false");
    *battery_low_found = true;
    *battery_low = local_battery_low;
  }
}

static int encode_message(const uint8_t *key, const uint8_t *input, size_t input_len,
                          uint8_t *out_arr, const uint8_t *rx_nonce, uint16_t msg_id) {
  uint8_t iv2[12];
  esp_fill_random(iv2, 12);
  alignas(16) uint8_t final_iv[24];
  memcpy(final_iv, rx_nonce, 12);
  memcpy(final_iv + 12, iv2, 12);

  size_t pad_len = 16 - (input_len & 15);
  alignas(16) uint8_t padded[128];
  if (input_len + pad_len > sizeof(padded))
    return -1;
  memcpy(padded, input, input_len);
  esp_fill_random(padded + input_len, pad_len);
  size_t padded_len = input_len + pad_len;

  uint8_t header[6] = {0x00, 0x00, (uint8_t)(msg_id >> 8), (uint8_t)(msg_id & 0xFF),
                       (uint8_t)(input_len & 0xFF), 0x00};

  alignas(16) uint8_t cipher[128];
  alignas(16) uint8_t tag[16];
  mbedtls_gcm_context aes;
  mbedtls_gcm_init(&aes);
  mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (mbedtls_gcm_starts(&aes, GCM_ENCRYPT, final_iv, sizeof(final_iv)) != 0) {
    mbedtls_gcm_free(&aes);
    return -1;
  }
  if (mbedtls_gcm_update_ad(&aes, header, sizeof(header)) != 0) {
    mbedtls_gcm_free(&aes);
    return -1;
  }
  size_t cipher_len = 0;
  if (mbedtls_gcm_update(&aes, padded, padded_len, cipher, sizeof(cipher), &cipher_len) != 0) {
    mbedtls_gcm_free(&aes);
    return -1;
  }
  size_t finish_len = 0;
  if (mbedtls_gcm_finish(&aes, nullptr, 0, &finish_len, tag, sizeof(tag)) != 0) {
    mbedtls_gcm_free(&aes);
    return -1;
  }
  mbedtls_gcm_free(&aes);

  size_t total_len = 6 + 12 + padded_len + 16;
  memcpy(out_arr, header, 6);
  memcpy(out_arr + 6, iv2, 12);
  memcpy(out_arr + 18, cipher, padded_len);
  memcpy(out_arr + 18 + padded_len, tag, 16);
  return (int) total_len;
}

static bool decode_message(const uint8_t *key, const uint8_t *input, size_t input_len,
                           uint8_t *output, const uint8_t *iv1, const uint8_t *iv2) {
  alignas(16) uint8_t final_iv[24];
  memcpy(final_iv, iv1, 12);
  memcpy(final_iv + 12, iv2, 12);
  alignas(16) uint8_t tag[16];
  mbedtls_gcm_context aes;
  mbedtls_gcm_init(&aes);
  mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (mbedtls_gcm_starts(&aes, GCM_DECRYPT, final_iv, sizeof(final_iv)) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  size_t out_len = 0;
  if (mbedtls_gcm_update(&aes, input, input_len, output, input_len + 16, &out_len) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  size_t finish_len = 0;
  if (mbedtls_gcm_finish(&aes, nullptr, 0, &finish_len, tag, sizeof(tag)) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  mbedtls_gcm_free(&aes);
  return true;
}

static bool decode_message_checked(const uint8_t *key, const uint8_t *message, size_t message_len,
                                   uint8_t *output, const uint8_t *iv1) {
  if (message_len < 34)
    return false;

  const uint8_t *header = message;
  const uint8_t *iv2 = message + 6;
  const uint8_t *cipher = message + 18;
  size_t cipher_len = message_len - 34;
  const uint8_t *expected_tag = message + 18 + cipher_len;

  alignas(16) uint8_t final_iv[24];
  memcpy(final_iv, iv1, 12);
  memcpy(final_iv + 12, iv2, 12);

  alignas(16) uint8_t actual_tag[16];
  mbedtls_gcm_context aes;
  mbedtls_gcm_init(&aes);
  mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (mbedtls_gcm_starts(&aes, GCM_DECRYPT, final_iv, sizeof(final_iv)) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  if (mbedtls_gcm_update_ad(&aes, header, 6) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  size_t out_len = 0;
  if (mbedtls_gcm_update(&aes, cipher, cipher_len, output, cipher_len + 16, &out_len) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  size_t finish_len = 0;
  if (mbedtls_gcm_finish(&aes, nullptr, 0, &finish_len, actual_tag, sizeof(actual_tag)) != 0) {
    mbedtls_gcm_free(&aes);
    return false;
  }
  mbedtls_gcm_free(&aes);
  return memcmp(actual_tag, expected_tag, sizeof(actual_tag)) == 0;
}

void GainsboroughTrilockLock::setup() {
  this->traits.set_supports_open(false);
  this->traits.set_assumed_state(false);
  this->traits.add_supported_state(lock::LOCK_STATE_LOCKED);
  this->traits.add_supported_state(lock::LOCK_STATE_UNLOCKED);
  this->traits.add_supported_state(lock::LOCK_STATE_JAMMED);
  this->traits.add_supported_state(lock::LOCK_STATE_LOCKING);
  this->traits.add_supported_state(lock::LOCK_STATE_UNLOCKING);
}

void GainsboroughTrilockLock::loop() {
  this->poll_cloud_if_due_();

  if (this->parent() == nullptr || !this->parent()->connected())
    return;

  this->ensure_gatt_ready_();

  if (notify_pending_) {
    notify_pending_ = false;
    this->handle_notify_();
  }

  if (sync_pending_) {
    sync_pending_ = false;
    this->handle_sync_notify_(sync_buf_, sync_len_);
  }

  this->run_auto_sync_cloud_refresh_if_due_();
  this->run_auto_status_request_if_due_();

  if (sync_bootstrap_pending_ && gatt_ready_ && sync_char_handle_ != 0)
    this->start_phone_like_sync_bootstrap_();

  if (sync_bootstrap_active_)
    this->process_phone_like_sync_bootstrap_();

  if (protocol_active_ && (millis() - last_notify_) > PROTOCOL_TIMEOUT_MS) {
    ESP_LOGW(TAG, "Protocol timeout");
    protocol_active_ = false;
  }

  if (sync_diag_active_ && (millis() - sync_diag_started_) > 15000) {
    ESP_LOGW(TAG, "Sync diagnostics timeout; received %u/%u bytes",
             (unsigned) sync_doai_msg_received_, (unsigned) sync_doai_msg_len_);
    sync_diag_active_ = false;
    sync_cloud_refresh_waiting_status_ = false;
    sync_cloud_upload_after_receive_ = false;
    sync_bootstrap_active_ = false;
    sync_bootstrap_pending_ = false;
  }

  this->send_pending_if_ready_();
}

void GainsboroughTrilockLock::update() {
  // Empty background polling because it pollutes the lock's command channel 
  // and breaks subsequent commands if the lock gets stuck in a dirty state.
}

void GainsboroughTrilockLock::dump_config() {
  LOG_LOCK(TAG, "Gainsborough Trilock Clean", this);
  ESP_LOGCONFIG(TAG, "  Service UUID: %s", SERVICE_UUID);
  ESP_LOGCONFIG(TAG, "  Characteristic UUID: %s", CMD_CHARACTERISTIC_UUID);
  ESP_LOGCONFIG(TAG, "  Cloud polling: %s", this->cloud_enabled_ ? "enabled" : "disabled");
  if (this->cloud_enabled_) {
    ESP_LOGCONFIG(TAG, "  Cloud property: %s", this->cloud_property_id_.c_str());
    ESP_LOGCONFIG(TAG, "  Cloud BLE MAC: %s", this->cloud_ble_mac_.c_str());
    ESP_LOGCONFIG(TAG, "  Cloud update interval: %ums", (unsigned) this->cloud_update_interval_ms_);
  }
}

void GainsboroughTrilockLock::set_cloud_config(const std::string &username, const std::string &refresh_token,
                                               const std::string &property_id, const std::string &ble_mac,
                                               const std::string &client_id, const std::string &client_secret,
                                               const std::string &endpoint, uint32_t update_interval_ms) {
  this->cloud_username_ = username;
  this->cloud_refresh_token_ = refresh_token;
  this->cloud_property_id_ = property_id;
  this->cloud_ble_mac_ = normalize_ble_mac(ble_mac);
  this->cloud_client_id_ = client_id;
  this->cloud_client_secret_ = client_secret;
  this->cloud_endpoint_ = endpoint;
  while (!this->cloud_endpoint_.empty() && this->cloud_endpoint_.back() == '/')
    this->cloud_endpoint_.pop_back();
  this->cloud_update_interval_ms_ = std::max<uint32_t>(update_interval_ms, 60000);
  this->cloud_enabled_ = !this->cloud_refresh_token_.empty() &&
                         !this->cloud_property_id_.empty() && !this->cloud_ble_mac_.empty();
}

void GainsboroughTrilockLock::poll_cloud_if_due_() {
  if (!this->cloud_enabled_ || this->cloud_polling_)
    return;
  // Keep cloud/TLS work out of ESPHome's safe-mode rollback window.
  if (millis() < 75000)
    return;
  if (!network::is_connected())
    return;
  const uint32_t now = millis();
  if (this->last_cloud_poll_ != 0 && (now - this->last_cloud_poll_) < this->cloud_update_interval_ms_)
    return;

  this->cloud_polling_ = true;
  bool success = false;
  if (this->cloud_id_token_.empty() || (this->cloud_token_expires_at_ != 0 && now + 60000 > this->cloud_token_expires_at_)) {
    if (!this->refresh_cloud_session_()) {
      constexpr uint32_t RETRY_DELAY_MS = 30000;
      this->last_cloud_poll_ = now - (this->cloud_update_interval_ms_ > RETRY_DELAY_MS
                                      ? this->cloud_update_interval_ms_ - RETRY_DELAY_MS
                                      : 0);
      this->cloud_polling_ = false;
      return;
    }
  }
  if (!this->poll_cloud_lock_state_()) {
    ESP_LOGW(TAG, "Cloud lock poll failed; forcing token refresh for next attempt");
    this->cloud_id_token_.clear();
    this->cloud_token_expires_at_ = 0;
  } else {
    success = true;
  }
  constexpr uint32_t RETRY_DELAY_MS = 30000;
  this->last_cloud_poll_ = success ? now : now - (this->cloud_update_interval_ms_ > RETRY_DELAY_MS
                                                 ? this->cloud_update_interval_ms_ - RETRY_DELAY_MS
                                                 : 0);
  this->cloud_polling_ = false;
}

void GainsboroughTrilockLock::run_auto_sync_cloud_refresh_if_due_() {
  if (!this->cloud_enabled_ || !gatt_ready_ || sync_char_handle_ == 0)
    return;
  if (sync_diag_active_ || sync_cloud_refresh_waiting_status_ || protocol_active_ || sync_bootstrap_active_)
    return;

  const uint32_t now = millis();
  if (last_sync_cloud_refresh_ != 0 && (now - last_sync_cloud_refresh_) < SYNC_CLOUD_REFRESH_INTERVAL_MS)
    return;

  last_sync_cloud_refresh_ = now;
  this->start_sync_cloud_refresh_(false);
}

void GainsboroughTrilockLock::run_auto_status_request_if_due_() {
  if (!has_key_ || !gatt_ready_)
    return;
  if (sync_diag_active_ || sync_cloud_refresh_waiting_status_ || protocol_active_ || sync_bootstrap_active_)
    return;

  const uint32_t now = millis();
  if (last_auto_status_request_ != 0 && (now - last_auto_status_request_) < AUTO_STATUS_REQUEST_INTERVAL_MS)
    return;

  last_auto_status_request_ = now;
  this->start_status_request_(false);
}

bool GainsboroughTrilockLock::refresh_cloud_session_() {
  ESP_LOGI(TAG, "Refreshing Gainsborough cloud session");
  const std::string body =
      std::string("{\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"ClientId\":\"") + json_escape(this->cloud_client_id_) +
      "\",\"AuthParameters\":{\"REFRESH_TOKEN\":\"" + json_escape(this->cloud_refresh_token_) +
      "\",\"SECRET_HASH\":\"" + json_escape(this->cloud_client_secret_) + "\"},\"ClientMetadata\":{}}";

  std::string response;
  int status = 0;
  const std::vector<std::pair<std::string, std::string>> headers = {
      {"x-amz-target", "AWSCognitoIdentityProviderService.InitiateAuth"},
      {"content-type", "application/x-amz-json-1.1"},
  };
  if (!http_request("https://cognito-idp.ap-southeast-2.amazonaws.com", "POST", &body, headers, &response, &status)) {
    ESP_LOGW(TAG, "Cognito refresh failed: HTTP %d body=%s", status, response.c_str());
    return false;
  }

  cJSON *root = cJSON_Parse(response.c_str());
  if (root == nullptr) {
    ESP_LOGW(TAG, "Cognito refresh returned invalid JSON");
    return false;
  }
  cJSON *auth = cJSON_GetObjectItemCaseSensitive(root, "AuthenticationResult");
  const char *id_token = auth != nullptr ? json_get_string(auth, "IdToken") : nullptr;
  cJSON *expires = auth != nullptr ? cJSON_GetObjectItemCaseSensitive(auth, "ExpiresIn") : nullptr;
  if (id_token == nullptr || !cJSON_IsNumber(expires)) {
    ESP_LOGW(TAG, "Cognito refresh missing IdToken/ExpiresIn");
    cJSON_Delete(root);
    return false;
  }
  this->cloud_id_token_ = id_token;
  const int expires_in = expires->valueint;
  this->cloud_token_expires_at_ = millis() + (uint32_t) expires_in * 1000;
  cJSON_Delete(root);
  ESP_LOGI(TAG, "Gainsborough cloud session refreshed; expires in %ds", expires_in);
  return true;
}

bool GainsboroughTrilockLock::ensure_cloud_session_() {
  if (!this->cloud_enabled_) {
    ESP_LOGW(TAG, "Gainsborough cloud is not configured");
    return false;
  }
  if (this->cloud_id_token_.empty() ||
      (this->cloud_token_expires_at_ != 0 && millis() + 60000 > this->cloud_token_expires_at_)) {
    return this->refresh_cloud_session_();
  }
  return true;
}

bool GainsboroughTrilockLock::fetch_cloud_gwasm_status_() {
  if (!this->ensure_cloud_session_())
    return false;

  const std::string url = this->cloud_endpoint_ + "/gwasm/" + this->cloud_property_id_ + "/" +
                          this->cloud_ble_mac_ + "/status";
  std::string response;
  int status = 0;
  const std::vector<std::pair<std::string, std::string>> headers = {
      {"Authorization", this->cloud_id_token_},
      {"User-Agent", "okhttp/4.9.3"},
  };
  if (!http_request(url, "GET", nullptr, headers, &response, &status)) {
    ESP_LOGW(TAG, "GWASM status GET failed: HTTP %d body=%s", status, response.c_str());
    return false;
  }

  cJSON *root = cJSON_Parse(response.c_str());
  if (root == nullptr) {
    ESP_LOGW(TAG, "GWASM status response was not JSON: %s", response.c_str());
    return false;
  }

  int msg_id = 0;
  const char *nonce_b64 = json_get_string(root, "doAiNonce");
  if (!json_get_int_(root, "doAiMsgId", &msg_id) || msg_id <= 0 || msg_id > 65535 ||
      nonce_b64 == nullptr || nonce_b64[0] == '\0') {
    ESP_LOGW(TAG, "GWASM status missing valid doAiMsgId/doAiNonce: %s", response.c_str());
    cJSON_Delete(root);
    return false;
  }

  uint8_t nonce[12];
  if (!decode_nonce_string_(nonce_b64, nonce)) {
    ESP_LOGW(TAG, "GWASM status returned invalid doAiNonce for msgId=%d: %s", msg_id, nonce_b64);
    cJSON_Delete(root);
    return false;
  }

  cJSON *diao_cnt = cJSON_GetObjectItemCaseSensitive(root, "diAoMsgCnt");
  ESP_LOGI(TAG, "GWASM status: doAiMsgId=%d diAoMsgCnt=%d",
           msg_id, cJSON_IsNumber(diao_cnt) ? diao_cnt->valueint : -1);
  this->set_cloud_doai_nonce_((uint16_t) msg_id, nonce);
  cJSON_Delete(root);
  return true;
}

bool GainsboroughTrilockLock::post_cloud_doai_message_(uint16_t msg_id, const uint8_t *payload, size_t len) {
  if (msg_id == 0 || payload == nullptr || len == 0) {
    ESP_LOGW(TAG, "Cannot post GWASM DoAi message: invalid msgId/payload");
    return false;
  }
  if (!this->ensure_cloud_session_())
    return false;

  std::string payload_b64;
  if (!base64_encode_bytes_(payload, len, &payload_b64)) {
    ESP_LOGW(TAG, "Failed to base64 encode Sync DoAi payload for cloud upload");
    return false;
  }

  const std::string url = this->cloud_endpoint_ + "/gwasm/" + this->cloud_property_id_ + "/" +
                          this->cloud_ble_mac_ + "/message";
  const std::string body = std::string("{\"doAiMsgId\":") + std::to_string(msg_id) +
                           ",\"doAiMsg\":\"" + json_escape(payload_b64) + "\"}";
  std::string response;
  int status = 0;
  const std::vector<std::pair<std::string, std::string>> headers = {
      {"Authorization", this->cloud_id_token_},
      {"User-Agent", "okhttp/4.9.3"},
      {"Content-Type", "application/json"},
  };
  ESP_LOGI(TAG, "Posting Sync DoAi payload to cloud: msgId=%u len=%u",
           msg_id, (unsigned) len);
  if (!http_request(url, "POST", &body, headers, &response, &status)) {
    ESP_LOGW(TAG, "GWASM DoAi POST failed: HTTP %d body=%s", status, response.c_str());
    return false;
  }
  ESP_LOGI(TAG, "GWASM DoAi POST succeeded: HTTP %d", status);
  return true;
}

bool GainsboroughTrilockLock::poll_cloud_lock_state_() {
  const std::string url = this->cloud_endpoint_ + "/properties/" + this->cloud_property_id_;
  std::string response;
  int status = 0;
  const std::vector<std::pair<std::string, std::string>> headers = {
      {"authorization", this->cloud_id_token_},
      {"user-agent", "okhttp/4.9.3"},
  };
  if (!http_request(url, "GET", nullptr, headers, &response, &status)) {
    ESP_LOGW(TAG, "Gainsborough property GET failed: HTTP %d body=%s", status, response.c_str());
    return false;
  }

  cJSON *root = cJSON_Parse(response.c_str());
  if (root == nullptr) {
    ESP_LOGW(TAG, "Gainsborough property response was not JSON");
    return false;
  }
  cJSON *locks = cJSON_GetObjectItemCaseSensitive(root, "locks");
  if (!cJSON_IsArray(locks)) {
    ESP_LOGW(TAG, "Gainsborough property response did not contain locks[]");
    cJSON_Delete(root);
    return false;
  }

  bool found = false;
  cJSON *lock = nullptr;
  cJSON_ArrayForEach(lock, locks) {
    const char *ble_mac = json_get_string(lock, "bleMac");
    if (ble_mac == nullptr)
      continue;
    if (normalize_ble_mac(ble_mac) != this->cloud_ble_mac_)
      continue;

    cJSON *door_closed = cJSON_GetObjectItemCaseSensitive(lock, "doorClosed");
    cJSON *battery_low = cJSON_GetObjectItemCaseSensitive(lock, "batteryLow");
    cJSON *battery_percent = cJSON_GetObjectItemCaseSensitive(lock, "batteryPercent");
    if (cJSON_IsBool(door_closed))
      this->publish_door_status_(cJSON_IsTrue(door_closed));
    if (cJSON_IsBool(battery_low) && cJSON_IsNumber(battery_percent))
      this->publish_battery_info_(cJSON_IsTrue(battery_low), battery_percent->valueint);
    ESP_LOGI(TAG, "Cloud telemetry: doorClosed=%s batteryLow=%s batteryPercent=%d",
             cJSON_IsTrue(door_closed) ? "true" : "false",
             cJSON_IsTrue(battery_low) ? "true" : "false",
             cJSON_IsNumber(battery_percent) ? battery_percent->valueint : -1);
    found = true;
    break;
  }

  cJSON_Delete(root);
  if (!found) {
    ESP_LOGW(TAG, "No cloud lock matched BLE MAC %s", this->cloud_ble_mac_.c_str());
    return false;
  }
  return true;
}

void GainsboroughTrilockLock::control(const lock::LockCall &call) {
  auto opt = call.get_state();
  if (!opt.has_value())
    return;
  auto state = *opt;
  ESP_LOGD(TAG, "Lock control: state=%u", (unsigned) state);
  if (state == lock::LOCK_STATE_LOCKED) {
    this->publish_state(lock::LOCK_STATE_LOCKING);
    this->enqueue_state_(STATE_LOCKED_PRIVACY);
  } else if (state == lock::LOCK_STATE_UNLOCKED) {
    this->publish_state(lock::LOCK_STATE_UNLOCKING);
    this->enqueue_state_(STATE_UNLOCKED);
  }
}

void GainsboroughTrilockLock::open_latch() {
  // no-op
}

void GainsboroughTrilockLock::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                                       esp_ble_gattc_cb_param_t *param) {
  // Call base class for ESPHome internal state management
  ble_client::BLEClientNode::gattc_event_handler(event, gattc_if, param);

  this->gattc_if_ = gattc_if;

  if (this->parent() == nullptr)
    return;

  auto *base = static_cast<esp32_ble_client::BLEClientBase *>(this->parent());

  switch (event) {
    case ESP_GATTC_OPEN_EVT:
      ESP_LOGD(TAG, "gattc_event OPEN status=%d", (int) param->open.status);
      break;

    case ESP_GATTC_CONNECT_EVT:
      ESP_LOGD(TAG, "gattc_event CONNECT conn_id=%u", (unsigned) param->connect.conn_id);
      if (param->connect.conn_id == this->parent()->get_conn_id()) {
        this->on_connected_();
      }
      break;

    case ESP_GATTC_DISCONNECT_EVT:
      ESP_LOGD(TAG, "gattc_event DISCONNECT reason=0x%02X", (int) param->disconnect.reason);
      if (param->disconnect.conn_id == this->parent()->get_conn_id())
        this->on_disconnected_();
      break;

    case ESP_GATTC_SEARCH_CMPL_EVT: {
      ESP_LOGD(TAG, "gattc_event SEARCH_CMPL status=%d", (int) param->search_cmpl.status);
      if (param->search_cmpl.conn_id != this->parent()->get_conn_id()) break;
      searching_ = false;
      if (param->search_cmpl.status == ESP_GATT_OK) {
        search_complete_ = true;
        
        auto service_uuid = esp32_ble::ESPBTUUID::from_raw(SERVICE_UUID);
        auto *service = base->get_service(service_uuid);
        if (service != nullptr) {
            ESP_LOGI(TAG, "Service: %s", service->uuid.to_string().c_str());
            for (auto *chr : service->characteristics) {
                ESP_LOGI(TAG, "  Characteristic: %s (Handle: 0x%04x)", chr->uuid.to_string().c_str(), chr->handle);
            }
        } else {
            ESP_LOGW(TAG, "Service %s not found during discovery", SERVICE_UUID);
        }
        ESP_LOGI(TAG, "Service discovery complete, awaiting tree parse.");
      }
      break;
    }

    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      if (param->reg_for_notify.status != ESP_GATT_OK) {
        ESP_LOGW(TAG, "reg_for_notify status error: %d", param->reg_for_notify.status);
        break;
      }
      auto *chr = base->get_characteristic(param->reg_for_notify.handle);
      if (chr == nullptr) {
        ESP_LOGW(TAG, "Char not found for handle 0x%04x", param->reg_for_notify.handle);
        break;
      }
      auto *cccd = chr->get_descriptor(static_cast<uint16_t>(0x2902));
      if (cccd == nullptr) {
        ESP_LOGI(TAG, "No CCCD found; assuming notifications enabled");
        gatt_ready_ = true;
        this->node_state = esp32_ble_tracker::ClientState::ESTABLISHED;
        break;
      }
      // This characteristic supports INDICATE. Enable indications (0x0002).
      uint8_t notify_en[2] = {0x02, 0x00};
      esp_err_t ret = esp_ble_gattc_write_char_descr(
          base->get_gattc_if(), base->get_conn_id(),
          cccd->handle, sizeof(notify_en), notify_en,
          ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
      if (ret != ESP_OK)
        ESP_LOGW(TAG, "Write CCCD failed: %d", ret);
      else
        ESP_LOGI(TAG, "CCCD Write Init (Indication enable)");
      break;
    }

    case ESP_GATTC_WRITE_DESCR_EVT: {
      if (param->write.status == ESP_GATT_OK) {
        ESP_LOGI(TAG, "Notifications enabled successfully");
        gatt_ready_ = true;
        this->node_state = esp32_ble_tracker::ClientState::ESTABLISHED;
      } else {
        ESP_LOGW(TAG, "CCCD Write failed, status=%d", param->write.status);
      }
      break;
    }

    case ESP_GATTC_NOTIFY_EVT: {
      if (param->notify.conn_id != this->parent()->get_conn_id())
        break;
      
      if (param->notify.handle == this->char_handle_) {
        size_t len = std::min((size_t) param->notify.value_len, sizeof(notify_buf_));
        memcpy(notify_buf_, param->notify.value, len);
        notify_len_ = len;
        notify_pending_ = true;
      } else if (param->notify.handle == this->sync_char_handle_) {
        size_t len = std::min((size_t) param->notify.value_len, sizeof(sync_buf_));
        memcpy(sync_buf_, param->notify.value, len);
        sync_len_ = len;
        sync_pending_ = true;
        this->log_sync_debug_packet_("RX", param->notify.handle, SYNC_CHARACTERISTIC_UUID, "notify",
                                     sync_buf_, len);
        ESP_LOGD(TAG, "Sync notification received: handle=0x%04X, len=%u, data=%s", param->notify.handle, len, format_hex_pretty(sync_buf_, len).c_str());
      }
      
      last_notify_ = millis();
      break;
    }

    default:
      break;
  }
}

void GainsboroughTrilockLock::set_aes_key_string(const std::string &key_b64) {
  if (key_b64.empty()) {
    ESP_LOGW(TAG, "AES key is empty");
    return;
  }
  uint8_t decoded[64];
  size_t out_len = 0;
  int ret = mbedtls_base64_decode(decoded, sizeof(decoded), &out_len,
                                  reinterpret_cast<const uint8_t *>(key_b64.data()),
                                  key_b64.size());
  if (ret != 0 || out_len < 32) {
    ESP_LOGW(TAG, "Failed to decode AES key (ret=%d, len=%u)", ret, (unsigned) out_len);
    return;
  }
  memcpy(aes_key_, decoded, 32);
  has_key_ = true;
}

void GainsboroughTrilockLock::set_target_state(uint8_t state) {
  if (state == 1) {
    this->publish_state(lock::LOCK_STATE_UNLOCKING);
    this->enqueue_state_(STATE_UNLOCKED);
  } else if (state == 2) {
    this->publish_state(lock::LOCK_STATE_LOCKING);
    this->enqueue_state_(STATE_LOCKED_PRIVACY);
  } else if (state == 3) {
    this->publish_state(lock::LOCK_STATE_LOCKING);
    this->enqueue_state_(STATE_LOCKED_DEADLOCK);
  }
}

void GainsboroughTrilockLock::on_connected_() {
  gatt_ready_ = false;
  searching_ = false;
  search_complete_ = false;
  last_gatt_attempt_ = 0;
  ESP_LOGI(TAG, "Connected to Gainsborough Trilock; requesting MTU 247...");
  esp_ble_gattc_send_mtu_req(this->gattc_if_, this->parent()->get_conn_id());
}

void GainsboroughTrilockLock::on_disconnected_() {
  gatt_ready_ = false;
  searching_ = false;
  search_complete_ = false;
  protocol_active_ = false;
  active_state_ = 0;
  pending_state_ = 0;
  notify_pending_ = false;
  notify_len_ = 0;
  sync_pending_ = false;
  sync_len_ = 0;
  sync_diag_active_ = false;
  sync_bootstrap_active_ = false;
  sync_bootstrap_pending_ = false;
  sync_cloud_refresh_waiting_status_ = false;
  sync_cloud_upload_after_receive_ = false;
  sync_doai_msg_received_ = 0;
  has_sync_nonce_override_ = false;
  has_sync_msg_id_override_ = false;
  this->clear_cloud_doai_nonce_();
  last_gatt_attempt_ = 0;
  ESP_LOGI(TAG, "Disconnected from Gainsborough Trilock");
}

void GainsboroughTrilockLock::publish_lock_state_(LockState state) {
  if (lock_status_sensor_ != nullptr) {
    switch (state) {
      case STATE_UNLOCKED:
        lock_status_sensor_->publish_state("UNLOCKED");
        break;
      case STATE_LOCKED_PRIVACY:
        lock_status_sensor_->publish_state("LOCKED_PRIVACY");
        break;
      case STATE_LOCKED_DEADLOCK:
        lock_status_sensor_->publish_state("LOCKED_DEADLOCK");
        break;
      case STATE_ERROR_FORCED:
        lock_status_sensor_->publish_state("ERROR_FORCED");
        break;
      case STATE_ERROR_JAMMED:
        lock_status_sensor_->publish_state("ERROR_JAMMED");
        break;
      default:
        lock_status_sensor_->publish_state("UNKNOWN");
        break;
    }
  }
  switch (state) {
    case STATE_UNLOCKED:
      this->publish_state(lock::LOCK_STATE_UNLOCKED);
      break;
    case STATE_LOCKED_PRIVACY:
    case STATE_LOCKED_DEADLOCK:
      this->publish_state(lock::LOCK_STATE_LOCKED);
      break;
    case STATE_ERROR_JAMMED:
      this->publish_state(lock::LOCK_STATE_JAMMED);
      break;
    default:
      break;
  }
}

void GainsboroughTrilockLock::publish_battery_info_(bool low, int pct) {
  if (battery_level_sensor_ != nullptr && pct >= 0 && pct <= 100)
    battery_level_sensor_->publish_state(pct);
  if (battery_low_binary_sensor_ != nullptr)
    battery_low_binary_sensor_->publish_state(low);
}

void GainsboroughTrilockLock::publish_door_status_(bool closed) {
  if (door_status_binary_sensor_ != nullptr)
    door_status_binary_sensor_->publish_state(!closed);
}

void GainsboroughTrilockLock::enqueue_state_(uint8_t state) {
  pending_state_ = state;
  pending_since_ = millis();
  ESP_LOGD(TAG, "Queued command state=%u", (unsigned) pending_state_);
  this->send_pending_if_ready_();
}

void GainsboroughTrilockLock::send_pending_if_ready_() {
  if (pending_state_ == 0)
    return;
  if (this->parent() == nullptr || !this->parent()->connected())
    return;
  if (!gatt_ready_)
    return;

  // Wait patiently for any active protocol to clear without spamming logs
  if (protocol_active_ && (millis() - last_notify_) < PROTOCOL_TIMEOUT_MS)
    return;

  if (!has_key_) {
    ESP_LOGE(TAG, "Cannot send command: AES key not set in secrets.yaml");
    pending_state_ = 0;
    pending_since_ = 0;
    return;
  }

  uint8_t state_to_send = pending_state_;
  uint32_t time_enqueued = pending_since_;
  active_state_ = state_to_send;
  bool ok = this->begin_command_(state_to_send);
  if (ok) {
    ESP_LOGD(TAG, "Sent pending command state=%u", (unsigned) state_to_send);
    pending_state_ = 0;
    pending_since_ = 0;
  } else {
    active_state_ = 0;
    if (time_enqueued != 0 && (millis() - time_enqueued) > 10000) {
      ESP_LOGW(TAG, "Pending command timed out before send (state=%u)", (unsigned) pending_state_);
      pending_state_ = 0;
      pending_since_ = 0;
    }
  }
}

void GainsboroughTrilockLock::ensure_gatt_ready_() {
  if (gatt_ready_)
    return;
  if (!search_complete_)
    return;

  uint32_t now = millis();
  if (last_gatt_attempt_ != 0 && (now - last_gatt_attempt_) < 5000)
    return;
  last_gatt_attempt_ = now;

  auto *base = static_cast<esp32_ble_client::BLEClientBase *>(this->parent());
  if (base == nullptr || !base->connected())
    return;

  auto service_uuid = esp32_ble::ESPBTUUID::from_raw(SERVICE_UUID);
  auto cmd_char_uuid = esp32_ble::ESPBTUUID::from_raw(CMD_CHARACTERISTIC_UUID);
  auto sync_char_uuid = esp32_ble::ESPBTUUID::from_raw(SYNC_CHARACTERISTIC_UUID);

  auto *cmd_chr = base->get_characteristic(service_uuid, cmd_char_uuid);
  auto *sync_chr = base->get_characteristic(service_uuid, sync_char_uuid);
  
  if (cmd_chr == nullptr) {
    ESP_LOGW(TAG, "CMD characteristic not found");
    return;
  }
  this->char_handle_ = cmd_chr->handle;
  esp_ble_gattc_register_for_notify(this->gattc_if_, base->get_remote_bda(), this->char_handle_);

  if (sync_chr != nullptr) {
    this->sync_char_handle_ = sync_chr->handle;
    esp_ble_gattc_register_for_notify(this->gattc_if_, base->get_remote_bda(), this->sync_char_handle_);
    ESP_LOGI(TAG, "Registered for notifications on CMD (0x%04x) and SYNC (0x%04x)", this->char_handle_, this->sync_char_handle_);
  } else {
    ESP_LOGW(TAG, "SYNC characteristic not found, continuing with CMD only");
    ESP_LOGI(TAG, "Registered for notifications on CMD (0x%04x)", this->char_handle_);
  }
  
  // Trigger a status request immediately after notification registration
  ESP_LOGI(TAG, "Triggering initial status request");
  uint8_t req[17];
  memset(req, 0, 17);
  req[0] = 0x10;
  esp_fill_random(req + 5, 12);
  memcpy(sender_nonce_, req + 5, 12);
  this->write_cmd_(req, 17);
}

void GainsboroughTrilockLock::handle_notify_() {
  if (notify_len_ == 0)
    return;
  this->handle_protocol_step_(notify_buf_, notify_len_);
  notify_len_ = 0;
}

void GainsboroughTrilockLock::handle_sync_notify_(const uint8_t *data, size_t len) {
  if (len == 0)
    return;

  ESP_LOGD(TAG, "Sync channel notification: len=%u, type=0x%02X, data=%s",
           (unsigned) len, data[0], format_hex_pretty(data, len).c_str());

  if (data[0] == 0x00) {
    if (len < 6) {
      ESP_LOGW(TAG, "Sync queue summary too short: %u raw=%s", (unsigned) len,
               format_hex_pretty(data, len).c_str());
      return;
    }
    uint8_t count = data[1];
    uint16_t doai_id = (uint16_t) data[2] | ((uint16_t) data[3] << 8);
    uint16_t diao_id = (uint16_t) data[4] | ((uint16_t) data[5] << 8);
    sync_last_summary_count_ = count;
    sync_last_summary_doai_msg_id_ = doai_id;
    sync_last_summary_diao_msg_id_ = diao_id;
    ESP_LOGI(TAG, "Sync queue summary: doAiCount=%u[@1] doAiMsgId=%u[@2..3] diAoMsgId=%u[@4..5] raw=%s",
             count, doai_id, diao_id, format_hex_pretty(data, len).c_str());
    ESP_LOGI(TAG, "Sync queue summary compact: doAiCount=%u doAiMsgId=%u diAoMsgId=%u",
             count, doai_id, diao_id);
    if (sync_diag_active_ && count > 0 && doai_id != 0 && sync_doai_msg_id_ == 0)
      this->start_sync_doai_transfer_(doai_id, 0);
    return;
  }

  if (data[0] == 0x01) {
    if (len < 13) {
      ESP_LOGW(TAG, "Sync DoAi status too short: %u", (unsigned) len);
      return;
    }
    uint8_t flags = data[1];
    uint16_t transfer_id = (uint16_t) data[2] | ((uint16_t) data[3] << 8);
    uint16_t msg_len = (uint16_t) data[4] | ((uint16_t) data[5] << 8);
    uint8_t msg_count = data[10];
    uint16_t msg_id = (uint16_t) data[11] | ((uint16_t) data[12] << 8);
    sync_last_status_msg_count_ = msg_count;
    sync_last_status_transfer_id_ = transfer_id;
    sync_last_status_msg_id_ = msg_id;
    sync_last_status_msg_len_ = msg_len;
    ESP_LOGI(TAG, "Sync DoAi status: flags=0x%02X[@1] transferId=%u[@2..3] msgLen=%u[@4..5] msgCount=%u[@10] msgId=%u[@11..12] crc=%02X%02X%02X%02X[@6..9]",
             flags, transfer_id, msg_len, msg_count, msg_id, data[6], data[7], data[8], data[9]);

    if (sync_cloud_refresh_waiting_status_ && sync_doai_msg_id_ == 0) {
      if (msg_count == 0 || msg_id == 0) {
        ESP_LOGW(TAG, "Sync cloud refresh found no BLE DoAi message to transfer: msgCount=%u msgId=%u",
                 msg_count, msg_id);
        sync_cloud_refresh_waiting_status_ = false;
        sync_diag_active_ = false;
        return;
      }
      sync_cloud_refresh_waiting_status_ = false;
      ESP_LOGI(TAG, "Sync cloud refresh selected BLE msgId=%u; fetching cloud nonce", msg_id);
      if (!this->fetch_cloud_gwasm_status_()) {
        sync_diag_active_ = false;
        return;
      }
      sync_cloud_upload_after_receive_ = true;
      ESP_LOGI(TAG, "Sync cloud refresh starting transfer: bleMsgId=%u cloudStatusMsgId=%u",
               msg_id, current_doai_msg_id_);
      this->start_sync_doai_transfer_with_nonce_(msg_id, msg_len, current_doai_nonce_, "cloudDoAiNonce");
      return;
    }

    if (sync_diag_active_) {
      if (transfer_id != 0 && transfer_id == sync_doai_msg_id_ && msg_len > 0) {
        sync_doai_msg_len_ = msg_len;
        ESP_LOGI(TAG, "Sync DoAi transfer active: msgId=%u expectedLen=%u", transfer_id, msg_len);
      } else if (msg_count > 0 && msg_id != 0 && sync_doai_msg_id_ == 0) {
        this->start_sync_doai_transfer_(msg_id, msg_len);
      }
    }
    return;
  }

  if (data[0] == 0x30) {
    if (len < 5)
      return;
    uint16_t msg_id = (uint16_t) data[1] | ((uint16_t) data[2] << 8);
    uint16_t offset = (uint16_t) data[3] | ((uint16_t) data[4] << 8);
    ESP_LOGD(TAG, "Sync DoAi fragment: msgId=%u[@1..2] offset=%u[@3..4] dataLen=%u payload=%s",
             msg_id, offset, (unsigned) (len - 5), format_hex_pretty(data + 5, len - 5).c_str());
    if (sync_diag_active_ && msg_id == sync_doai_msg_id_)
      this->append_sync_fragment_(offset, data + 5, len - 5);
    return;
  }

  if (data[0] == 0x12) {
    ESP_LOGI(TAG, "Sync DoAi delete response: %s", format_hex_pretty(data, len).c_str());
    return;
  }

  ESP_LOGD(TAG, "Unhandled sync response type=0x%02X", data[0]);
}

void GainsboroughTrilockLock::start_sync_doai_transfer_(uint16_t msg_id, uint16_t msg_len) {
  if (!current_doai_nonce_valid_ || current_doai_msg_id_ != msg_id) {
    if (current_doai_nonce_valid_) {
      ESP_LOGW(TAG, "Refusing Sync DoAi transfer for msgId=%u: cloud doAiNonce is for msgId=%u",
               msg_id, current_doai_msg_id_);
    } else {
      ESP_LOGW(TAG, "Refusing Sync DoAi transfer for msgId=%u: cloud doAiNonce is not set", msg_id);
    }
    ESP_LOGW(TAG, "Call sync_set_cloud_nonce before requesting this Sync DoAi message; no random nonce fallback is used");
    return;
  }

  this->start_sync_doai_transfer_with_nonce_(msg_id, msg_len, current_doai_nonce_, "cloudDoAiNonce");
}

void GainsboroughTrilockLock::start_sync_doai_transfer_with_nonce_(uint16_t msg_id, uint16_t msg_len,
                                                                   const uint8_t *nonce,
                                                                   const char *nonce_source) {
  sync_doai_msg_id_ = msg_id;
  sync_doai_msg_len_ = msg_len;
  sync_doai_msg_received_ = 0;
  memset(sync_doai_msg_, 0, sizeof(sync_doai_msg_));
  memcpy(sender_nonce_, nonce, sizeof(sender_nonce_));

  uint8_t req[17];
  req[0] = 0x10;
  req[1] = msg_id & 0xFF;
  req[2] = (msg_id >> 8) & 0xFF;
  req[3] = 0x00;
  req[4] = 0x00;
  memcpy(req + 5, sender_nonce_, sizeof(sender_nonce_));
  ESP_LOGI(TAG, "Starting Sync DoAi transfer: msgId=%u expectedLen=%u", msg_id, msg_len);
  ESP_LOGD(TAG, "Sync DoAi transfer nonce source=%s nonce=%s",
           nonce_source, format_hex_pretty(sender_nonce_, sizeof(sender_nonce_)).c_str());
  if (!this->write_sync_(req, sizeof(req))) {
    ESP_LOGW(TAG, "Failed to start Sync DoAi transfer");
  } else {
    uint8_t status_req[1] = {0x01};
    this->write_sync_(status_req, sizeof(status_req));
  }
}

void GainsboroughTrilockLock::append_sync_fragment_(uint16_t offset, const uint8_t *data, size_t len) {
  if (offset + len > sizeof(sync_doai_msg_)) {
    ESP_LOGW(TAG, "Sync DoAi message exceeds buffer: offset=%u len=%u capacity=%u",
             offset, (unsigned) len, (unsigned) sizeof(sync_doai_msg_));
    sync_diag_active_ = false;
    return;
  }
  memcpy(sync_doai_msg_ + offset, data, len);
  sync_doai_msg_received_ = std::max(sync_doai_msg_received_, (size_t) offset + len);
  ESP_LOGD(TAG, "Sync DoAi assembled %u/%u bytes", (unsigned) sync_doai_msg_received_,
           (unsigned) sync_doai_msg_len_);

  if (sync_doai_msg_len_ == 0 && sync_doai_msg_received_ >= 6) {
    uint16_t plain_len = (uint16_t) sync_doai_msg_[4] | ((uint16_t) sync_doai_msg_[5] << 8);
    uint16_t pad_len = 16 - (plain_len & 15);
    sync_doai_msg_len_ = 34 + plain_len + pad_len;
    ESP_LOGI(TAG, "Inferred Sync DoAi total length from encrypted header: %u",
             (unsigned) sync_doai_msg_len_);
  }

  if (sync_doai_msg_len_ != 0 && sync_doai_msg_received_ >= sync_doai_msg_len_)
    this->decode_sync_doai_message_();
}

void GainsboroughTrilockLock::decode_sync_doai_message_() {
  size_t total_len = sync_doai_msg_len_;
  if (total_len < 34 || total_len > sync_doai_msg_received_) {
    ESP_LOGW(TAG, "Sync DoAi assembled message has unexpected length: total=%u received=%u",
             (unsigned) total_len, (unsigned) sync_doai_msg_received_);
    return;
  }

  ESP_LOGI(TAG, "Sync DoAi payload assembled: msgId=%u len=%u",
           sync_doai_msg_id_, (unsigned) total_len);
  if (sync_cloud_upload_after_receive_) {
    sync_cloud_upload_after_receive_ = false;
    if (this->post_cloud_doai_message_(sync_doai_msg_id_, sync_doai_msg_, total_len)) {
      ESP_LOGI(TAG, "Polling cloud property state after GWASM DoAi upload");
      this->poll_cloud_lock_state_();
      this->set_timeout("gwasm_poll_after_post", 2500, [this]() {
        ESP_LOGI(TAG, "Polling cloud property state after GWASM processing delay");
        this->poll_cloud_lock_state_();
      });
      sync_diag_active_ = false;
      sync_bootstrap_active_ = false;
      return;
    }
  }

  if (!current_doai_nonce_valid_ || current_doai_msg_id_ != sync_doai_msg_id_) {
    ESP_LOGW(TAG, "Refusing Sync DoAi decrypt for msgId=%u: matching cloud doAiNonce is not available",
             sync_doai_msg_id_);
    return;
  }

  uint16_t plain_len = (uint16_t) sync_doai_msg_[4] | ((uint16_t) sync_doai_msg_[5] << 8);
  size_t cipher_len = total_len - 34;
  if (cipher_len > 512) {
    ESP_LOGW(TAG, "Sync DoAi cipher too large: %u", (unsigned) cipher_len);
    return;
  }

  alignas(16) uint8_t dec[544]{};
  bool decoded = false;
  alignas(16) uint8_t final_iv[24];
  memcpy(final_iv, current_doai_nonce_, sizeof(current_doai_nonce_));
  memcpy(final_iv + 12, sync_doai_msg_ + 6, 12);
  ESP_LOGI(TAG, "Sync DoAi decrypt inputs: msgId=%u cloudDoAiNonce=%s rxNonce=%s iv=%s",
           sync_doai_msg_id_, format_hex_pretty(current_doai_nonce_, sizeof(current_doai_nonce_)).c_str(),
           format_hex_pretty(sync_doai_msg_ + 6, 12).c_str(),
           format_hex_pretty(final_iv, sizeof(final_iv)).c_str());
  if (decode_message_checked(aes_key_, sync_doai_msg_, total_len, dec, current_doai_nonce_)) {
    size_t scan_len = plain_len != 0 && plain_len <= cipher_len ? plain_len : cipher_len;
    ESP_LOGI(TAG, "Authenticated Sync DoAi payload plainLen=%u scanLen=%u data=%s",
             plain_len, (unsigned) scan_len, format_hex_pretty(dec, scan_len).c_str());
    this->scan_sync_payload_for_telemetry_(dec, scan_len);
    decoded = true;
  } else {
    ESP_LOGW(TAG, "Sync DoAi authenticated decrypt failed with cloud doAiNonce; not deleting message");
  }

  if (decoded) {
    if (sync_diag_no_delete_) {
      ESP_LOGW(TAG, "Sync DoAi decrypted during diagnostics; not deleting/acking message");
    } else {
      uint8_t del[3] = {0x12, (uint8_t) (sync_doai_msg_id_ & 0xFF), (uint8_t) (sync_doai_msg_id_ >> 8)};
      this->write_sync_(del, sizeof(del));
    }
  }
  sync_diag_active_ = false;
  sync_bootstrap_active_ = false;
}

void GainsboroughTrilockLock::scan_sync_payload_for_telemetry_(const uint8_t *data, size_t len) {
  bool door_found = false;
  bool door_closed = false;
  bool battery_found = false;
  int battery_percent = -1;
  bool battery_low_found = false;
  bool battery_low = false;

  scan_proto_telemetry_(data, len, 0, &door_found, &door_closed, &battery_found,
                        &battery_percent, &battery_low_found, &battery_low);

  if (door_found)
    this->publish_door_status_(door_closed);
  if (battery_found || battery_low_found)
    this->publish_battery_info_(battery_low, battery_percent);

  if (!door_found && !battery_found && !battery_low_found)
    ESP_LOGW(TAG, "No high-confidence door/battery telemetry found in Sync DoAi payload yet");
}

void GainsboroughTrilockLock::log_sync_debug_packet_(const char *dir, uint16_t handle, const char *uuid,
                                                     const char *mode, const uint8_t *data, size_t len) {
  if (!sync_debug_)
    return;
  uint8_t type = len > 0 ? data[0] : 0xFF;
  uint16_t msg_id = 0;
  uint16_t msg_len = 0;
  uint8_t msg_count = 0;
  uint32_t crc = 0;
  if (len >= 13 && type == 0x01) {
    msg_len = (uint16_t) data[4] | ((uint16_t) data[5] << 8);
    msg_count = data[10];
    msg_id = (uint16_t) data[11] | ((uint16_t) data[12] << 8);
    crc = (uint32_t) data[6] | ((uint32_t) data[7] << 8) | ((uint32_t) data[8] << 16) |
          ((uint32_t) data[9] << 24);
  } else if (len >= 6 && type == 0x00) {
    msg_count = data[1];
    msg_id = (uint16_t) data[2] | ((uint16_t) data[3] << 8);
  } else if (len >= 5 && (type == 0x10 || type == 0x12 || type == 0x30)) {
    msg_id = (uint16_t) data[1] | ((uint16_t) data[2] << 8);
    if (type == 0x30)
      msg_len = (uint16_t) data[3] | ((uint16_t) data[4] << 8);
  }
  ESP_LOGI(TAG,
           "SYNC_DEBUG t=%u %s handle=0x%04X uuid=%s mode=%s len=%u type=0x%02X msgId=%u msgLen=%u msgCount=%u crc=%08X data=%s",
           millis(), dir, handle, uuid, mode, (unsigned) len, type, msg_id, msg_len, msg_count,
           (unsigned) crc, format_hex_pretty(data, len).c_str());
}

void GainsboroughTrilockLock::reset_sync_diagnostics_state_() {
  sync_diag_active_ = true;
  sync_diag_no_delete_ = true;
  sync_diag_started_ = millis();
  sync_doai_msg_id_ = 0;
  sync_doai_msg_len_ = 0;
  sync_doai_msg_received_ = 0;
  sync_last_summary_count_ = 0;
  sync_last_summary_doai_msg_id_ = 0;
  sync_last_summary_diao_msg_id_ = 0;
  sync_last_status_msg_count_ = 0;
  sync_last_status_transfer_id_ = 0;
  sync_last_status_msg_id_ = 0;
  sync_last_status_msg_len_ = 0;
  memset(sync_doai_msg_, 0, sizeof(sync_doai_msg_));
}

void GainsboroughTrilockLock::set_cloud_doai_nonce_(uint16_t msg_id, const uint8_t *bytes) {
  current_doai_msg_id_ = msg_id;
  memcpy(current_doai_nonce_, bytes, sizeof(current_doai_nonce_));
  current_doai_nonce_valid_ = true;
  ESP_LOGD(TAG, "Stored cloud Sync DoAi nonce: msgId=%u nonce=%s",
           current_doai_msg_id_, format_hex_pretty(current_doai_nonce_, sizeof(current_doai_nonce_)).c_str());
}

void GainsboroughTrilockLock::clear_cloud_doai_nonce_() {
  current_doai_msg_id_ = 0;
  memset(current_doai_nonce_, 0, sizeof(current_doai_nonce_));
  current_doai_nonce_valid_ = false;
}

const char *GainsboroughTrilockLock::sync_bootstrap_variant_name_() const {
  switch (sync_bootstrap_current_variant_) {
    case SyncBootstrapVariant::A:
      return "A";
    case SyncBootstrapVariant::B:
      return "B";
    case SyncBootstrapVariant::C:
      return "C";
    case SyncBootstrapVariant::D:
      return "D";
    case SyncBootstrapVariant::E:
      return "E";
    default:
      return "auto";
  }
}

bool GainsboroughTrilockLock::sync_bootstrap_variant_done_() {
  return sync_last_summary_count_ > 0 || sync_last_status_msg_count_ > 0 ||
         sync_last_status_msg_len_ > 0 || sync_doai_msg_received_ > 0;
}

bool GainsboroughTrilockLock::advance_sync_bootstrap_variant_() {
  if (sync_bootstrap_requested_variant_ != SyncBootstrapVariant::AUTO) {
    if (++sync_bootstrap_attempt_ < sync_bootstrap_retry_count_) {
      sync_bootstrap_step_ = 0;
      sync_bootstrap_next_action_ = millis() + 250;
      return true;
    }
    return false;
  }

  if (++sync_bootstrap_attempt_ < sync_bootstrap_retry_count_) {
    sync_bootstrap_step_ = 0;
    sync_bootstrap_next_action_ = millis() + 250;
    return true;
  }

  sync_bootstrap_attempt_ = 0;
  switch (sync_bootstrap_current_variant_) {
    case SyncBootstrapVariant::A:
      sync_bootstrap_current_variant_ = SyncBootstrapVariant::B;
      break;
    case SyncBootstrapVariant::B:
      sync_bootstrap_current_variant_ = SyncBootstrapVariant::C;
      break;
    case SyncBootstrapVariant::C:
      sync_bootstrap_current_variant_ = SyncBootstrapVariant::D;
      break;
    case SyncBootstrapVariant::D:
      if (!sync_bootstrap_has_target_ || !sync_bootstrap_has_nonce_)
        return false;
      sync_bootstrap_current_variant_ = SyncBootstrapVariant::E;
      break;
    default:
      return false;
  }
  sync_bootstrap_step_ = 0;
  sync_bootstrap_next_action_ = millis() + 250;
  return true;
}

void GainsboroughTrilockLock::start_phone_like_sync_bootstrap_() {
  if (!gatt_ready_ || sync_char_handle_ == 0)
    return;
  sync_bootstrap_pending_ = false;
  sync_bootstrap_active_ = true;
  sync_bootstrap_current_variant_ = sync_bootstrap_requested_variant_ == SyncBootstrapVariant::AUTO
                                        ? SyncBootstrapVariant::A
                                        : sync_bootstrap_requested_variant_;
  sync_bootstrap_step_ = 0;
  sync_bootstrap_attempt_ = 0;
  sync_bootstrap_next_action_ = millis();
  this->reset_sync_diagnostics_state_();
  std::string nonce_text = sync_bootstrap_has_nonce_
                               ? format_hex_pretty(sync_bootstrap_nonce_, sizeof(sync_bootstrap_nonce_))
                               : "none";
  ESP_LOGI(TAG, "Starting phone-like sync bootstrap: variant=%s retries=%u target=%u nonce=%s",
           this->sync_bootstrap_variant_name_(), sync_bootstrap_retry_count_,
           sync_bootstrap_has_target_ ? sync_bootstrap_target_msg_id_ : 0, nonce_text.c_str());
}

void GainsboroughTrilockLock::process_phone_like_sync_bootstrap_() {
  const uint32_t now = millis();
  if (now < sync_bootstrap_next_action_)
    return;
  if (this->sync_bootstrap_variant_done_()) {
    this->finish_phone_like_sync_bootstrap_(true);
    return;
  }

  const uint8_t queue_req[1] = {0x00};
  const uint8_t status_req[1] = {0x01};
  esp_gatt_write_type_t write_type =
      sync_bootstrap_current_variant_ == SyncBootstrapVariant::D ? ESP_GATT_WRITE_TYPE_NO_RSP : ESP_GATT_WRITE_TYPE_RSP;

  if (sync_bootstrap_current_variant_ == SyncBootstrapVariant::E) {
    if (!sync_bootstrap_has_target_ || !sync_bootstrap_has_nonce_) {
      ESP_LOGW(TAG, "Skipping bootstrap variant E because target msgId or nonce is missing");
      if (!this->advance_sync_bootstrap_variant_())
        this->finish_phone_like_sync_bootstrap_(false);
      return;
    }
    if (sync_bootstrap_step_ == 0) {
      uint8_t req[17];
      req[0] = 0x10;
      req[1] = sync_bootstrap_target_msg_id_ & 0xFF;
      req[2] = (sync_bootstrap_target_msg_id_ >> 8) & 0xFF;
      req[3] = 0x00;
      req[4] = 0x00;
      this->set_cloud_doai_nonce_(sync_bootstrap_target_msg_id_, sync_bootstrap_nonce_);
      memcpy(sender_nonce_, current_doai_nonce_, sizeof(sender_nonce_));
      memcpy(req + 5, current_doai_nonce_, sizeof(current_doai_nonce_));
      sync_doai_msg_id_ = sync_bootstrap_target_msg_id_;
      ESP_LOGI(TAG, "Bootstrap variant E: transfer-start msgId=%u cloudDoAiNonce=%s",
               sync_bootstrap_target_msg_id_,
               format_hex_pretty(current_doai_nonce_, sizeof(current_doai_nonce_)).c_str());
      this->write_sync_(req, sizeof(req), ESP_GATT_WRITE_TYPE_RSP);
      sync_bootstrap_step_ = 1;
      sync_bootstrap_next_action_ = now + 100;
      return;
    }
    if (sync_bootstrap_step_ == 1) {
      this->write_sync_(status_req, sizeof(status_req), ESP_GATT_WRITE_TYPE_RSP);
      sync_bootstrap_step_ = 2;
      sync_bootstrap_wait_until_ = now + 1500;
      sync_bootstrap_next_action_ = sync_bootstrap_wait_until_;
      return;
    }
  } else {
    if (sync_bootstrap_step_ == 0) {
      if (sync_bootstrap_current_variant_ == SyncBootstrapVariant::B)
        ESP_LOGI(TAG, "Bootstrap variant B: notifications already enabled before 00/01");
      ESP_LOGI(TAG, "Bootstrap variant %s attempt %u: write 00",
               this->sync_bootstrap_variant_name_(), sync_bootstrap_attempt_ + 1);
      this->write_sync_(queue_req, sizeof(queue_req), write_type);
      sync_bootstrap_step_ = 1;
      sync_bootstrap_next_action_ = now + 100;
      return;
    }
    if (sync_bootstrap_step_ == 1) {
      ESP_LOGI(TAG, "Bootstrap variant %s attempt %u: write 01",
               this->sync_bootstrap_variant_name_(), sync_bootstrap_attempt_ + 1);
      this->write_sync_(status_req, sizeof(status_req), write_type);
      sync_bootstrap_step_ = 2;
      sync_bootstrap_wait_until_ = now + 1500;
      sync_bootstrap_next_action_ = sync_bootstrap_wait_until_;
      return;
    }
  }

  if (now >= sync_bootstrap_wait_until_) {
    ESP_LOGI(TAG, "Bootstrap variant %s attempt %u saw no queued DoAi data; summary count=%u status count=%u msgLen=%u",
             this->sync_bootstrap_variant_name_(), sync_bootstrap_attempt_ + 1, sync_last_summary_count_,
             sync_last_status_msg_count_, sync_last_status_msg_len_);
    if (!this->advance_sync_bootstrap_variant_())
      this->finish_phone_like_sync_bootstrap_(false);
  }
}

void GainsboroughTrilockLock::finish_phone_like_sync_bootstrap_(bool success) {
  ESP_LOGI(TAG, "Phone-like sync bootstrap %s: summaryCount=%u summaryDoAiMsgId=%u statusCount=%u statusMsgId=%u msgLen=%u received=%u",
           success ? "complete" : "exhausted", sync_last_summary_count_, sync_last_summary_doai_msg_id_,
           sync_last_status_msg_count_, sync_last_status_msg_id_, sync_last_status_msg_len_,
           (unsigned) sync_doai_msg_received_);
  sync_bootstrap_active_ = false;
  sync_bootstrap_pending_ = false;
  if (!success)
    sync_diag_active_ = false;
}

bool GainsboroughTrilockLock::write_cmd_(const uint8_t *data, size_t len) {
  return this->write_channel_(this->char_handle_, data, len, ESP_GATT_WRITE_TYPE_RSP, "CMD");
}

bool GainsboroughTrilockLock::write_sync_(const uint8_t *data, size_t len) {
  return this->write_sync_(data, len, ESP_GATT_WRITE_TYPE_RSP);
}

bool GainsboroughTrilockLock::write_sync_(const uint8_t *data, size_t len, esp_gatt_write_type_t write_type) {
  return this->write_channel_(this->sync_char_handle_, data, len, write_type, "SYNC");
}

bool GainsboroughTrilockLock::write_channel_(uint16_t handle, const uint8_t *data, size_t len,
                                             esp_gatt_write_type_t write_type, const char *channel) {
  auto *base = static_cast<esp32_ble_client::BLEClientBase *>(this->parent());
  if (base == nullptr || !base->connected() || handle == 0)
    return false;

  const char *mode = write_type == ESP_GATT_WRITE_TYPE_NO_RSP ? "without_response" : "with_response";
  if (handle == sync_char_handle_)
    this->log_sync_debug_packet_("TX", handle, SYNC_CHARACTERISTIC_UUID, mode, data, len);
  ESP_LOGD(TAG, "BLE write %s handle=0x%04X mode=%s len=%u data=%s", channel, handle, mode, (unsigned) len,
           format_hex_pretty(data, len).c_str());
  esp_err_t ret = esp_ble_gattc_write_char(
      this->gattc_if_,
      base->get_conn_id(),
      handle,
      len,
      const_cast<uint8_t *>(data),
      write_type,
      ESP_GATT_AUTH_REQ_NONE
  );
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "esp_ble_gattc_write_char failed: %d", ret);
    return false;
  }
  return true;
}

bool GainsboroughTrilockLock::begin_command_(uint8_t desired_state) {
  if (!has_key_ || !gatt_ready_) {
    return false;
  }
  if (protocol_active_ && (millis() - last_notify_) < PROTOCOL_TIMEOUT_MS) {
    return false;
  }
  protocol_active_ = true;
  last_notify_ = millis();
  ESP_LOGD(TAG, "Begin protocol cmd=0x02 desired_state=%u", desired_state);
  send_command_(0x02);
  return true;
}

void GainsboroughTrilockLock::send_command_(uint8_t cmd) {
  uint8_t buf[1] = {cmd};
  if (!this->write_cmd_(buf, 1))
    ESP_LOGW(TAG, "BLE write failed for cmd=0x%02X", cmd);
}

void GainsboroughTrilockLock::handle_protocol_step_(const uint8_t *data, size_t len) {
  if (len < 2)
    return;
  ESP_LOGD(TAG, "Protocol RX len=%u type=0x%02X 0x%02X", (unsigned) len, data[0], data[1]);

  if (data[0] == 0x02 && data[1] == 0x00) {
    if (active_state_ == 0) {
      ESP_LOGW(TAG, "Received 0x02,0x00 but no active state, ignoring");
      return;
    }
    uint16_t msg_id = (uint16_t)(data[19] << 8) | data[18];
    uint8_t nonce[12];
    memcpy(nonce, data + 6, 12);
    uint8_t state_to_use = is_status_query_ ? 0 : active_state_;
    this->generate_payload_(msg_id, nonce, state_to_use);
  } else if (data[0] == 0x02 && data[1] == 0x03) {
    ESP_LOGD(TAG, "Lock ready to receive encoded message");
    this->send_encoded_message_();
  } else if (data[0] == 0x02 && data[1] == 0x04) {
    ESP_LOGD(TAG, "Lock accepted message, requesting status");
    uint8_t ack[1] = {0x01};
    this->write_cmd_(ack, 1);
  } else if (data[0] == 0x01 && data[1] == 0x00) {
    this->request_status_message_(data, len);
  } else if (data[0] == 0x01 && data[1] == 0x02) {
    this->delete_message_(data, len);
  } else if (data[0] == 0x30) {
    this->decode_incoming_message_(data, len);
  } else if (data[0] == 0x01 && data[1] == 0x06) {
    if (pending_state_ != 0) {
      ESP_LOGD(TAG, "Transaction complete, retry - starting new command");
      protocol_active_ = false;
      active_state_ = 0;
      is_status_query_ = false;
      return;
    }
    protocol_active_ = false;
    active_state_ = 0;
    is_status_query_ = false;
    ESP_LOGD(TAG, "Transaction fully complete, disconnecting...");
    this->parent()->disconnect();
  }
}

void GainsboroughTrilockLock::generate_payload_(uint16_t msg_id, const uint8_t *rx_nonce,
                                                     uint8_t desired_state) {
  ESP_LOGD(TAG, "Generating payload: msg_id=%u desired_state=%u", msg_id, desired_state);
  uint8_t req[32];
  size_t req_len = encode_request(req, sizeof(req), desired_state, (uint64_t) esp_random());
  if (req_len == 0) {
    ESP_LOGW(TAG, "encode_request failed");
    return;
  }
  int enc_len = encode_message(aes_key_, req, req_len, encoded_msg_, rx_nonce, msg_id + 1);
  if (enc_len <= 0) {
    ESP_LOGW(TAG, "encode_message failed");
    return;
  }

  encoded_len_ = (uint8_t) enc_len;
  uint16_t new_id = msg_id + 1;
  encoded_id_[0] = new_id & 0xFF;
  encoded_id_[1] = (new_id >> 8) & 0xFF;

  uint8_t write_back[5] = {0x20, encoded_id_[0], encoded_id_[1], encoded_len_, 0};
  ESP_LOGD(TAG, "BLE TX: write_back len=5 id=0x%02X%02X enc_len=%u", 
           encoded_id_[1], encoded_id_[0], encoded_len_);
  this->write_cmd_(write_back, 5);
}

void GainsboroughTrilockLock::send_encoded_message_() {
  if (encoded_len_ < 4) {
    ESP_LOGW(TAG, "Encoded message too short: %u", encoded_len_);
    return;
  }
  uint8_t send_buf[200];
  size_t total = 0;
  send_buf[total++] = 0x30;
  send_buf[total++] = encoded_id_[0];
  send_buf[total++] = encoded_id_[1];
  send_buf[total++] = 0x00;
  send_buf[total++] = 0x00;
  memcpy(send_buf + total, encoded_msg_, encoded_len_);
  total += encoded_len_;
  ESP_LOGD(TAG, "BLE TX: send_buf len=%u", (unsigned) total);
  this->write_cmd_(send_buf, total);

  uint32_t crc_val = calc_crc32(encoded_msg_ + 2, encoded_len_ - 2);
  uint8_t end_msg[9] = {0x21, encoded_id_[0], encoded_id_[1], encoded_len_, 0,
                        (uint8_t)(crc_val), (uint8_t)(crc_val >> 8),
                        (uint8_t)(crc_val >> 16), (uint8_t)(crc_val >> 24)};
  ESP_LOGD(TAG, "BLE TX: end_msg len=9 CRC=0x%08X", (unsigned) crc_val);
  this->write_cmd_(end_msg, sizeof(end_msg));
}

void GainsboroughTrilockLock::request_status_message_(const uint8_t *data, size_t len) {
  if (len < 13)
    return;
  uint8_t msg_count = data[10];
  if (msg_count == 0) {
    ESP_LOGD(TAG, "No DoAi messages yet - lock accepted command, waiting for async response");
    protocol_active_ = false;
    active_state_ = 0;
    return;
  }

  esp_fill_random(sender_nonce_, 12);
  uint8_t req[17];
  req[0] = 0x10;
  req[1] = data[11];
  req[2] = data[12];
  req[3] = 0;
  req[4] = 0;
  memcpy(req + 5, sender_nonce_, 12);
  ESP_LOGD(TAG, "BLE TX: hello len=17");
  this->write_cmd_(req, 17);
}

void GainsboroughTrilockLock::delete_message_(const uint8_t *data, size_t len) {
  if (len < 4)
    return;
  uint8_t ack[3] = {0x12, data[2], data[3]};
  ESP_LOGD(TAG, "BLE TX: ack len=3");
  this->write_cmd_(ack, 3);
}

void GainsboroughTrilockLock::decode_incoming_message_(const uint8_t *data, size_t len) {
  if (len < 23)
    return;
  uint16_t rx_len = (uint16_t)(data[10] << 8) | data[9];
  uint8_t rx_nonce[12];
  memcpy(rx_nonce, data + 11, 12);
  size_t enc_len = len - 23;
  if (enc_len == 0 || enc_len > 128)
    return;
  alignas(16) uint8_t dec[160];
  if (decode_message(aes_key_, data + 23, enc_len, dec, sender_nonce_, rx_nonce)) {
    ESP_LOGD(TAG, "Decrypted Status Payload (len %u): %s", (unsigned)enc_len, format_hex_pretty(dec, enc_len).c_str());
    
    uint8_t desired = 0, reported = 0;
    bool door = false;
    int battery = 0;
    decode_confirm(dec, rx_len, &desired, &reported, &door, &battery);
    
    uint8_t state_to_publish = reported;
    if (desired != 0 && desired != reported) {
      ESP_LOGD(TAG, "Status mismatch - publishing desired state");
      state_to_publish = desired;
    }
    
    pending_state_ = 0;
    status_pending_retry_ = false;
    this->publish_lock_state_((LockState) state_to_publish);
  } else {
    ESP_LOGW(TAG, "decode_message failed!");
  }
  protocol_active_ = false;
}

void GainsboroughTrilockLock::request_status() {
  this->start_status_request_(true);
}

void GainsboroughTrilockLock::start_status_request_(bool manual) {
  if (this->parent() == nullptr || !this->parent()->connected()) {
    if (manual)
      ESP_LOGW(TAG, "Cannot request status: Not connected");
    return;
  }
  if (!has_key_ || !gatt_ready_) {
    if (manual)
      ESP_LOGW(TAG, "Cannot request status: lock protocol is not ready");
    return;
  }
  if (sync_diag_active_ || sync_cloud_refresh_waiting_status_ || sync_bootstrap_active_) {
    if (manual)
      ESP_LOGW(TAG, "Cannot request status: sync refresh is already active");
    return;
  }
  if (protocol_active_ && (millis() - last_notify_) < PROTOCOL_TIMEOUT_MS) {
    if (manual)
      ESP_LOGW(TAG, "Cannot request status: another lock command is already active");
    return;
  }

  ESP_LOGI(TAG, "Requesting lock status%s", manual ? "" : " (auto)");
  is_status_query_ = true;
  active_state_ = 0x01; 
  if (!this->begin_command_(0)) {
    is_status_query_ = false;
    active_state_ = 0;
    if (manual)
      ESP_LOGW(TAG, "Failed to start status request");
  }
}

void GainsboroughTrilockLock::request_sync_diagnostics() {
  if (this->parent() == nullptr || !this->parent()->connected()) {
    ESP_LOGW(TAG, "Cannot request sync diagnostics: Not connected");
    return;
  }
  if (!gatt_ready_ || sync_char_handle_ == 0) {
    ESP_LOGW(TAG, "Cannot request sync diagnostics: Sync characteristic not ready");
    return;
  }
  if (!has_key_) {
    ESP_LOGW(TAG, "Cannot request sync diagnostics: AES key is not set");
    return;
  }

  ESP_LOGI(TAG, "Requesting Sync DoAi diagnostics for door/battery discovery");
  this->reset_sync_diagnostics_state_();

  uint8_t queue_req[1] = {0x00};
  this->write_sync_(queue_req, sizeof(queue_req));
  uint8_t status_req[1] = {0x01};
  this->write_sync_(status_req, sizeof(status_req));
  if (has_sync_msg_id_override_) {
    uint16_t msg_id = sync_msg_id_override_;
    has_sync_msg_id_override_ = false;
    ESP_LOGI(TAG, "Using cloud Sync DoAi msgId override: %u", msg_id);
    this->start_sync_doai_transfer_(msg_id, 0);
  }
}

void GainsboroughTrilockLock::request_sync_diagnostics_with_nonce(const std::string &nonce) {
  uint8_t parsed[12];
  if (!decode_nonce_string_(nonce, parsed)) {
    ESP_LOGW(TAG, "Invalid Sync DoAi nonce. Expected 12 bytes as base64 or hex");
    return;
  }
  memcpy(sync_nonce_override_, parsed, sizeof(sync_nonce_override_));
  has_sync_nonce_override_ = true;
  ESP_LOGI(TAG, "Loaded cloud Sync DoAi nonce: %s",
           format_hex_pretty(sync_nonce_override_, sizeof(sync_nonce_override_)).c_str());
  ESP_LOGW(TAG, "Nonce-only diagnostics cannot start a Sync DoAi transfer without a cloud msgId; use sync_set_cloud_nonce or sync_diagnostics_with_msg_id_nonce_bytes");
  this->request_sync_diagnostics();
}

void GainsboroughTrilockLock::request_sync_diagnostics_with_nonce_bytes(float b0, float b1, float b2, float b3,
                                                                        float b4, float b5, float b6, float b7,
                                                                        float b8, float b9, float b10, float b11) {
  float values[12] = {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11};
  for (int i = 0; i < 12; i++) {
    if (values[i] < 0 || values[i] > 255) {
      ESP_LOGW(TAG, "Invalid Sync DoAi nonce byte %d=%.0f", i, values[i]);
      return;
    }
    sync_nonce_override_[i] = (uint8_t) values[i];
  }
  has_sync_nonce_override_ = true;
  ESP_LOGI(TAG, "Loaded cloud Sync DoAi nonce bytes: %s",
           format_hex_pretty(sync_nonce_override_, sizeof(sync_nonce_override_)).c_str());
  ESP_LOGW(TAG, "Nonce-only diagnostics cannot start a Sync DoAi transfer without a cloud msgId; use sync_set_cloud_nonce or sync_diagnostics_with_msg_id_nonce_bytes");
  this->request_sync_diagnostics();
}

void GainsboroughTrilockLock::request_sync_diagnostics_with_msg_id_nonce_bytes(float msg_id, float b0, float b1,
                                                                               float b2, float b3, float b4,
                                                                               float b5, float b6, float b7,
                                                                               float b8, float b9, float b10,
                                                                               float b11) {
  if (msg_id <= 0 || msg_id > 65535) {
    ESP_LOGW(TAG, "Invalid Sync DoAi cloud msgId %.0f", msg_id);
    return;
  }
  sync_msg_id_override_ = (uint16_t) msg_id;
  has_sync_msg_id_override_ = true;
  uint8_t nonce[12];
  float values[12] = {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11};
  for (int i = 0; i < 12; i++) {
    if (values[i] < 0 || values[i] > 255) {
      ESP_LOGW(TAG, "Invalid Sync DoAi nonce byte %d=%.0f", i, values[i]);
      return;
    }
    nonce[i] = (uint8_t) values[i];
  }
  this->set_cloud_doai_nonce_((uint16_t) msg_id, nonce);
  has_sync_nonce_override_ = false;
  this->request_sync_diagnostics();
}

void GainsboroughTrilockLock::sync_set_cloud_nonce(float msg_id, float b0, float b1, float b2, float b3,
                                                   float b4, float b5, float b6, float b7, float b8,
                                                   float b9, float b10, float b11) {
  if (msg_id <= 0 || msg_id > 65535) {
    ESP_LOGW(TAG, "Invalid cloud Sync DoAi msgId %.0f", msg_id);
    return;
  }
  uint8_t nonce[12];
  float values[12] = {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11};
  for (int i = 0; i < 12; i++) {
    if (values[i] < 0 || values[i] > 255) {
      ESP_LOGW(TAG, "Invalid cloud Sync DoAi nonce byte %d=%.0f", i, values[i]);
      return;
    }
    nonce[i] = (uint8_t) values[i];
  }
  this->set_cloud_doai_nonce_((uint16_t) msg_id, nonce);
}

void GainsboroughTrilockLock::sync_cloud_refresh() {
  this->start_sync_cloud_refresh_(true);
}

void GainsboroughTrilockLock::start_sync_cloud_refresh_(bool manual) {
  if (this->parent() == nullptr || !this->parent()->connected()) {
    if (manual)
      ESP_LOGW(TAG, "Cannot run Sync cloud refresh: BLE is not connected");
    return;
  }
  if (!gatt_ready_ || sync_char_handle_ == 0) {
    if (manual)
      ESP_LOGW(TAG, "Cannot run Sync cloud refresh: Sync characteristic not ready");
    return;
  }
  if (sync_diag_active_ || sync_cloud_refresh_waiting_status_) {
    if (manual)
      ESP_LOGW(TAG, "Cannot run Sync cloud refresh: another sync is already active");
    return;
  }
  ESP_LOGI(TAG, "Starting Sync cloud refresh%s", manual ? "" : " (auto)");
  this->reset_sync_diagnostics_state_();
  sync_cloud_refresh_waiting_status_ = true;
  sync_cloud_upload_after_receive_ = false;

  uint8_t status_req[1] = {0x01};
  this->write_sync_(status_req, sizeof(status_req));
}

void GainsboroughTrilockLock::sync_upload_last_doai_payload() {
  if (sync_doai_msg_id_ == 0 || sync_doai_msg_received_ == 0) {
    ESP_LOGW(TAG, "No assembled Sync DoAi payload is available to upload");
    return;
  }
  size_t len = sync_doai_msg_len_ != 0 && sync_doai_msg_len_ <= sync_doai_msg_received_
                   ? sync_doai_msg_len_
                   : sync_doai_msg_received_;
  if (this->post_cloud_doai_message_(sync_doai_msg_id_, sync_doai_msg_, len)) {
    ESP_LOGI(TAG, "Polling cloud property state after manual GWASM DoAi upload");
    this->poll_cloud_lock_state_();
  }
}

void GainsboroughTrilockLock::sync_force_current_nonce_transfer(float target_msg_id) {
  if (target_msg_id <= 0 || target_msg_id > 65535) {
    ESP_LOGW(TAG, "Invalid forced Sync DoAi msgId %.0f", target_msg_id);
    return;
  }
  if (this->parent() == nullptr || !this->parent()->connected()) {
    ESP_LOGW(TAG, "Cannot force Sync DoAi transfer: BLE is not connected");
    return;
  }
  if (!gatt_ready_ || sync_char_handle_ == 0) {
    ESP_LOGW(TAG, "Cannot force Sync DoAi transfer: Sync characteristic not ready");
    return;
  }
  if (!current_doai_nonce_valid_) {
    ESP_LOGW(TAG, "Cannot force Sync DoAi transfer: no current cloud nonce is stored");
    return;
  }

  ESP_LOGW(TAG,
           "Forcing Sync DoAi transfer: targetMsgId=%u storedCloudNonceMsgId=%u nonce=%s; diagnostics only, no delete/ack",
           (uint16_t) target_msg_id, current_doai_msg_id_,
           format_hex_pretty(current_doai_nonce_, sizeof(current_doai_nonce_)).c_str());
  this->reset_sync_diagnostics_state_();
  sync_cloud_upload_after_receive_ = false;
  this->start_sync_doai_transfer_with_nonce_((uint16_t) target_msg_id, 0, current_doai_nonce_,
                                             "forcedCurrentCloudNonce");
}

bool GainsboroughTrilockLock::parse_nonce_bytes_(const float *values, bool allow_absent) {
  bool any_present = false;
  for (int i = 0; i < 12; i++) {
    if (values[i] >= 0)
      any_present = true;
  }
  if (!any_present && allow_absent)
    return false;
  for (int i = 0; i < 12; i++) {
    if (values[i] < 0 || values[i] > 255) {
      ESP_LOGW(TAG, "Invalid Sync DoAi nonce byte %d=%.0f", i, values[i]);
      return false;
    }
    sync_bootstrap_nonce_[i] = (uint8_t) values[i];
  }
  return true;
}

void GainsboroughTrilockLock::sync_bootstrap_diagnostics(float target_msg_id, float b0, float b1, float b2,
                                                         float b3, float b4, float b5, float b6, float b7,
                                                         float b8, float b9, float b10, float b11,
                                                         float retry_count, const std::string &bootstrap_variant) {
  sync_bootstrap_has_target_ = false;
  sync_bootstrap_target_msg_id_ = 0;
  if (target_msg_id > 0 && target_msg_id <= 65535) {
    sync_bootstrap_has_target_ = true;
    sync_bootstrap_target_msg_id_ = (uint16_t) target_msg_id;
  } else if (target_msg_id != 0) {
    ESP_LOGW(TAG, "Invalid bootstrap target_msg_id %.0f; use 0 for none", target_msg_id);
    return;
  }

  float values[12] = {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11};
  sync_bootstrap_has_nonce_ = this->parse_nonce_bytes_(values, true);
  sync_bootstrap_retry_count_ = retry_count <= 0 ? 1 : (uint8_t) std::min<float>(retry_count, 5);

  std::string variant = bootstrap_variant;
  std::transform(variant.begin(), variant.end(), variant.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (variant.empty() || variant == "auto") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::AUTO;
  } else if (variant == "a") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::A;
  } else if (variant == "b") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::B;
  } else if (variant == "c") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::C;
  } else if (variant == "d") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::D;
  } else if (variant == "e") {
    sync_bootstrap_requested_variant_ = SyncBootstrapVariant::E;
  } else {
    ESP_LOGW(TAG, "Unknown bootstrap_variant '%s'; use auto, A, B, C, D, or E", bootstrap_variant.c_str());
    return;
  }

  if (sync_bootstrap_requested_variant_ == SyncBootstrapVariant::E &&
      (!sync_bootstrap_has_target_ || !sync_bootstrap_has_nonce_)) {
    ESP_LOGW(TAG, "Bootstrap variant E requires target_msg_id and all 12 nonce bytes");
    return;
  }

  auto *base = this->parent() == nullptr ? nullptr : static_cast<esp32_ble_client::BLEClientBase *>(this->parent());
  if (base == nullptr) {
    ESP_LOGW(TAG, "Cannot run sync bootstrap diagnostics: BLE client missing");
    return;
  }

  sync_bootstrap_pending_ = true;
  sync_bootstrap_active_ = false;
  if (!base->connected()) {
    ESP_LOGI(TAG, "Sync bootstrap diagnostics requested; connecting BLE client first");
    base->connect();
    return;
  }
  if (!gatt_ready_ || sync_char_handle_ == 0) {
    ESP_LOGI(TAG, "Sync bootstrap diagnostics waiting for GATT/notifications");
    return;
  }
  this->start_phone_like_sync_bootstrap_();
}

}  // namespace gainsborough_trilock
}  // namespace esphome

#endif  // USE_ESP32
