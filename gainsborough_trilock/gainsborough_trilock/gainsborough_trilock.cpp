/*
 * This file contains code originally derived from:
 * https://github.com/mcchas/ble-freestyle-client
 * Copyright (c) 2024 mcchas
 * * Modifications and additions:
 * Copyright (c) 2026 Royyan
 * * Licensed under the MIT License. 
 * See the LICENSE file in the project root for full license information.
 */

#include "gainsborough_trilock.h"
#include "esphome/components/esp32_ble/ble_uuid.h"
#include "esphome/components/esp32_ble_client/ble_client_base.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "mbedtls/base64.h"
#include "aes/esp_aes_gcm.h"
#include "esp_gap_ble_api.h"
#include "esp_gatt_defs.h"
#include "esp_random.h"
#include <array>
#include <cstring>

#ifdef USE_ESP32

#define GCM_ENCRYPT 1
#define GCM_DECRYPT 0

namespace esphome {
namespace gainsborough_trilock {

static const char *const TAG = "gainsborough_trilock";

namespace espbt = esphome::esp32_ble_tracker;

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

static bool decode_confirm(const uint8_t *data, size_t len, uint8_t *desired_state, uint8_t *reported_state) {
  size_t i = 0;
  while (i < len) {
    uint8_t tag = data[i++];
    uint8_t field = tag >> 3;
    uint8_t wire = tag & 7;
    if (wire == 0) {
      uint64_t val = 0;
      int shift = 0;
      do {
        if (i >= len)
          return false;
        val |= (uint64_t)(data[i] & 0x7F) << shift;
        shift += 7;
      } while (data[i++] & 0x80);
      if (field == 1 && desired_state != nullptr)
        *desired_state = (uint8_t) val;
      if (field == 2 && reported_state != nullptr)
        *reported_state = (uint8_t) val;
    } else if (wire == 2) {
      uint64_t slen = 0;
      int shift = 0;
      do {
        if (i >= len)
          return false;
        slen |= (uint64_t)(data[i] & 0x7F) << shift;
        shift += 7;
      } while (data[i++] & 0x80);
      if (i + slen > len)
        return false;
      if (field == 2 && slen >= 2) {
        decode_confirm(data + i, (size_t) slen, desired_state, reported_state);
      }
      i += (size_t) slen;
    } else {
      return false;
    }
  }
  return true;
}

static int encode_message(const uint8_t *key, const uint8_t *input, size_t input_len,
                          uint8_t *out_arr, const uint8_t *rx_nonce, uint16_t msg_id) {
  uint8_t iv2[12];
  esp_fill_random(iv2, 12);
  uint8_t final_iv[24];
  memcpy(final_iv, rx_nonce, 12);
  memcpy(final_iv + 12, iv2, 12);

  size_t pad_len = 16 - (input_len & 15);
  uint8_t padded[128];
  if (input_len + pad_len > sizeof(padded))
    return -1;
  memcpy(padded, input, input_len);
  esp_fill_random(padded + input_len, pad_len);
  size_t padded_len = input_len + pad_len;

  uint8_t header[6] = {0x00, 0x00, (uint8_t)(msg_id >> 8), (uint8_t)(msg_id & 0xFF),
                       (uint8_t)(input_len & 0xFF), 0x00};

  uint8_t cipher[128];
  uint8_t tag[16];
  esp_gcm_context aes;
  esp_aes_gcm_init(&aes);
  esp_aes_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (esp_aes_gcm_starts(&aes, GCM_ENCRYPT, final_iv, sizeof(final_iv)) != 0) {
    esp_aes_gcm_free(&aes);
    return -1;
  }
  if (esp_aes_gcm_update_ad(&aes, header, sizeof(header)) != 0) {
    esp_aes_gcm_free(&aes);
    return -1;
  }
  size_t cipher_len = 0;
  if (esp_aes_gcm_update(&aes, padded, padded_len, cipher, sizeof(cipher), &cipher_len) != 0) {
    esp_aes_gcm_free(&aes);
    return -1;
  }
  size_t finish_len = 0;
  if (esp_aes_gcm_finish(&aes, nullptr, 0, &finish_len, tag, sizeof(tag)) != 0) {
    esp_aes_gcm_free(&aes);
    return -1;
  }
  esp_aes_gcm_free(&aes);

  size_t total_len = 6 + 12 + padded_len + 16;
  memcpy(out_arr, header, 6);
  memcpy(out_arr + 6, iv2, 12);
  memcpy(out_arr + 18, cipher, padded_len);
  memcpy(out_arr + 18 + padded_len, tag, 16);
  return (int) total_len;
}

static bool decode_message(const uint8_t *key, const uint8_t *input, size_t input_len,
                           uint8_t *output, const uint8_t *iv1, const uint8_t *iv2) {
  uint8_t final_iv[24];
  memcpy(final_iv, iv1, 12);
  memcpy(final_iv + 12, iv2, 12);
  uint8_t tag[16];
  esp_gcm_context aes;
  esp_aes_gcm_init(&aes);
  esp_aes_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (esp_aes_gcm_starts(&aes, GCM_DECRYPT, final_iv, sizeof(final_iv)) != 0) {
    esp_aes_gcm_free(&aes);
    return false;
  }
  size_t out_len = 0;
  if (esp_aes_gcm_update(&aes, input, input_len, output, input_len + 16, &out_len) != 0) {
    esp_aes_gcm_free(&aes);
    return false;
  }
  size_t finish_len = 0;
  if (esp_aes_gcm_finish(&aes, nullptr, 0, &finish_len, tag, sizeof(tag)) != 0) {
    esp_aes_gcm_free(&aes);
    return false;
  }
  esp_aes_gcm_free(&aes);
  return true;
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
  if (this->parent() == nullptr || !this->parent()->connected())
    return;

  this->ensure_gatt_ready_();

  if (notify_pending_) {
    notify_pending_ = false;
    this->handle_notify_();
  }

  if (protocol_active_ && (millis() - last_notify_) > PROTOCOL_TIMEOUT_MS) {
    ESP_LOGW(TAG, "Protocol timeout");
    protocol_active_ = false;
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
        // Rely on base ble_client to set node_state after tracking services
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
      size_t len = std::min((size_t) param->notify.value_len, sizeof(notify_buf_));
      memcpy(notify_buf_, param->notify.value, len);
      notify_len_ = len;
      notify_pending_ = true;
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
  auto char_uuid = esp32_ble::ESPBTUUID::from_raw(CMD_CHARACTERISTIC_UUID);

  auto *chr = base->get_characteristic(service_uuid, char_uuid);
  if (chr == nullptr) {
    ESP_LOGW(TAG, "CMD characteristic not found (Service might not be fully parsed yet)");
    return;
  }

  this->char_handle_ = chr->handle;
  ESP_LOGI(TAG, "Registering for notifications on CMD char handle 0x%04x", this->char_handle_);
  esp_err_t ret = esp_ble_gattc_register_for_notify(
      this->gattc_if_, base->get_remote_bda(), this->char_handle_);
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "register_for_notify failed: %d", ret);
  }
}

void GainsboroughTrilockLock::handle_notify_() {
  if (notify_len_ == 0)
    return;
  this->handle_protocol_step_(notify_buf_, notify_len_);
  notify_len_ = 0;
}

bool GainsboroughTrilockLock::write_cmd_(const uint8_t *data, size_t len) {
  auto *base = static_cast<esp32_ble_client::BLEClientBase *>(this->parent());
  if (base == nullptr || !base->connected() || this->char_handle_ == 0)
    return false;

  ESP_LOGD(TAG, "BLE write len=%u", (unsigned) len);
  esp_err_t ret = esp_ble_gattc_write_char(
      this->gattc_if_,
      base->get_conn_id(),
      this->char_handle_,
      len,
      const_cast<uint8_t *>(data),
      ESP_GATT_WRITE_TYPE_RSP,
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
    this->generate_payload_(msg_id, nonce, active_state_);
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
      return;
    }
    protocol_active_ = false;
    active_state_ = 0;
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
  uint8_t dec[160];
  if (decode_message(aes_key_, data + 23, enc_len, dec, sender_nonce_, rx_nonce)) {
    uint8_t desired = 0, reported = 0;
    decode_confirm(dec, rx_len, &desired, &reported);
    ESP_LOGD(TAG, "Protocol RX: desired=%u reported=%u", desired, reported);
    
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

}  // namespace gainsborough_trilock
}  // namespace esphome

#endif  // USE_ESP32
