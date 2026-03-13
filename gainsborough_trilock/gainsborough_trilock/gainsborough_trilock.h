/**
 * @file gainsborough_trilock.h
 * @brief ESPHome Gainsborough Trilock BLE lock component.
 */
#pragma once

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/lock/lock.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/component.h"

namespace esphome {
namespace gainsborough_trilock {

static const char *SERVICE_UUID = "00000001-4757-4100-6c78-67726f757000";
static const char *CMD_CHARACTERISTIC_UUID = "00000301-4757-4100-6c78-67726f757000";

enum LockState : uint8_t {
  STATE_UNKNOWN = 0,
  STATE_UNLOCKED = 1,
  STATE_LOCKED_PRIVACY = 2,
  STATE_LOCKED_DEADLOCK = 3,
  STATE_ERROR_FORCED = 4,
  STATE_ERROR_JAMMED = 5,
};

class GainsboroughTrilockLock : public lock::Lock,
                                  public PollingComponent,
                                  public ble_client::BLEClientNode {
 public:
  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;

  void control(const lock::LockCall &call) override;
  void open_latch() override;

  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                          esp_ble_gattc_cb_param_t *param) override;

  void set_aes_key_string(const std::string &key_b64);
  void set_lock_status_sensor(text_sensor::TextSensor *sensor) { lock_status_sensor_ = sensor; }
  void set_target_state(uint8_t state);

 protected:
  void on_connected_();
  void on_disconnected_();
  void publish_lock_state_(LockState state);

  void enqueue_state_(uint8_t state);
  void send_pending_if_ready_();
  void ensure_gatt_ready_();
  void handle_notify_();

  bool write_cmd_(const uint8_t *data, size_t len);
  bool begin_command_(uint8_t desired_state);
  void send_command_(uint8_t cmd);

  void handle_protocol_step_(const uint8_t *data, size_t len);
  void generate_payload_(uint16_t msg_id, const uint8_t *rx_nonce, uint8_t desired_state);
  void send_encoded_message_();
  void request_status_message_(const uint8_t *data, size_t len);
  void delete_message_(const uint8_t *data, size_t len);
  void decode_incoming_message_(const uint8_t *data, size_t len);

  text_sensor::TextSensor *lock_status_sensor_{nullptr};

  uint8_t aes_key_[32]{};
  bool has_key_{false};

  bool gatt_ready_{false};
  bool searching_{false};
  bool search_complete_{false};
  uint32_t last_gatt_attempt_{0};
  esp_gatt_if_t gattc_if_{0};
  uint16_t char_handle_{0};

  uint8_t pending_state_{0};
  uint8_t active_state_{0};
  uint32_t pending_since_{0};

  bool protocol_active_{false};
  bool status_pending_retry_{false};
  uint32_t last_notify_{0};
  static constexpr uint32_t PROTOCOL_TIMEOUT_MS = 12000;

  uint8_t notify_buf_[256]{};
  size_t notify_len_{0};
  bool notify_pending_{false};

  uint8_t encoded_msg_[192]{};
  uint8_t encoded_len_{0};
  uint8_t encoded_id_[2]{};
  uint8_t sender_nonce_[12]{};
};

}  // namespace gainsborough_trilock
}  // namespace esphome
