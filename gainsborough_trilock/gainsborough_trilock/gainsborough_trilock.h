/**
 * @file gainsborough_trilock.h
 * @brief ESPHome Gainsborough Trilock BLE lock component.
 */
#pragma once

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/lock/lock.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/core/component.h"
#include <string>

namespace esphome {
namespace gainsborough_trilock {

static const char *SERVICE_UUID = "00000001-4757-4100-6c78-67726f757000";
static const char *CMD_CHARACTERISTIC_UUID = "00000301-4757-4100-6c78-67726f757000";
static const char *SYNC_CHARACTERISTIC_UUID = "00000201-4757-4100-6c78-67726f757000";

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
  void request_status();
  void request_sync_diagnostics();
  void request_sync_diagnostics_with_nonce(const std::string &nonce);
  void request_sync_diagnostics_with_nonce_bytes(float b0, float b1, float b2, float b3, float b4, float b5,
                                                float b6, float b7, float b8, float b9, float b10, float b11);
  void request_sync_diagnostics_with_msg_id_nonce_bytes(float msg_id, float b0, float b1, float b2, float b3,
                                                       float b4, float b5, float b6, float b7, float b8,
                                                       float b9, float b10, float b11);
  void sync_set_cloud_nonce(float msg_id, float b0, float b1, float b2, float b3, float b4, float b5, float b6,
                            float b7, float b8, float b9, float b10, float b11);
  void sync_cloud_refresh();
  void sync_upload_last_doai_payload();
  void sync_force_current_nonce_transfer(float target_msg_id);
  void sync_bootstrap_diagnostics(float target_msg_id, float b0, float b1, float b2, float b3, float b4, float b5,
                                  float b6, float b7, float b8, float b9, float b10, float b11,
                                  float retry_count, const std::string &bootstrap_variant);

  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                          esp_ble_gattc_cb_param_t *param) override;

  void set_aes_key_string(const std::string &key_b64);
  void set_sync_debug(bool sync_debug) { sync_debug_ = sync_debug; }
  void set_lock_status_sensor(text_sensor::TextSensor *sensor) { lock_status_sensor_ = sensor; }
  void set_battery_level_sensor(sensor::Sensor *sensor) { battery_level_sensor_ = sensor; }
  void set_battery_low_binary_sensor(binary_sensor::BinarySensor *sensor) { battery_low_binary_sensor_ = sensor; }
  void set_door_status_binary_sensor(binary_sensor::BinarySensor *sensor) { door_status_binary_sensor_ = sensor; }
  void set_target_state(uint8_t state);
  void set_cloud_config(const std::string &username, const std::string &refresh_token,
                        const std::string &property_id, const std::string &ble_mac,
                        const std::string &client_id, const std::string &client_secret,
                        const std::string &endpoint, uint32_t update_interval_ms);

 protected:
  void on_connected_();
  void on_disconnected_();
  void publish_lock_state_(LockState state);
  void publish_battery_info_(bool low, int pct);
  void publish_door_status_(bool closed);

  void enqueue_state_(uint8_t state);
  void send_pending_if_ready_();
  void ensure_gatt_ready_();
  void handle_notify_();

  bool write_cmd_(const uint8_t *data, size_t len);
  bool write_sync_(const uint8_t *data, size_t len);
  bool write_sync_(const uint8_t *data, size_t len, esp_gatt_write_type_t write_type);
  bool write_channel_(uint16_t handle, const uint8_t *data, size_t len, esp_gatt_write_type_t write_type,
                      const char *channel);
  bool begin_command_(uint8_t desired_state);
  void send_command_(uint8_t cmd);

  void handle_protocol_step_(const uint8_t *data, size_t len);
  void generate_payload_(uint16_t msg_id, const uint8_t *rx_nonce, uint8_t desired_state);
  void send_encoded_message_();
  void request_status_message_(const uint8_t *data, size_t len);
  void delete_message_(const uint8_t *data, size_t len);
  void decode_incoming_message_(const uint8_t *data, size_t len);
  void handle_sync_notify_(const uint8_t *data, size_t len);
  void start_sync_doai_transfer_(uint16_t msg_id, uint16_t msg_len);
  void start_sync_doai_transfer_with_nonce_(uint16_t msg_id, uint16_t msg_len, const uint8_t *nonce,
                                            const char *nonce_source);
  void append_sync_fragment_(uint16_t offset, const uint8_t *data, size_t len);
  void decode_sync_doai_message_();
  void scan_sync_payload_for_telemetry_(const uint8_t *data, size_t len);
  void start_phone_like_sync_bootstrap_();
  void process_phone_like_sync_bootstrap_();
  void finish_phone_like_sync_bootstrap_(bool success);
  void reset_sync_diagnostics_state_();
  void set_cloud_doai_nonce_(uint16_t msg_id, const uint8_t *bytes);
  void clear_cloud_doai_nonce_();
  bool sync_bootstrap_variant_done_();
  bool advance_sync_bootstrap_variant_();
  const char *sync_bootstrap_variant_name_() const;
  bool parse_nonce_bytes_(const float *values, bool allow_absent);
  void log_sync_debug_packet_(const char *dir, uint16_t handle, const char *uuid, const char *mode,
                              const uint8_t *data, size_t len);
  void poll_cloud_if_due_();
  void run_auto_sync_cloud_refresh_if_due_();
  void start_sync_cloud_refresh_(bool manual);
  bool ensure_cloud_session_();
  bool refresh_cloud_session_();
  bool fetch_cloud_gwasm_status_();
  bool post_cloud_doai_message_(uint16_t msg_id, const uint8_t *payload, size_t len);
  bool poll_cloud_lock_state_();
  void run_auto_status_request_if_due_();
  void start_status_request_(bool manual);

  text_sensor::TextSensor *lock_status_sensor_{nullptr};
  sensor::Sensor *battery_level_sensor_{nullptr};
  binary_sensor::BinarySensor *battery_low_binary_sensor_{nullptr};
  binary_sensor::BinarySensor *door_status_binary_sensor_{nullptr};

  uint8_t aes_key_[32]{};
  bool has_key_{false};
  bool sync_debug_{false};

  bool gatt_ready_{false};
  bool searching_{false};
  bool search_complete_{false};
  uint32_t last_gatt_attempt_{0};
  esp_gatt_if_t gattc_if_{0};
  uint16_t char_handle_{0};
  uint16_t sync_char_handle_{0};

  uint8_t pending_state_{0};
  uint8_t active_state_{0};
  uint32_t pending_since_{0};

  bool protocol_active_{false};
  bool is_status_query_{false};
  bool status_pending_retry_{false};
  uint32_t last_notify_{0};
  uint32_t last_auto_status_request_{0};
  static constexpr uint32_t PROTOCOL_TIMEOUT_MS = 12000;
  static constexpr uint32_t AUTO_STATUS_REQUEST_INTERVAL_MS = 60000;

  alignas(16) uint8_t notify_buf_[256]{};
  size_t notify_len_{0};
  bool notify_pending_{false};

  alignas(16) uint8_t sync_buf_[256]{};
  size_t sync_len_{0};
  bool sync_pending_{false};

  bool sync_diag_active_{false};
  bool sync_diag_no_delete_{true};
  uint16_t sync_doai_msg_id_{0};
  uint16_t sync_doai_msg_len_{0};
  uint32_t sync_diag_started_{0};
  alignas(16) uint8_t sync_doai_msg_[768]{};
  size_t sync_doai_msg_received_{0};
  uint8_t sync_nonce_override_[12]{};
  bool has_sync_nonce_override_{false};
  uint16_t sync_msg_id_override_{0};
  bool has_sync_msg_id_override_{false};
  uint16_t current_doai_msg_id_{0};
  uint8_t current_doai_nonce_[12]{};
  bool current_doai_nonce_valid_{false};
  uint8_t sync_last_summary_count_{0};
  uint16_t sync_last_summary_doai_msg_id_{0};
  uint16_t sync_last_summary_diao_msg_id_{0};
  uint8_t sync_last_status_msg_count_{0};
  uint16_t sync_last_status_transfer_id_{0};
  uint16_t sync_last_status_msg_id_{0};
  uint16_t sync_last_status_msg_len_{0};

  enum class SyncBootstrapVariant : uint8_t {
    AUTO = 0,
    A,
    B,
    C,
    D,
    E,
  };
  bool sync_bootstrap_pending_{false};
  bool sync_bootstrap_active_{false};
  SyncBootstrapVariant sync_bootstrap_requested_variant_{SyncBootstrapVariant::AUTO};
  SyncBootstrapVariant sync_bootstrap_current_variant_{SyncBootstrapVariant::A};
  uint8_t sync_bootstrap_step_{0};
  uint8_t sync_bootstrap_retry_count_{1};
  uint8_t sync_bootstrap_attempt_{0};
  uint32_t sync_bootstrap_next_action_{0};
  uint32_t sync_bootstrap_wait_until_{0};
  bool sync_bootstrap_has_target_{false};
  uint16_t sync_bootstrap_target_msg_id_{0};
  bool sync_bootstrap_has_nonce_{false};
  uint8_t sync_bootstrap_nonce_[12]{};

  bool cloud_enabled_{false};
  bool cloud_polling_{false};
  std::string cloud_username_;
  std::string cloud_refresh_token_;
  std::string cloud_property_id_;
  std::string cloud_ble_mac_;
  std::string cloud_client_id_;
  std::string cloud_client_secret_;
  std::string cloud_endpoint_;
  std::string cloud_id_token_;
  uint32_t cloud_update_interval_ms_{300000};
  uint32_t last_cloud_poll_{0};
  uint32_t cloud_token_expires_at_{0};
  uint32_t last_sync_cloud_refresh_{0};
  static constexpr uint32_t SYNC_CLOUD_REFRESH_INTERVAL_MS = 60000;
  bool sync_cloud_upload_after_receive_{false};
  bool sync_cloud_refresh_waiting_status_{false};

  uint8_t encoded_msg_[192]{};
  uint8_t encoded_len_{0};
  uint8_t encoded_id_[2]{};
  uint8_t sender_nonce_[12]{};
};

}  // namespace gainsborough_trilock
}  // namespace esphome
