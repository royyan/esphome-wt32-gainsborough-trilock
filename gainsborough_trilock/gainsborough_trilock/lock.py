import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import lock, ble_client, text_sensor, sensor, binary_sensor, esp32
from esphome.const import CONF_ID, DEVICE_CLASS_BATTERY, UNIT_PERCENT

AUTO_LOAD = ["json"]

from . import GainsboroughTrilockLock

CONF_AES_KEY = "aes_key"
CONF_BLE_CLIENT_ID = "ble_client_id"
CONF_LOCK_STATUS_SENSOR = "lock_status_sensor"
CONF_BATTERY_LEVEL = "battery_level"
CONF_BATTERY_LOW = "battery_low"
CONF_DOOR_STATUS = "door_status"
CONF_CLOUD = "cloud"
CONF_USERNAME = "username"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_PROPERTY_ID = "property_id"
CONF_BLE_MAC = "ble_mac"
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_ENDPOINT = "endpoint"
CONF_CLOUD_UPDATE_INTERVAL = "update_interval"
CONF_SYNC_DEBUG = "sync_debug"

DEFAULT_CLOUD_ENDPOINT = "https://api-s.gainsboroughhardware.cloud/v0"

CONFIG_SCHEMA = (
    lock.lock_schema(GainsboroughTrilockLock)
    .extend(
        {
            cv.Required(CONF_BLE_CLIENT_ID): cv.use_id(ble_client.BLEClient),
            cv.Required(CONF_AES_KEY): cv.string_strict,
            cv.Optional(CONF_LOCK_STATUS_SENSOR): text_sensor.text_sensor_schema(),
            cv.Optional(CONF_BATTERY_LEVEL): sensor.sensor_schema(
                unit_of_measurement=UNIT_PERCENT,
                accuracy_decimals=0,
                device_class=DEVICE_CLASS_BATTERY,
            ),
            cv.Optional(CONF_BATTERY_LOW): binary_sensor.binary_sensor_schema(
                device_class="battery"
            ),
            cv.Optional(CONF_DOOR_STATUS): binary_sensor.binary_sensor_schema(
                device_class="door",
            ),
            cv.Optional(CONF_CLOUD): cv.Schema(
                {
                    cv.Optional(CONF_USERNAME, default=""): cv.string_strict,
                    cv.Required(CONF_REFRESH_TOKEN): cv.string_strict,
                    cv.Required(CONF_PROPERTY_ID): cv.string_strict,
                    cv.Required(CONF_BLE_MAC): cv.string_strict,
                    cv.Required(CONF_CLIENT_ID): cv.string_strict,
                    cv.Required(CONF_CLIENT_SECRET): cv.string_strict,
                    cv.Optional(CONF_ENDPOINT, default=DEFAULT_CLOUD_ENDPOINT): cv.string_strict,
                    cv.Optional(CONF_CLOUD_UPDATE_INTERVAL, default="5min"): cv.update_interval,
                }
            ),
            cv.Optional(CONF_SYNC_DEBUG, default=False): cv.boolean,
        }
    )
    .extend(cv.polling_component_schema("30s"))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await lock.register_lock(var, config)

    await ble_client.register_ble_node(var, config)
    esp32.include_builtin_idf_component("esp_http_client")
    esp32.include_builtin_idf_component("json")
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE", True)

    cg.add(var.set_aes_key_string(config[CONF_AES_KEY]))
    cg.add(var.set_sync_debug(config[CONF_SYNC_DEBUG]))

    if CONF_LOCK_STATUS_SENSOR in config:
        sens = await text_sensor.new_text_sensor(config[CONF_LOCK_STATUS_SENSOR])
        cg.add(var.set_lock_status_sensor(sens))

    if CONF_BATTERY_LEVEL in config:
        sens = await sensor.new_sensor(config[CONF_BATTERY_LEVEL])
        cg.add(var.set_battery_level_sensor(sens))

    if CONF_BATTERY_LOW in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_BATTERY_LOW])
        cg.add(var.set_battery_low_binary_sensor(sens))

    if CONF_DOOR_STATUS in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_DOOR_STATUS])
        cg.add(var.set_door_status_binary_sensor(sens))

    if CONF_CLOUD in config:
        cloud = config[CONF_CLOUD]
        cg.add(
            var.set_cloud_config(
                cloud[CONF_USERNAME],
                cloud[CONF_REFRESH_TOKEN],
                cloud[CONF_PROPERTY_ID],
                cloud[CONF_BLE_MAC],
                cloud[CONF_CLIENT_ID],
                cloud[CONF_CLIENT_SECRET],
                cloud[CONF_ENDPOINT],
                cloud[CONF_CLOUD_UPDATE_INTERVAL].total_milliseconds,
            )
        )
