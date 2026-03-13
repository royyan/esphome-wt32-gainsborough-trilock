import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import lock, ble_client, text_sensor
from esphome.const import CONF_ID

from . import GainsboroughTrilockLock

CONF_AES_KEY = "aes_key"
CONF_BLE_CLIENT_ID = "ble_client_id"
CONF_LOCK_STATUS_SENSOR = "lock_status_sensor"

CONFIG_SCHEMA = (
    lock.lock_schema(GainsboroughTrilockLock)
    .extend(
        {
            cv.Required(CONF_BLE_CLIENT_ID): cv.use_id(ble_client.BLEClient),
            cv.Required(CONF_AES_KEY): cv.string_strict,
            cv.Optional(CONF_LOCK_STATUS_SENSOR): text_sensor.text_sensor_schema(),
        }
    )
    .extend(cv.polling_component_schema("30s"))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await lock.register_lock(var, config)

    await ble_client.register_ble_node(var, config)

    cg.add(var.set_aes_key_string(config[CONF_AES_KEY]))

    if CONF_LOCK_STATUS_SENSOR in config:
        sens = await text_sensor.new_text_sensor(config[CONF_LOCK_STATUS_SENSOR])
        cg.add(var.set_lock_status_sensor(sens))
