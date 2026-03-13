"""Gainsborough Trilock BLE lock - ESPHome external component."""

import esphome.codegen as cg
from esphome.components import lock, ble_client

CODEOWNERS = ["@royyan"]
DEPENDENCIES = ["ble_client", "esp32"]

gainsborough_trilock_ns = cg.esphome_ns.namespace("gainsborough_trilock")

GainsboroughTrilockLock = gainsborough_trilock_ns.class_(
    "GainsboroughTrilockLock",
    lock.Lock,
    cg.PollingComponent,
    ble_client.BLEClientNode,
)

GainsboroughTrilockLock.add_header("gainsborough_trilock.h")
GainsboroughTrilockLock.add_include('#include "gainsborough_trilock.h"')
