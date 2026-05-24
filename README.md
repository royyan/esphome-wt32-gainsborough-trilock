# ESPHome WT32-ETH01 (Gainsborough Trilock)

## Credits & Attribution
This project is a fork/adaptation based heavily on the excellent work done by [mcchas](https://github.com/mcchas) in the [ble-freestyle-client](https://github.com/mcchas/ble-freestyle-client) repository.

This folder is a clean ESPHome config targeting the WT32-ETH01 board
with Ethernet (LAN8720), BLE client, OTA, and Home Assistant API.

## Quick start
1. Copy `secrets_template.yaml` to `secrets.yaml` and fill in values.
2. Flash once over UART, then use OTA updates.

Example:
  esphome run esphome/gainsborough_trilock_wt32.yaml

If you need a static IP, uncomment the `manual_ip` section in the YAML.
