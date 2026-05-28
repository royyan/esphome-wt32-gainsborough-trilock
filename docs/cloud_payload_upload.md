# Cloud DoAi payload upload

This diagnostic path follows the Android APK GWASM sync flow:

1. Fetch the current Sync DoAi status:
   `GET /gwasm/{propertyId}/{bleMac}/status`
2. Decode `doAiNonce` and store it against `doAiMsgId`.
3. Request the BLE Sync DoAi transfer using:
   `10 <msgId little-endian> 00 00 <12-byte doAiNonce>`
4. Assemble type `0x30` Sync DoAi fragments into the raw encrypted DoAi payload.
5. Upload the raw payload to cloud:
   `POST /gwasm/{propertyId}/{bleMac}/message`
6. Poll `GET /properties/{propertyId}` for cloud-updated `doorClosed`,
   `batteryLow`, and `batteryPercent`.

## Home Assistant service

Call:

```yaml
service: esphome.gainsborough_trilock_esp32c3_sync_cloud_refresh
data: {}
```

This service uses the configured ESPHome cloud refresh token to obtain an ID
token. Do not paste short-lived ID tokens into YAML.

## Expected logs

Successful nonce fetch:

```text
GWASM status: doAiMsgId=41 doAiNonce=8C.79.7B.C1.5A.30.2E.02.B1.57.6B.ED
Stored cloud Sync DoAi nonce: msgId=41 nonce=8C.79.7B.C1.5A.30.2E.02.B1.57.6B.ED
```

Successful BLE request:

```text
Starting Sync DoAi transfer: msgId=41 expectedLen=0 cloudDoAiNonce=8C.79.7B.C1.5A.30.2E.02.B1.57.6B.ED
```

Successful upload and cloud readback:

```text
Raw Sync DoAi message (... bytes): ...
Posting Sync DoAi payload to GWASM cloud: msgId=41 rawLen=...
GWASM DoAi POST succeeded: HTTP 200
Cloud telemetry: doorClosed=... batteryLow=... batteryPercent=...
```

## Manual re-upload

If a payload has already been assembled and you only want to retry the cloud
POST:

```yaml
service: esphome.gainsborough_trilock_esp32c3_sync_upload_last_doai_payload
data: {}
```

This does not acknowledge/delete the BLE message and does not actuate the lock.
