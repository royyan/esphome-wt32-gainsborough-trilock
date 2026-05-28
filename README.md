# ESPHome Gainsborough Freestyle Trilock BLE Bridge

This project provides an ESPHome component to bridge Gainsborough Freestyle Trilock BLE locks to Home Assistant.

This project is based on the reverse-engineering work done by mcchas:
[ble-freestyle-client](https://github.com/mcchas/ble-freestyle-client).

## Hardware Support

- Original target: WT32-ETH01 (Ethernet + BLE)
- Current target: ESP32-C3 (WiFi + BLE)

## Files

- `gainsborough_trilock_esp32c3.yaml`: ESPHome configuration for ESP32-C3.
- `gainsborough_trilock/gainsborough_trilock/`: custom ESPHome component.
- `secrets_template.yaml`: example secrets file. Copy this to `secrets.yaml`.
- `tools/freestyle-gwasm-status.js`: optional local helper for inspecting cloud property/status data.

## Setup

1. Copy `secrets_template.yaml` to `secrets.yaml`.
2. Fill in WiFi, ESPHome API/OTA, lock, and Freestyle cloud values.
3. Compile and flash:

   ```bash
   esphome run gainsborough_trilock_esp32c3.yaml
   ```

`secrets.yaml` is intentionally ignored by git. Do not commit real lock keys,
refresh tokens, property IDs, BLE MAC addresses, or app client secrets.

Required secrets:

```yaml
trilock_aes_key: "<base64 32-byte BLE lock key>"
trilock_ble_mac: "aa:bb:cc:dd:ee:ff"
api_encryption_key: "<ESPHome API key>"
ota_password: "<ESPHome OTA password>"

freestyle_refresh_token: "<Cognito refresh token>"
freestyle_property_id: "<Freestyle property UUID>"
freestyle_cloud_ble_mac: "<lock BLE MAC as known by cloud>"
freestyle_client_id: "<Cognito app client id>"
freestyle_client_secret: "<Cognito app client secret>"

wifi_ssid: "<ssid>"
wifi_password: "<password>"
```

## How It Works

The lock exposes two useful BLE channels:

- Command channel: normal encrypted lock/status protocol.
- Sync channel: DoAi/DiAo sync transport used by the official phone app and
  Gainsborough cloud service.

The ESPHome component keeps the normal BLE lock protocol in place for direct
status requests, then also emulates the important part of the official phone
sync flow so cloud telemetry can be refreshed without the phone being connected.

### Periodic Refresh

Every minute, when BLE is connected and no other lock/sync command is active,
the component runs:

1. A normal lock status request over the command channel.
2. A cloud sync refresh over the sync channel.

Both paths are guarded so they skip themselves if another BLE command, sync
transfer, or bootstrap operation is already in progress.

### Sync Cloud Refresh Flow

The cloud refresh flow mirrors the successful phone/app behavior:

1. ESPHome writes `01` to the sync characteristic to ask the lock for current
   DoAi sync status.
2. The lock returns a type `0x01` status notification containing:
   - `msgCount`
   - BLE-side `msgId`
   - expected message length when a transfer is active
3. ESPHome refreshes its Cognito ID token if needed using the configured
   `freestyle_refresh_token`, `freestyle_client_id`, and
   `freestyle_client_secret`.
4. ESPHome calls:

   ```text
   GET /v0/gwasm/{propertyId}/{bleMac}/status
   ```

   The cloud response includes `doAiMsgId` and `doAiNonce`.
5. ESPHome starts a BLE DoAi transfer using the cloud nonce:

   ```text
   10 <msgId little-endian> 00 00 <12-byte doAiNonce>
   ```

6. The lock replies with type `0x30` fragments. ESPHome assembles the encrypted
   raw DoAi payload.
7. ESPHome uploads the assembled payload to:

   ```text
   POST /v0/gwasm/{propertyId}/{bleMac}/message
   {
     "doAiMsgId": <msgId>,
     "doAiMsg": "<base64 raw payload>"
   }
   ```

8. The cloud validates/decrypts/processes the payload, then ESPHome polls:

   ```text
   GET /v0/properties/{propertyId}
   ```

   The component publishes the resulting door and battery telemetry to Home
   Assistant.

The component does not delete or acknowledge sync messages as part of this
diagnostic/cloud-refresh path.

## Obtaining Freestyle Cloud Values

These values come from the official Freestyle/Gainsborough mobile app protocol.
Use only your own account and lock.

### Property ID and Cloud BLE MAC

The property ID and lock BLE MAC are returned by the authenticated cloud
property response used by the phone app. The helper script can print them after
logging in with your Freestyle account. It is self-contained and only requires
Node.js 18 or newer.

The helper does not read `secrets.yaml`; it generates values for it. The
Freestyle app Cognito user pool, client id, client secret, and API endpoint are
included as defaults because they are app-level constants from the Android app.
You can override them with environment variables or a local ignored helper
config if the app changes:

```bash
cp tools/freestyle-app-config.template.json tools/freestyle-app-config.json
```

You can put `username` and `password` in `tools/freestyle-app-config.json`, or
pass them as environment variables:

```bash
FREESTYLE_USERNAME="you@example.com" \
FREESTYLE_PASSWORD="your-password" \
node tools/freestyle-gwasm-status.js
```

If you already have a refresh token, you can avoid sending the password:

```bash
FREESTYLE_REFRESH_TOKEN="<refresh token>" \
node tools/freestyle-gwasm-status.js
```

Environment variables override `tools/freestyle-app-config.json` values when
both are present.

Username/password login uses the vendored reference implementation in
`tools/freestyle-client` first. This is the same client used during reverse
engineering. If that copy is missing, the helper checks `../external` and then
falls back to its standalone Cognito `USER_SRP_AUTH` implementation. If
authentication fails, rerun with auth debugging:

```bash
FREESTYLE_DEBUG_AUTH=1 node tools/freestyle-gwasm-status.js
```

Refresh-token login uses `REFRESH_TOKEN_AUTH`.

To force the standalone implementation even when the reference client exists:

```bash
FREESTYLE_STANDALONE_AUTH=1 node tools/freestyle-gwasm-status.js
```

The script prints:

- `propertyId`: use as `freestyle_property_id`
- `bleMac`: use as `freestyle_cloud_ble_mac`
- current cloud door/battery fields
- current GWASM `doAiMsgId` and `doAiNonce`
- a copy/paste `secrets.yaml` block for the ESPHome cloud fields

The cloud BLE MAC is often formatted without colons. The component normalizes
both forms.

### Refresh Token

The refresh token is issued by AWS Cognito after the official app login flow.
There are three practical ways to obtain it:

- Use a local Freestyle client/helper that performs the same Cognito login and
  exposes the session refresh token.
- Inspect an authenticated session from the official Android app on your own
  device.
- Capture your own app login traffic with a trusted local TLS debugging setup.

The included `tools/freestyle-gwasm-status.js` prints the refresh token in the
final `secrets.yaml` block when Cognito returns one. Username/password login
usually returns a refresh token. Refresh-token auth usually reuses the existing
refresh token instead of returning a new one.

For one-line output compatibility, you can also print `refreshToken=...`:

```bash
FREESTYLE_USERNAME="you@example.com" \
FREESTYLE_PASSWORD="your-password" \
FREESTYLE_PRINT_REFRESH_TOKEN=1 \
node tools/freestyle-gwasm-status.js
```

Store the printed value only in `secrets.yaml` as
`freestyle_refresh_token`.

The final `secrets.yaml` block prints `freestyle_client_secret` because the
script is generating the ESPHome secret values. To redact it in terminal output:

```bash
FREESTYLE_REDACT_CLIENT_SECRET=1 node tools/freestyle-gwasm-status.js
```

### Client ID and Client Secret

The mobile app uses a Cognito app client ID and client secret when refreshing
tokens. They can be identified from the official Android APK by decompiling the
app and searching for the Cognito configuration, auth constants, or
`InitiateAuth` request construction.

Typical workflow:

1. Decompile the APK with a Java/Kotlin decompiler such as jadx.
2. Search for strings such as `ClientId`, `SECRET_HASH`,
   `REFRESH_TOKEN_AUTH`, `cognito-idp.ap-southeast-2.amazonaws.com`, or the
   Gainsborough API endpoint.
3. Put the discovered values in `secrets.yaml` as:
   - `freestyle_client_id`
   - `freestyle_client_secret`

These values are not personal account credentials, but they are still not
committed here because they are vendor app credentials.

## ESP32-C3 WiFi + BLE Coexistence Notes

The ESP32-C3 is a single-core RISC-V chip with a shared 2.4 GHz radio for both
WiFi and BLE. This requires careful configuration.

### Framework

Uses `esp-idf` instead of Arduino for lower RAM usage and better radio
time-sharing.

### BLE Scan Parameters

The ESP32-C3 config uses a reduced scan window so WiFi is not starved while BLE
is active.

### WiFi Power Save

- `power_save_mode: LIGHT` allows the radio to yield time to BLE between WiFi beacon intervals.

### Boot Sequence

WiFi connects before BLE activity starts, reducing radio contention at boot.

### Coexistence SDK Options

- `CONFIG_ESP32_WIFI_SW_COEXIST_ENABLE` enables the coexistence scheduler.
- `CONFIG_SW_COEXIST_PREFERENCE_BALANCE` balances priority between WiFi and BLE.

### AES Encryption

The component uses the standard `mbedtls/gcm.h` API for authenticated AES-GCM
operations used by the direct BLE command protocol.

## Publishing Safety

Before publishing:

1. Confirm `secrets.yaml` is ignored and not tracked:

   ```bash
   git status --ignored --short
   ```

2. Search tracked files for accidental secrets:

   ```bash
   git grep -n -E "refresh_token|IdToken|Authorization|property_id|client_secret"
   ```

3. Do not publish old git history that previously contained real tokens or
   IDs. Start from a clean sanitized repository or rewrite history before
   pushing publicly.
