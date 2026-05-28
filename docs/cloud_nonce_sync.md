# Cloud Nonce Sync

The sync BLE transport already works. For Sync DoAi decrypt, the transfer request must use the official cloud `doAiNonce` for the exact `doAiMsgId`.

## Fetch `doAiNonce`

Use the Gainsborough cloud status tooling already used for diagnostics and read:

- `doAiMsgId`
- `doAiNonce`

Do not probe cloud status with arbitrary message ids. Use the current values returned by the cloud status response.

## Inject Nonce

Call this ESPHome API service before requesting the Sync DoAi transfer:

```yaml
service: esphome.gainsborough_trilock_sync_set_cloud_nonce
data:
  msg_id: 30
  b0: 75
  b1: 84
  b2: 35
  b3: 159
  b4: 211
  b5: 245
  b6: 194
  b7: 218
  b8: 28
  b9: 91
  b10: 178
  b11: 95
```

Then run the existing sync diagnostics for that message, or call the combined service:

```yaml
service: esphome.gainsborough_trilock_sync_diagnostics_with_msg_id_nonce_bytes
data:
  msg_id: 30
  b0: 75
  b1: 84
  b2: 35
  b3: 159
  b4: 211
  b5: 245
  b6: 194
  b7: 218
  b8: 28
  b9: 91
  b10: 178
  b11: 95
```

## Expected Logs

Successful nonce injection:

```text
Stored cloud Sync DoAi nonce: msgId=30 nonce=4B.54.23.9F.D3.F5.C2.DA.1C.5B.B2.5F
```

Expected transfer request:

```text
SYNC_DEBUG ... TX ... len=17 type=0x10 msgId=30 ... data=10.1E.00.00.00.4B.54.23.9F.D3.F5.C2.DA.1C.5B.B2.5F
```

Expected decrypt inputs:

```text
Sync DoAi decrypt inputs: msgId=30 cloudDoAiNonce=4B.54.23.9F.D3.F5.C2.DA.1C.5B.B2.5F rxNonce=<payload bytes 6..17> iv=<cloud nonce + rxNonce>
```

## Troubleshooting

If the transfer is refused:

```text
Refusing Sync DoAi transfer for msgId=30: cloud doAiNonce is not set
```

or:

```text
Refusing Sync DoAi transfer for msgId=30: cloud doAiNonce is for msgId=<other>
```

Inject the nonce again with the matching `doAiMsgId`.

If decrypt still fails after the expected `10.1E...4B.54...` TX packet appears, next debugging targets are:

- confirm the cloud `doAiNonce` is current and was not advanced by another cloud call
- compare payload header bytes `0..5` and rxNonce bytes `6..17`
- verify the AES key matches the lock
- capture the full `Raw Sync DoAi message` and `Sync DoAi decrypt inputs` logs
