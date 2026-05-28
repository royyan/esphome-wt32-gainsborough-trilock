# Sync Bootstrap Diagnostics

Use `sync_bootstrap_diagnostics` to make the ESP32-C3 try the phone-like sync bootstrap on the Trilock sync characteristic only. The diagnostic path does not send delete/consume acknowledgements and does not actuate the lock.

## Home Assistant Service Call

Service name:

```yaml
esphome.gainsborough_trilock_sync_bootstrap_diagnostics
```

ESPHome API service variables are required, so use these sentinel values when a field is not available:

- `target_msg_id: 0` means no target DoAi message id.
- `b0` through `b11: -1` means no nonce.
- `bootstrap_variant: auto` tries A, B, C, D, then E if a target id and nonce are provided.

Example with a cloud `doAiMsgId` and 12-byte `doAiNonce`:

```yaml
target_msg_id: 2
b0: 212
b1: 110
b2: 187
b3: 107
b4: 239
b5: 196
b6: 40
b7: 163
b8: 68
b9: 58
b10: 219
b11: 126
retry_count: 1
bootstrap_variant: auto
```

Example without cloud values:

```yaml
target_msg_id: 0
b0: -1
b1: -1
b2: -1
b3: -1
b4: -1
b5: -1
b6: -1
b7: -1
b8: -1
b9: -1
b10: -1
b11: -1
retry_count: 1
bootstrap_variant: auto
```

## Logs To Capture

Set the component option `sync_debug: true` and capture logs containing:

- `SYNC_DEBUG`
- `Bootstrap variant`
- `Sync queue summary`
- `Sync DoAi status`
- `Sync DoAi fragment`
- `Raw Sync DoAi message`
- `Sync diagnostics timeout`

Success indicators:

- `doAiCount > 0`
- `msgCount > 0`
- `msgLen > 0`
- a type `0x30` fragment arrives
- `Raw Sync DoAi message (...)` is printed as dot-separated hex

Failure indicators:

- `msgCount=0`
- `msgId=0`
- `msgLen=0`
- `Sync diagnostics timeout; received 0/0 bytes`

## Variants

- `A`: write `00`, wait 100 ms, write `01`, wait 1.5 s.
- `B`: confirm notifications are enabled first, then write `00`/`01`.
- `C`: write `00` and `01` with response.
- `D`: write `00` and `01` without response.
- `E`: write `10 <msgId little-endian> 00 00 <12-byte doAiNonce>`, then write `01`.

Variant E uses the provided nonce as the local transfer nonce. It still does not delete or acknowledge the message after diagnostics.
