# Phase 6 — Multi-channel APK (signing-block)

**Status:** done.

## Mechanism

Channel data is stored as an ID-value pair inside the **APK Signing Block** (between ZIP contents and Central Directory), using Walle-compatible ID `0x71777777` and JSON payload:

```json
{"channel":"huawei"}
```

Stamping happens **after** V2/V3 signing and does **not** invalidate the signature.

## Packer CLI

| Flag / command | Effect |
|----------------|--------|
| `--channel <name>` | Stamp primary signed output (requires `--keystore`) |
| `--channels <file>` | Emit sibling `out-<channel>.apk` for each line |
| `channel get <apk>` | Print channel (empty if unmarked) |
| `channel put <apk> <name> [-o out]` | Stamp any already-signed APK |
| `channel batch <apk> <file> [-o-dir dir]` | Batch stamp |

`channels.txt` format: one name per line; `#` comments and blanks ignored.

## Runtime

```java
String ch = ChannelReader.getChannel(context); // or getChannel(apkFile)
```

## Demo

`protectDemo` signs with the Android debug keystore and stamps `--channel demo`.
`MainActivity` asserts `ChannelReader.getChannel(this) == "demo"`.
