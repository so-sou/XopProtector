# Phase 2A — Assets encryption (`--encrypt-assets`)

**Status:** implemented — verify with `protectDemo` (flag on by default for demo).

## Behavior

| Item | Detail |
|------|--------|
| Opt-in | `--encrypt-assets` (default **OFF** for general packer; demo enables it) |
| Scope | All files under `assets/**` except `assets/protector/**` |
| Skip | `assets/protector/**`, `assets/dexopt/**`, media needing `openFd` |
| Cipher | `PAS1 \|\| AES-GCM(nonce\|\|ct\|\|tag)` |
| Storage | `assets/protector/aenc/<relpath>` (original deleted) |
| Index | `assets/protector/assets.map` |
| Key | `PROTECTOR_ASSETS_KEY` in `libprotector.so` (XOR-padded) |
| Config | `"encrypt_assets":true` inside HMAC payload |

## App API

```java
String s = ProtectorAssets.readString(context, "secret.txt");
InputStream in = ProtectorAssets.open(context, "config/app.json");
```

Do **not** use `AssetManager.open("secret.txt")` after encryption — path moved under `protector/aenc/`.

## Out of scope (later)

- `resources.arsc` encryption (Phase 2C — deferred; high risk)
- Transparent `AssetManager` hook

Res path shortening is **Phase 2B** — see `doc/res-protect.md`.

## Verify

```powershell
.\gradlew.bat protectDemo
# expect: assets encrypt: 0/N (0%) … 100%; Assets encrypt: files=…
#         encrypt_assets=true, Wrote PROTECTOR_ASSETS_KEY
```
