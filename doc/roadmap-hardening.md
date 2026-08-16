# Hardening roadmap (post third-party gap review)

**Status:** Phase 0 scaffolding done; Phase 1 (PVM2 ISA v4) implemented — verify on device.

## Priority order

| Phase | Focus | Gate |
|-------|--------|------|
| 0 | Baseline flags + docs + VMP skip telemetry | **done** |
| 1A | PVM2 float/double ALU + cmp + conversions | **done** (`floatProbe`/`doubleProbe` compile) |
| 1B | PVM2 `monitor-enter` / `monitor-exit` | **done** (`syncProbe` compile) |
| 2 | Assets encrypt + optional res name obfuscation | **2A + 2B done** (`--encrypt-assets` / `--enable-res-protect`) |
| 3 | Cert pinning + proxy detect (opt-in) | **done** (`NetGuard`, `--detect-proxy`) |
| 4 | Stronger string obfuscation (build-time) | **done** (rolling XOR + encode tool) |
| 5 | Structured threat export / light crash reason | **done** (`pid`/`sdk`, `crash_reason.txt`, CrashGuard) |
| 6 | Multi-channel APK (signing-block channel) | **done** (`--channel` / `ChannelReader`) |
| 7 | LLVM CFF/BCF (sensitive TUs only) | **done** (source CFF default; LLVM opt-in) |
| 8 | Flutter/RN (separate product line) | POC only when requested |
| — | Industry profile Step A | **done** (`--profile industry`, see `doc/industry-profile.md`) |
| — | Auto True-VMP CLI/Desktop contract | **Phase 0–3 done** (packer 0.6.25 app-scoped Industry; Desktop Advanced incl. assets/res/channel/NetGuard) |

## Reserved ProtectOptions (Phase 0)

- `enableResProtect` — Phase 2B (**wired**; `--enable-res-protect`)
- `enableNetGuard` — Phase 3 (default off)
- `enableChannelMark` — Phase 6 (**wired**; set when `--channel` / `--channels` used)

CLI wiring lands with each phase; flags must not change packer defaults until implemented.

## PVM2 version note

Phase 1 bumps image **version to 4** and morph `OP_COUNT` to **50**.
Runtime still accepts v1–v3 images (op_count 40 morph tables).
