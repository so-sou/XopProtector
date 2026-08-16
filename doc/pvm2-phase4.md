# PVM2 Phase 4 — compat / perf / business SO / release

**Status:** done — device verified (`status=PASS`, `so=42`, `libdemo_biz.so` RC4 + sokeys).

## Goals
| Area | Deliverable |
|------|-------------|
| Performance | Cache parsed `Pvm2Image` on `CodeItem` (no re-parse per `interpret`) |
| Performance | Hoist boxed-primitive `FindClass` out of the per-arg loop |
| Business SO | Demo `libdemo_biz.so` + `--protect-so` in `protectDemo` |
| Release | `scripts/release-demo.ps1` + version `0.6.0` + CHANGELOG |

## Out of scope (later)
- jmethodID / field ID global caches
- ~~float/double / monitor-* / invoke-polymorphic~~ → float/double/monitor in `doc/pvm2-phase5.md`; polymorphic still later
- CI matrix / x86 ABIs
- Full commercial-class feature parity (industry SO filters, budgets, True-VMP)

## Verify
```powershell
.\scripts\release-demo.ps1 -Serial 111410D096402300012
# expect logcat: status=PASS and so=42; optional "decrypted business SO .text: libdemo_biz.so"
```

## Notes
- Prefer `System.loadLibrary("demo_biz")` after shell bootstrap (demo loads in `Business` clinit from Activity — keys already present).
- Packer skips SOs with `.text` relocs; `libdemo_biz` is deliberately reloc-safe.
