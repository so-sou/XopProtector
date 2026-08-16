# Phase 4 — Rolling string obfuscation

**Status:** done.

## Change

| Item | Detail |
|------|--------|
| Algorithm | `c[i] = p[i] ^ (0x5A ^ ((i * 0x1B) & 0xFF))` |
| Native | `OBSC_ROLL` / `unobsc` in `protector_macro.h` |
| Java | `StrEnc.roll` / `d` / `e` / `toCLiteral` / `toJavaBytes` |
| Tool | `scripts/obsc_encode.py` (+ `obsc_strings.txt` batch) |
| Migrated | `risk.cpp` detectors, shell `StrEnc` literals |

Not cryptographic. Optional LLVM IR string encryption is still out of scope; Phase 7 covers CFF/BCF (see `doc/llvm-obfuscation.md`).

```bash
python scripts/obsc_encode.py "frida"
python scripts/obsc_encode.py --java "protector/config.json"
```
