# PVM2 Phase 5 — float / double / monitor ISA (v4)

**Status:** implemented — verify with `protectDemo` + device smoke.

## Goals

| Area | Deliverable |
|------|-------------|
| Float/double ALU | `add/sub/mul/div/rem` (+ `/2addr`) |
| Long ALU | full binop set including div/rem (+ `/2addr`) |
| Int div/rem | previously missing `div-int` / `rem-int` (+ lit8/lit16) |
| Conversions | `int/long/float/double` unops + `neg-*` / `not-*` |
| Compare | `cmpl/cmpg-float`, `cmpl/cmpg-double`, `cmp-long` |
| Sync | `monitor-enter` / `monitor-exit` |
| Const | `const-wide` / `const-wide/high16` |
| Image | version **4**, morph `OP_COUNT=50` |

## Out of scope (later)

- `invoke-polymorphic` / `invoke-custom`
- Nested VMP→VMP recurse optimization
- Resource / network / LLVM phases (see `doc/roadmap-hardening.md`)

## Image format **v4**

Same layout as v3; morph table length is **50** (ops `NOP`…`MONITOR_EXIT`).
Runtime still accepts v1–v3 (`op_count=40`).

## Demo probes

- `Business.floatProbe` / `doubleProbe` / `floatCmpProbe` / `syncProbe`
- Expect logcat: `status=PASS` including `f=` / `d=` / `fcmp=` / `sync=`

## Verify

```powershell
.\gradlew.bat protectDemo
.\scripts\release-demo.ps1 -Serial <device>
# expect: TRUE_VMP ...floatProbe / syncProbe (no skip), status=PASS
```
