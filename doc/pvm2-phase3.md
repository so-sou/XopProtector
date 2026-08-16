# PVM2 Phase 3 — morph + multi-ISA + RASP gate

**Status:** done — device verified (`status=PASS`, `isa_id=2` morph on SPRING2_PRO).

## Goals
| Area | Deliverable |
|------|-------------|
| Opcode morphing | Per-APK permutation of opcode bytes 0..39 embedded in each v3 image |
| Multi-ISA | `isa_id` ∈ {0,1,2} selects packer profile + native dispatch entry (`pvm2_run_a/b/c`) |
| RASP / SO bind | `interpret()` refuses when `environment_degraded`; light `so_guard_check` on prepare + periodic gate |

## Image format **v3** (extends v2)
```
PVM2
u16 version = 3
u16 reg_count          # includes trailing scratch (same as v2)
u16 ins_size
u16 handler_count
u16 code_size
u8  ret_kind
u8  isa_id             # 0..2 (was reserved)
u16 str_count
# strings / method / field / type pools (same as v2)
u8  op_count           # = 40
u8  forward[op_count]  # forward[canonical] = wire opcode in code[]
# handlers
# code[]               # first byte of each insn is *wire* opcode
```
v1/v2 remain readable (identity demorph).

## Runtime
1. `prepare_true_vmp_images()` — AES-GCM decrypt; `so_guard_check()` before exposing images.
2. `interpret()` — `risk::vmp_allowed()`; parse; demorph wire→canonical; dispatch via `pvm2_run_{a|b|c}` by `isa_id`.

## Out of scope → Phase 4
- Full float/double path, monitor-*, polymorphic invoke
- Per-method unique maps (APK-level map is enough here)
- ~~Commercial release pipeline / perf tuning~~ → see `doc/pvm2-phase4.md`
