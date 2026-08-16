# PVM2 Phase 2 — opcode expansion

**Status:** done — device verified (`status=PASS` on SPRING2_PRO / Android 11).

## Scope (this phase)
| Area | Support |
|------|---------|
| Invoke | `invoke-static` / `virtual` / `direct` / `interface` / `super` (+ `/range`) via JNI |
| Fields | `sget`/`sput`/`iget`/`iput` (I/J/Z/L + array types) |
| Arrays | `new-array`, `filled-new-array`(/range), `array-length`, `aget`/`aput` (int/object) |
| Objects | `new-instance`, `check-cast`, `instance-of`, `const-class` |
| Exceptions | `throw`, `move-exception`, try/catch table (typed + catch-all) |
| Misc | `lit16` binops, `neg-int`, instance methods (trampoline boxes `this`) |

## Out of scope → Phase 3+
- ~~Multi-interpreter / opcode morphing~~ → see `doc/pvm2-phase3.md`
- `monitor-*`, `invoke-polymorphic/custom`
- Nested VMP→VMP recurse optimization
- Float/double full path

## Image format **v2**
```
PVM2
u16 version = 2
...
# Notes
- v2 images allocate **one trailing scratch register** (`reg_count = dalvik_regs + 1`).
  Params still occupy the Dalvik param window: `[reg_count - 1 - ins_size, reg_count - 2]`.
- `binop/lit*` lowers via scratch so `mul-int/lit8 v0, v0, #2` is not clobbered.
u16 reg_count
u16 ins_size
u16 handler_count
u16 code_size
u8  ret_kind
u8  reserved
u16 str_count
# strings (utf8)
u16 method_count
# method_count × u16 str_idx   // "LOwner;->name:(I)Ljava/lang/String;"
u16 field_count
# field_count × u16 str_idx    // "LOwner;->name:I"
u16 type_count
# type_count × u16 str_idx     // "Ljava/lang/String;" / "[I"
# handler_count × {u16 start, u16 end, u16 handler_pc, u16 catch_type_idx|0xFFFF}
# code[code_size]
```
v1 images remain readable (no method/field pools; `handler_count` was 0).

## New opcodes (16+)
See `Pvm2Opcodes.java` / `pvm2_format.h`.
