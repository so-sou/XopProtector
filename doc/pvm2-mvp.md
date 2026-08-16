# PVM2 MVP (Phase 1) — True VMP

## Goal
Selected methods **never** restore Dalvik into DEX. Packer emits a JNI trampoline
in the hollowed DEX; runtime interprets a custom **PVM2** image from `code.bin`.

## Flags (`code.bin` v3 `flags`)
| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `FLAG_VMP` | Legacy PVM1 (decode → write Dalvik) |
| 1 | `FLAG_TRUE_VMP` | PVM2 interpreter (no DEX write) |

## Packer
```
--true-vmp-prefix Lcom/foo/   # repeatable; admission-checked methods only
```
Unsupported opcodes / prototypes fall back to normal hollowing (or `--vmp-prefix` PVM1).

## PVM2 image
```
magic[4] = 'P''V''M''2'
u16 version = 1
u16 reg_count
u16 ins_size
u16 reserved
u16 code_size          # bytes following string pool
u8  ret_kind           # 0=V 1=I 2=J 3=L 4=Z
u8  reserved2
u16 str_count
# str_count × (u16 len + utf8 bytes)
# code_size bytes of instructions
```

## Entry
`Lcom/yqsh/protector/shell/VmBridge;->interpret(II[Ljava/lang/Object;)Ljava/lang/Object;`
