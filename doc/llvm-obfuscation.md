# Phase 7 — Native CFF / BCF (sensitive TUs)

**Status:** done (stock-NDK source layer default; LLVM passes opt-in).

## Two layers

| Layer | Default | What |
|-------|---------|------|
| **Source CFF/BCF** | **ON** | `common/obfuscate.h` — opaque predicates, bogus branches, flattened dispatch, MBA XOR |
| **LLVM passes** | **OFF** | O-LLVM / Hikari `-mllvm -fla/-bcf/-sub` on sensitive TUs only |

Stacks with existing `.bitcode` RC4 (`PROTECTOR_ENCRYPT`).

## Sensitive TUs (LLVM path)

Always candidates (when `-Pprotector.llvmObf=true`):

- `risk/risk.cpp`, `risk/so_guard.cpp`
- `crypto/section_decrypt.cpp`, `aes.cpp`, `dex_asset.cpp`, `assets_crypt.cpp`
- `vm/vm_codec.cpp`

Optional (hot path — off by default):

- `-Pprotector.llvmObfVm=true` → also `pvm2_interp.cpp` / `pvm2_format.cpp`

## Gradle / CMake

```bash
# Default release: source-level obfuscation only
.\gradlew.bat :native:assembleRelease

# Disable source macros
.\gradlew.bat :native:assembleRelease -Pprotector.srcObf=false

# Enable LLVM passes (requires OLLVM/Hikari clang as NDK toolchain)
.\scripts\probe-llvm-obf.ps1
.\gradlew.bat :native:assembleRelease -Pprotector.llvmObf=true

# Hikari-style flags (comma-separated → CMake ';')
.\gradlew.bat :native:assembleRelease -Pprotector.llvmObf=true `
  -Pprotector.llvmObfFlags="-mllvm,-enable-cffobf,-mllvm,-enable-bcfobf,-mllvm,-enable-subobf"
```

CMake knobs: `PROTECTOR_SRC_OBF`, `PROTECTOR_LLVM_OBF`, `PROTECTOR_LLVM_OBF_VM`, `PROTECTOR_LLVM_OBF_FLAGS`.

## Applied source sites

- `handle_risk` — control-flow flattening
- `detect_frida` — bogus control flow
- `unpad_unknown_key` — CFF + MBA XOR

## Notes

- Stock Android NDK clang **rejects** `-mllvm -fla`; LLVM layer needs a custom toolchain.
- Do not enable `llvmObfVm` without measuring PVM2 startup / interpret cost.
- CI budget: watch `libprotector.so` size and demo smoke after turning LLVM ON.
