# Phase 7 LLVM / native obfuscation helpers.
# Applied only to sensitive translation units (risk / crypto / vm_codec).

option(PROTECTOR_LLVM_OBF
        "Apply OLLVM/Hikari -mllvm passes to sensitive TUs (requires custom clang)"
        OFF)
option(PROTECTOR_LLVM_OBF_VM
        "Also obfuscate pvm2_interp / pvm2_format (larger + slower)"
        OFF)
option(PROTECTOR_SRC_OBF
        "Enable portable source-level CFF/BCF macros (stock NDK)"
        ON)

# Semicolon-separated clang flags. Defaults match classic O-LLVM.
# Hikari example:
#   -mllvm;-enable-cffobf;-mllvm;-enable-bcfobf;-mllvm;-enable-subobf
set(PROTECTOR_LLVM_OBF_FLAGS
        "-mllvm;-fla;-mllvm;-bcf;-mllvm;-bcf_prob=40;-mllvm;-sub"
        CACHE STRING "Clang -mllvm flags for sensitive TUs")

set(PROTECTOR_SENSITIVE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/risk/risk.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/risk/so_guard.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/section_decrypt.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/aes.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/dex_asset.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/assets_crypt.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vm/vm_codec.cpp
)

if (PROTECTOR_LLVM_OBF_VM)
    list(APPEND PROTECTOR_SENSITIVE_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/vm/pvm2_interp.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/vm/pvm2_format.cpp)
endif ()

function(protector_apply_llvm_obf target)
    if (NOT PROTECTOR_LLVM_OBF)
        message(STATUS "PROTECTOR_LLVM_OBF=OFF (stock NDK; source-level SRC_OBF still available)")
        return()
    endif ()

    message(STATUS "PROTECTOR_LLVM_OBF=ON flags=${PROTECTOR_LLVM_OBF_FLAGS}")
    if (PROTECTOR_LLVM_OBF_VM)
        message(STATUS "  + PROTECTOR_LLVM_OBF_VM (pvm2_interp/format)")
    endif ()

    # CACHE STRING uses ';' — expand to a CMake list and append extras.
    set(_flags ${PROTECTOR_LLVM_OBF_FLAGS})
    list(APPEND _flags -fno-inline-functions)
    set_source_files_properties(${PROTECTOR_SENSITIVE_SOURCES}
            PROPERTIES COMPILE_OPTIONS "${_flags}")
endfunction()
