#include "crypto/section_decrypt.h"
#include "common/protector_macro.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/runtime_state.h"
#include "crypto/aes.h"
#include "crypto/rc4.h"
#include "hook/hooks.h"
#include "risk/risk.h"
#include "risk/so_guard.h"
#include "so/business_so.h"

#include <android/log.h>
#include <android/api-level.h>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>

// Must be unmangled so packer can find them via dynamic symbol table.
extern "C" {
KEEP_SYMBOL PROTECTOR_DATA_SECTION uint8_t PROTECTOR_UNKNOWN_DATA[16] = {0};
KEEP_SYMBOL PROTECTOR_DATA_SECTION uint8_t PROTECTOR_INSN_KEY[16] = {0};
KEEP_SYMBOL PROTECTOR_DATA_SECTION uint8_t PROTECTOR_DEX_KEY[16] = {0};
KEEP_SYMBOL PROTECTOR_DATA_SECTION uint8_t PROTECTOR_ASSETS_KEY[16] = {0};
KEEP_SYMBOL PROTECTOR_DATA_SECTION uint8_t PROTECTOR_HMAC_KEY[32] = {0};
}

namespace protector {

static int page_mprotect(void* start, void* end, int prot) {
    uintptr_t start_addr = PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(start));
    uintptr_t end_addr =
            PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(end) - 1) + get_cache_page_size();
    size_t size = end_addr - start_addr;
    if (mprotect(reinterpret_cast<void*>(start_addr), size, prot) != 0) {
        PLOGW("mprotect fail err=%s", strerror(errno));
        return -1;
    }
    return 0;
}

static void decrypt_section(const char* section_name, int temp_prot, int target_prot) {
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void*>(&decrypt_section), &info) == 0
        || info.dli_fbase == nullptr) {
        PLOGE("dladdr failed for section decrypt");
        abort();
    }

    std::string so_path;
    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            so_path.assign(info.dli_fname);
        } else {
            so_path = find_so_path(info.dli_fname);
        }
    }
    if (so_path.empty()) {
        so_path = find_so_path("libprotector.so");
    }
    if (so_path.empty()) {
        PLOGE("cannot resolve protector.so path");
        abort();
    }

    Elf_Shdr shdr{};
    get_elf_section(&shdr, so_path.c_str(), section_name);
    if (shdr.sh_size == 0) {
        PLOGE("section %s missing", section_name);
        abort();
    }

    if ((shdr.sh_flags & SHF_ALLOC) == 0) {
        PLOGE("section %s is not SHF_ALLOC; cannot decrypt in-memory", section_name);
        abort();
    }

    auto* target = reinterpret_cast<uint8_t*>(info.dli_fbase) + shdr.sh_addr;
    if (page_mprotect(target, target + shdr.sh_size, temp_prot) != 0) {
        abort();
    }

    // Size-preserving RC4 for executable .bitcode (ELF section length is fixed).
    // code.bin method bodies use AES-GCM separately.
    auto* bitcode = static_cast<uint8_t*>(malloc(shdr.sh_size));
    if (!bitcode) {
        abort();
    }
    struct rc4_state dec_state {};
    rc4_init(&dec_state, PROTECTOR_UNKNOWN_DATA, 16);
    rc4_crypt(&dec_state, target, bitcode, static_cast<int>(shdr.sh_size));
    memcpy(target, bitcode, shdr.sh_size);
    memset(bitcode, 0, shdr.sh_size);
    free(bitcode);
    __builtin___clear_cache(reinterpret_cast<char*>(target),
                            reinterpret_cast<char*>(target + shdr.sh_size));

    if (page_mprotect(target, target + shdr.sh_size, target_prot) != 0) {
        abort();
    }
    PLOGI("decrypted section %s size=%u", section_name, static_cast<unsigned>(shdr.sh_size));
}

void decrypt_bitcode() {
    decrypt_section(SECTION_NAME_BITCODE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    PROT_READ | PROT_EXEC);
}

/**
 * Bootstrap pad for PROTECTOR_UNKNOWN_DATA. Must live outside .bitcode because
 * it is needed to RC4-decrypt .bitcode itself. Split + XOR so a single
 * 16-byte literal is not sitting next to the symbol in .data.
 */
static void unpad_unknown_key() {
    // clang-format off
    const uint8_t a[8] = {0x3b, 0x7c, 0x19, 0x5e, 0xa2, 0xdf, 0x48, 0x31};
    const uint8_t b[8] = {0x6c, 0x85, 0xea, 0x27, 0x54, 0x9b, 0x0f, 0xd6};
    // clang-format on
    for (int i = 0; i < 8; i++) {
        PROTECTOR_UNKNOWN_DATA[i] ^= a[i];
        PROTECTOR_UNKNOWN_DATA[i + 8] ^= b[i];
    }
}

static void wipe_unknown_key() {
    memset(PROTECTOR_UNKNOWN_DATA, 0, 16);
}

static void seed_rng() {
    unsigned seed = 0;
    FILE* ur = fopen("/dev/urandom", "rb");
    if (ur != nullptr) {
        if (fread(&seed, 1, sizeof(seed), ur) != sizeof(seed)) {
            seed = 0;
        }
        fclose(ur);
    }
    if (seed == 0) {
        seed = static_cast<unsigned>(time(nullptr))
                ^ static_cast<unsigned>(getpid())
                ^ static_cast<unsigned>(reinterpret_cast<uintptr_t>(&seed));
    }
    srand(seed);
}

void init_protector() {
    seed_rng();
    unpad_unknown_key();
#ifdef DECRYPT_BITCODE
    decrypt_bitcode();
#endif
    // RC4 key no longer needed after .bitcode is plaintext in memory.
    wipe_unknown_key();
    protector::risk::so_guard_init();
#ifndef NDEBUG
    if (!crypto::aes_self_test()) {
        __android_log_print(ANDROID_LOG_ERROR, "protector", "AES self-test failed");
        abort();
    }
#endif
    runtime_state().sdk_level = android_get_device_api_level();
    // Early bytehook + dlopen hooks so business SOs loaded before initApp
    // are queued / decrypted once sokeys arrive (see --protect-so).
    protector::hook::ensure_bytehook();
    protector::so::install_business_so_hooks();
    // Defer ART hooks to init_app — constructor-time Dobby ELF parse can SEGV on
    // some Android 14 / APEX libart layouts before the process is fully up.
    protector::risk::risk_checker().start();
    PLOGI("init_protector done (ART hooks deferred; dlopen hooks early)");
}

} // namespace protector

INIT_ARRAY_SECTION void protector_early_init() {
    protector::init_protector();
}
