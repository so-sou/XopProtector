#include "risk/so_guard.h"
#include "risk/risk.h"
#include "common/crc32.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "common/runtime_state.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

namespace protector::risk {

static std::atomic_bool g_so_guard_ready{false};
static uint32_t g_bitcode_crc = 0;
static uint8_t* g_bitcode_addr = nullptr;
static size_t g_bitcode_size = 0;
static uintptr_t g_so_base = 0;

static bool resolve_self(Dl_info* info, std::string* so_path) {
    if (dladdr(reinterpret_cast<const void*>(&so_guard_init), info) == 0
        || info->dli_fbase == nullptr) {
        return false;
    }
    g_so_base = reinterpret_cast<uintptr_t>(info->dli_fbase);
    if (info->dli_fname != nullptr && info->dli_fname[0] == '/') {
        so_path->assign(info->dli_fname);
    } else if (info->dli_fname != nullptr) {
        *so_path = find_so_path(info->dli_fname);
    }
    if (so_path->empty()) {
        *so_path = find_so_path("libprotector.so");
    }
    return !so_path->empty();
}

PROTECTOR_ENCRYPT void so_guard_init() {
    Dl_info info{};
    std::string so_path;
    if (!resolve_self(&info, &so_path)) {
        PLOGW("so_guard_init: cannot resolve self");
        return;
    }

    Elf_Shdr shdr{};
    get_elf_section(&shdr, so_path.c_str(), SECTION_NAME_BITCODE);
    if (shdr.sh_size == 0 || (shdr.sh_flags & SHF_ALLOC) == 0) {
        PLOGW("so_guard_init: .bitcode missing");
        return;
    }

    g_bitcode_addr = reinterpret_cast<uint8_t*>(info.dli_fbase) + shdr.sh_addr;
    g_bitcode_size = static_cast<size_t>(shdr.sh_size);
    g_bitcode_crc = crc32_update(0, g_bitcode_addr, g_bitcode_size);

    (void)madvise(g_bitcode_addr, g_bitcode_size, MADV_DONTDUMP);

    FILE* st = fopen("/proc/self/status", "r");
    if (st) {
        char line[256];
        int tracer = -1;
        while (fgets(line, sizeof(line), st)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                sscanf(line + 10, "%d", &tracer);
                break;
            }
        }
        fclose(st);
        if (tracer == 0) {
            prctl(PR_SET_DUMPABLE, 0);
        }
    }

    g_so_guard_ready.store(true, std::memory_order_release);
    PLOGI("so_guard ready crc=%08x size=%zu", g_bitcode_crc, g_bitcode_size);
}

static bool maps_rwx_on_self() {
    if (g_so_base == 0) return false;
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool hit = false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        bool wx = (strchr(perms, 'w') != nullptr && strchr(perms, 'x') != nullptr);
        if (!wx) continue;
        if (strstr(line, "libprotector") != nullptr) {
            hit = true;
            break;
        }
        if (start >= g_so_base && start < g_so_base + 16ull * 1024 * 1024
            && end > g_so_base && strstr(line, ".so") != nullptr) {
            // Anonymous RWX abutting our SO often means inline trampoline.
            if (strstr(line, "/") == nullptr) {
                hit = true;
                break;
            }
        }
    }
    fclose(fp);
    return hit;
}

static bool maps_has_dump_tools() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "memdump")
            || strstr(line, "libGameGuardian")
            || strstr(line, "frida-gadget")
            || strstr(line, "frida-agent")
            || strstr(line, "libdump.so")) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

PROTECTOR_ENCRYPT void so_guard_check() {
    if (!g_so_guard_ready.load(std::memory_order_acquire)) return;
    int flags = runtime_state().config.risk_flags.load(std::memory_order_relaxed);
    if ((flags & FLAG_DISABLE_SO_INTEGRITY) != 0) return;

    if (g_bitcode_addr != nullptr && g_bitcode_size > 0) {
        uint32_t now = crc32_update(0, g_bitcode_addr, g_bitcode_size);
        if (now != g_bitcode_crc) {
            PLOGW("so_guard bitcode crc mismatch expect=%08x got=%08x", g_bitcode_crc, now);
            handle_risk("so_bitcode_crc", CrashKind::SigIll);
            return;
        }
    }

    if (maps_rwx_on_self()) {
        PLOGW("so_guard: RWX mapping on libprotector");
        handle_risk("so_rwx", CrashKind::SigIll);
        return;
    }

    if (maps_has_dump_tools()) {
        PLOGW("so_guard: dump/hook tooling in maps");
        handle_risk("so_dump_tool", CrashKind::SigSegv);
    }
}

} // namespace protector::risk
