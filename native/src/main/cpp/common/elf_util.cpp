#include "common/elf_util.h"
#include "common/log.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>

namespace protector {

std::string find_so_path(const char* so_name) {
    if (so_name == nullptr || so_name[0] == 0) return {};
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", getpid());
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return {};

#ifdef __LP64__
    const char* fmt = "%*llx-%*llx %*s %*llx %*s %*s %255s";
#else
    const char* fmt = "%*x-%*x %*s %*x %*s %*s %255s";
#endif

    // Prefer protector so_plain mirror (plaintext) over /data/app packaged ciphertext.
    std::string plain_hit;
    std::string any_hit;
    char line[512];
    int lines = 0;
    while (fgets(line, sizeof(line), fp) != nullptr && lines++ < 10000) {
        char path[256] = {0};
        if (sscanf(line, fmt, path) != 1) continue;
        const char* base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (strcmp(base, so_name) != 0) continue;
        if (strstr(path, "/so_plain/") != nullptr) {
            plain_hit = path;
            break;
        }
        if (any_hit.empty()) {
            any_hit = path;
        }
    }
    fclose(fp);
    return !plain_hit.empty() ? plain_hit : any_hit;
}

void get_elf_section(Elf_Shdr* target, const char* elf_path, const char* sh_name) {
    if (target == nullptr || elf_path == nullptr || sh_name == nullptr) return;
    memset(target, 0, sizeof(Elf_Shdr));

    FILE* fp = fopen(elf_path, "rb");
    if (!fp) {
        PLOGW("cannot open elf: %s", elf_path);
        return;
    }

    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_shoff == 0
        || ehdr.e_shentsize != sizeof(Elf_Shdr)
        || ehdr.e_shnum == 0) {
        fclose(fp);
        return;
    }

    if (fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET) != 0) {
        fclose(fp);
        return;
    }
    std::vector<Elf_Shdr> shdrs(ehdr.e_shnum);
    if (fread(shdrs.data(), sizeof(Elf_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        fclose(fp);
        return;
    }

    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        fclose(fp);
        return;
    }
    const Elf_Shdr& shstr = shdrs[ehdr.e_shstrndx];
    if (shstr.sh_size == 0 || shstr.sh_size > 1024 * 1024) {
        fclose(fp);
        return;
    }
    std::vector<char> shstrtab(shstr.sh_size);
    if (fseek(fp, static_cast<long>(shstr.sh_offset), SEEK_SET) != 0
        || fread(shstrtab.data(), 1, shstr.sh_size, fp) != shstr.sh_size) {
        fclose(fp);
        return;
    }
    fclose(fp);

    for (const auto& sh : shdrs) {
        if (sh.sh_name >= shstr.sh_size) continue;
        const char* name = shstrtab.data() + sh.sh_name;
        if (strcmp(name, sh_name) == 0) {
            *target = sh;
            PLOGD("found section %s size=%u", sh_name, static_cast<unsigned>(sh.sh_size));
            return;
        }
    }
    PLOGW("section not found: %s in %s", sh_name, elf_path);
}

bool get_first_pt_load_vaddr(const char* elf_path, uint64_t* out_vaddr) {
    if (elf_path == nullptr || out_vaddr == nullptr) return false;
    *out_vaddr = 0;
    FILE* fp = fopen(elf_path, "rb");
    if (!fp) return false;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_phoff == 0
        || ehdr.e_phentsize != sizeof(Elf_Phdr)
        || ehdr.e_phnum == 0) {
        fclose(fp);
        return false;
    }
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }
    bool found = false;
    uint64_t min_vaddr = UINT64_MAX;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf_Phdr ph{};
        if (fread(&ph, 1, sizeof(ph), fp) != sizeof(ph)) break;
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_vaddr < min_vaddr) {
            min_vaddr = ph.p_vaddr;
            found = true;
        }
    }
    fclose(fp);
    if (!found) return false;
    *out_vaddr = min_vaddr;
    return true;
}

bool find_so_load_bias(const char* so_name, uintptr_t* out_bias) {
    if (so_name == nullptr || so_name[0] == 0 || out_bias == nullptr) return false;
    std::string path = find_so_path(so_name);
    if (path.empty()) return false;

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    uintptr_t map_start = 0;
    bool found_map = false;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Prefer exact path match for the resolved ELF (so_plain over packaged).
        bool path_hit = !path.empty() && strstr(line, path.c_str()) != nullptr;
        if (!path_hit) continue;
        if (strchr(line, '/') == nullptr) continue;
        unsigned long start = 0;
        if (sscanf(line, "%lx-", &start) == 1) {
            map_start = static_cast<uintptr_t>(start);
            found_map = true;
            break;
        }
    }
    fclose(fp);
    if (!found_map) return false;

    uint64_t p_vaddr = 0;
    if (!get_first_pt_load_vaddr(path.c_str(), &p_vaddr)) {
        *out_bias = map_start; // best-effort fallback
        return true;
    }
    *out_bias = map_start - static_cast<uintptr_t>(p_vaddr);
    return true;
}

} // namespace protector
