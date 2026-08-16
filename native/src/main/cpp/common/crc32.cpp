#include "common/crc32.h"

#include <mutex>

namespace protector {

static uint32_t crc_table[256];
static std::once_flag crc_table_once;

static void init_crc_table() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
}

uint32_t crc32_update(uint32_t crc, const uint8_t* buf, size_t len) {
    std::call_once(crc_table_once, init_crc_table);
    crc = crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

} // namespace protector
