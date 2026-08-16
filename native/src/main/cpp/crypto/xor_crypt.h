#pragma once
#include <cstdint>
#include <string>

namespace protector::crypto {

inline void xor_inplace(uint8_t* data, size_t len, uint32_t key) {
    if (key == 0 || data == nullptr || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        uint32_t shift = (i & 3u) << 3u;
        data[i] = static_cast<uint8_t>(data[i] ^ ((key >> shift) & 0xffu));
    }
}

inline void xor_to(const uint8_t* src, uint8_t* dst, size_t len, uint32_t key) {
    if (src == nullptr || dst == nullptr) return;
    for (size_t i = 0; i < len; i++) {
        if (key == 0) {
            dst[i] = src[i];
        } else {
            uint32_t shift = (i & 3u) << 3u;
            dst[i] = static_cast<uint8_t>(src[i] ^ ((key >> shift) & 0xffu));
        }
    }
}

} // namespace protector::crypto
