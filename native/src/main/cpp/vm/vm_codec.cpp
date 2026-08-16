#include "vm/vm_codec.h"
#include "common/protector_macro.h"
#include "common/log.h"

#include <cstring>

namespace protector::vm {

static constexpr uint8_t kMagic[4] = {'P', 'V', 'M', '1'};

static inline uint8_t keystream(uint32_t method_idx, size_t i) {
    return static_cast<uint8_t>((method_idx * 131u + static_cast<uint32_t>(i) * 17u + 0xA5u) & 0xffu);
}

PROTECTOR_ENCRYPT bool unpack_pvm1(uint32_t method_idx,
                                   const uint8_t* packed, size_t packed_len,
                                   uint8_t* plain, size_t plain_len) {
    if (packed == nullptr || plain == nullptr) return false;
    if (packed_len < 4 + plain_len) return false;
    if (memcmp(packed, kMagic, 4) != 0) {
        PLOGW("PVM1 magic mismatch method=%u", method_idx);
        return false;
    }
    const uint8_t* src = packed + 4;
    for (size_t i = 0; i < plain_len; i++) {
        uint8_t b = src[i];
        if ((i & 1u) == 0u) {
            b = static_cast<uint8_t>(((b << 4) & 0xf0) | ((b >> 4) & 0x0f));
        }
        plain[i] = static_cast<uint8_t>(b ^ keystream(method_idx, i));
    }
    return true;
}

} // namespace protector::vm
