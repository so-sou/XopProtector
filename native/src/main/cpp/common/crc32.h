#pragma once

#include <cstdint>
#include <cstddef>

namespace protector {

/** IEEE / zlib CRC-32. Seed with 0 for first call (matches mz_crypt_crc32_update). */
uint32_t crc32_update(uint32_t crc, const uint8_t* buf, size_t len);

} // namespace protector
