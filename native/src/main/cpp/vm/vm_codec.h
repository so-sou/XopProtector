#pragma once

#include <cstdint>
#include <cstddef>

namespace protector::vm {

/** Legacy PVM1 packing (decode → write Dalvik). */
constexpr uint32_t FLAG_VMP = 1u;
/** True VMP: PVM2 image interpreted natively (never restored to DEX). */
constexpr uint32_t FLAG_TRUE_VMP = 2u;

/**
 * Decode PVM1 image (magic + packed bytes) into Dalvik insn bytes.
 * plain_len must equal packed_len - 4.
 */
bool unpack_pvm1(uint32_t method_idx,
                 const uint8_t* packed, size_t packed_len,
                 uint8_t* plain, size_t plain_len);

} // namespace protector::vm
