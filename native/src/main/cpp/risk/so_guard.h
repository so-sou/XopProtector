#pragma once

#include <cstdint>

namespace protector::risk {

/**
 * Capture .bitcode CRC after decrypt, apply MADV_DONTDUMP, and remember
 * libprotector load bias for later integrity / anti-dump checks.
 * Call once from init_protector after decrypt_bitcode().
 */
void so_guard_init();

/**
 * Re-check in-memory .bitcode CRC and scan maps for suspicious RWX /
 * dump tooling touching libprotector.so. Fires handle_risk on failure.
 */
void so_guard_check();

} // namespace protector::risk
