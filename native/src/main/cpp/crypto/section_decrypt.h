#pragma once

namespace protector {

/** Decrypt .bitcode in-place (no-op unless DECRYPT_BITCODE). */
void decrypt_bitcode();

/** Early init: decrypt then install hooks / risk. */
void init_protector();

} // namespace protector
