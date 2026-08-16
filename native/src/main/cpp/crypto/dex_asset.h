#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace protector::crypto {

/**
 * Decrypt assets/protector/dexes.zip when wrapped as PDX1:
 *   magic(4)='PDX1' || AES-GCM(nonce||ct||tag)
 * Plain ZIP (starts with PK) is left unchanged (legacy packs).
 * On success writes plaintext ZIP to the same path (in-place replace).
 *
 * Prefer {@link decrypt_and_extract_dexes} on cold start (skips plaintext zip I/O).
 */
bool decrypt_dexes_zip_file(const std::string& path, const uint8_t key[16]);

/**
 * Cold-start fast path: PDX1 decrypt in memory → extract {@code *.dex} into
 * {@code out_dir} (parallel inflate) → delete the on-disk zip (ciphertext).
 * Never leaves a plaintext ZIP on disk. Legacy PK zip is extracted the same way.
 *
 * @param key 16-byte AES key for PDX1; ignored for plaintext ZIP (may be null then).
 * @return true if at least one .dex was written, or ZIP had no dex entries (empty OK).
 */
bool decrypt_and_extract_dexes(const std::string& zip_path,
                               const uint8_t key[16],
                               const std::string& out_dir);

} // namespace protector::crypto
