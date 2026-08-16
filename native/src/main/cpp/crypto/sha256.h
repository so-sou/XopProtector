/**
 * Minimal SHA-256 + HMAC-SHA-256 for config integrity verification.
 * Public-domain style implementation — no external dependencies.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace protector::crypto {

struct sha256_ctx {
    uint8_t buf[64];
    uint32_t state[8];
    uint64_t count;
};

void sha256_init(sha256_ctx* ctx);
void sha256_update(sha256_ctx* ctx, const void* data, size_t len);
void sha256_final(sha256_ctx* ctx, uint8_t digest[32]);

/** One-shot SHA-256. */
inline void sha256(const void* data, size_t len, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/**
 * HMAC-SHA-256.
 * @param key      secret key
 * @param key_len  key length in bytes
 * @param data     message
 * @param data_len message length
 * @param mac_out  32-byte output MAC
 */
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const void* data, size_t data_len,
                 uint8_t mac_out[32]);

} // namespace protector::crypto
