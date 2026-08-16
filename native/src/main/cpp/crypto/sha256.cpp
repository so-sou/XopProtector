/**
 * Minimal SHA-256 + HMAC-SHA-256 implementation.
 * Optimised for ARM64; no malloc, no external deps.
 */
#include "crypto/sha256.h"
#include <string.h>

namespace protector::crypto {

// ── SHA-256 core ────────────────────────────────────────────────────

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t big32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

static inline void put_big32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = big32(block + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx* ctx, const void* data, size_t len) {
    auto* p = static_cast<const uint8_t*>(data);
    size_t idx = static_cast<size_t>(ctx->count & 63);
    ctx->count += static_cast<uint64_t>(len);
    while (len > 0) {
        size_t n = 64 - idx;
        if (n > len) n = len;
        memcpy(ctx->buf + idx, p, n);
        idx += n;
        p += n;
        len -= n;
        if (idx == 64) {
            sha256_transform(ctx->state, ctx->buf);
            idx = 0;
        }
    }
}

void sha256_final(sha256_ctx* ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    size_t idx = static_cast<size_t>(ctx->count & 63);
    // Padding
    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        memset(ctx->buf + idx, 0, 64 - idx);
        sha256_transform(ctx->state, ctx->buf);
        idx = 0;
    }
    memset(ctx->buf + idx, 0, 56 - idx);
    put_big32(ctx->buf + 56, static_cast<uint32_t>(bits >> 32));
    put_big32(ctx->buf + 60, static_cast<uint32_t>(bits));
    sha256_transform(ctx->state, ctx->buf);
    for (int i = 0; i < 8; i++) put_big32(digest + i * 4, ctx->state[i]);
}

// ── HMAC-SHA-256 ────────────────────────────────────────────────────

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const void* data, size_t data_len,
                 uint8_t mac_out[32]) {
    uint8_t key_block[64] = {0};
    const size_t block_sz = 64;

    // Step 1 — key derivation
    if (key_len > block_sz) {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_block);  // hash → first 32 bytes of key_block
        // rest stays 0
    } else {
        memcpy(key_block, key, key_len);
    }

    // Step 2 — inner: H((K ^ ipad) || msg)
    uint8_t inner_key[64];
    for (int i = 0; i < 64; i++) inner_key[i] = key_block[i] ^ 0x36;

    sha256_ctx inner;
    sha256_init(&inner);
    sha256_update(&inner, inner_key, 64);
    sha256_update(&inner, data, data_len);
    uint8_t inner_hash[32];
    sha256_final(&inner, inner_hash);

    // Step 3 — outer: H((K ^ opad) || inner_hash)
    uint8_t outer_key[64];
    for (int i = 0; i < 64; i++) outer_key[i] = key_block[i] ^ 0x5c;

    sha256_ctx outer;
    sha256_init(&outer);
    sha256_update(&outer, outer_key, 64);
    sha256_update(&outer, inner_hash, 32);
    sha256_final(&outer, mac_out);
}

} // namespace protector::crypto
