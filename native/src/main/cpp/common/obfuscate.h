#pragma once

/**
 * Phase 7 — portable control-flow / bogus-flow helpers (stock NDK clang).
 * Stacks with optional OLLVM/Hikari passes (see cmake PROTECTOR_LLVM_OBF).
 *
 * Enable with PROTECTOR_SRC_OBF=1 (Release default). When off, macros are no-ops
 * so call sites stay readable.
 */

#include <cstdint>

#ifndef PROTECTOR_SRC_OBF
#define PROTECTOR_SRC_OBF 0
#endif

namespace protector::obf {

/** Volatile seed — resists constant-fold of opaque predicates. */
__attribute__((noinline)) inline uint32_t opaque_seed() {
    volatile uint32_t x = 0xA5C37u;
    x ^= static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&x) & 0xFFu);
    x ^= static_cast<uint32_t>(__LINE__ * 0x9E37u);
    return x;
}

/** Always true: n(n+1) is even. */
__attribute__((noinline)) inline bool opaque_true() {
    volatile uint32_t n = opaque_seed();
    return ((n * (n + 1u)) & 1u) == 0u;
}

/** Always false. */
__attribute__((noinline)) inline bool opaque_false() {
    return !opaque_true();
}

/** MBA: x ^ y without a single XOR (harder for simple pattern match). */
__attribute__((always_inline)) inline uint8_t mba_xor8(uint8_t x, uint8_t y) {
    return static_cast<uint8_t>((x | y) - (x & y));
}

} // namespace protector::obf

#if PROTECTOR_SRC_OBF

/** Insert a dead branch the optimizer cannot fully eliminate. */
#define PROTECTOR_BCF_NEVER() (::protector::obf::opaque_false())
#define PROTECTOR_BCF_ALWAYS() (::protector::obf::opaque_true())

/** Dead code sink — never executed when predicates hold. */
#define PROTECTOR_BCF_SINK()                                           \
    do {                                                               \
        if (PROTECTOR_BCF_NEVER()) {                                   \
            volatile uint32_t __pobf_sink =                             \
                    ::protector::obf::opaque_seed() ^ (__LINE__);      \
            (void)__pobf_sink;                                         \
        }                                                              \
    } while (0)

/**
 * Flattened dispatcher skeleton:
 *   volatile int st = 0;
 *   PROTECTOR_CFF_BEGIN(st)
 *   PROTECTOR_CFF_CASE(0) { ...; PROTECTOR_CFF_GOTO(st, 1); }
 *   PROTECTOR_CFF_CASE(1) { ...; PROTECTOR_CFF_FINISH(st); }
 *   PROTECTOR_CFF_END(st)
 */
#define PROTECTOR_CFF_BEGIN(st) \
    for (;;) {                  \
        switch (st) {
#define PROTECTOR_CFF_CASE(n) case (n):
#define PROTECTOR_CFF_GOTO(st, n) \
    do {                          \
        (st) = (n);               \
        break;                    \
    } while (0)
#define PROTECTOR_CFF_FINISH(st) \
    do {                         \
        (st) = -1;               \
        break;                   \
    } while (0)
#define PROTECTOR_CFF_END(st) \
    default:                  \
        goto __pobf_cff_done; \
        }                     \
        if ((st) < 0) {       \
            break;            \
        }                     \
    }                         \
    __pobf_cff_done:          \
    do {                      \
    } while (0)

#define PROTECTOR_MBA_XOR8(a, b) (::protector::obf::mba_xor8((a), (b)))

#else

#define PROTECTOR_BCF_NEVER() (false)
#define PROTECTOR_BCF_ALWAYS() (true)
#define PROTECTOR_BCF_SINK() ((void)0)
#define PROTECTOR_CFF_BEGIN(st) if (true) {
#define PROTECTOR_CFF_CASE(n) if ((st) == (n) || true) {
#define PROTECTOR_CFF_GOTO(st, n) \
    do {                          \
        (st) = (n);               \
    } while (0)
#define PROTECTOR_CFF_FINISH(st) \
    do {                         \
        (st) = -1;               \
    } while (0)
#define PROTECTOR_CFF_END(st) }
#define PROTECTOR_MBA_XOR8(a, b) static_cast<uint8_t>((a) ^ (b))

#endif
