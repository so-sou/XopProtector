#ifndef _PROTECTOR_CRYPTO_RC4_H_
#define _PROTECTOR_CRYPTO_RC4_H_

#include <stdint.h>

struct rc4_state {
    uint8_t perm[256];
    uint8_t index1;
    uint8_t index2;
};

#ifdef __cplusplus
extern "C" {
#endif

void rc4_init(struct rc4_state* state, const uint8_t* key, int keylen);
void rc4_crypt(struct rc4_state* state,
               const uint8_t* inbuf, uint8_t* outbuf, int buflen);

#ifdef __cplusplus
}
#endif

#endif
