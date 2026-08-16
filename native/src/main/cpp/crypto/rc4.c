#include "crypto/rc4.h"

static void swap_bytes(uint8_t* a, uint8_t* b) {
    uint8_t temp = *a;
    *a = *b;
    *b = temp;
}

void rc4_init(struct rc4_state* const state, const uint8_t* key, int keylen) {
    uint8_t j;
    int i;

    for (i = 0; i < 256; i++) {
        state->perm[i] = (uint8_t)i;
    }
    state->index1 = 0;
    state->index2 = 0;

    for (j = i = 0; i < 256; i++) {
        j += state->perm[i] + key[i % keylen];
        swap_bytes(&state->perm[i], &state->perm[j]);
    }
}

void rc4_crypt(struct rc4_state* const state,
               const uint8_t* inbuf, uint8_t* outbuf, int buflen) {
    int i;
    uint8_t j;

    for (i = 0; i < buflen; i++) {
        state->index1++;
        state->index2 += state->perm[state->index1];
        swap_bytes(&state->perm[state->index1], &state->perm[state->index2]);
        j = state->perm[state->index1] + state->perm[state->index2];
        outbuf[i] = inbuf[i] ^ state->perm[j];
    }
}
