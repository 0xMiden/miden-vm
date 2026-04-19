#ifndef CRYPTO_LIBRARY_H
#define CRYPTO_LIBRARY_H

#include <stdint.h>
#include <stdbool.h>

#define STATE_WIDTH 12

bool add_constants_and_apply_sbox(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]);
bool add_constants_and_apply_inv_sbox(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]);

#endif //CRYPTO_LIBRARY_H
