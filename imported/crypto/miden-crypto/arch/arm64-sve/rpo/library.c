#include <stddef.h>
#include <arm_sve.h>
#include "library.h"
#include "rpo_hash_128bit.h"
#include "rpo_hash_256bit.h"

// The STATE_WIDTH of RPO hash is 12x u64 elements.
// The current generation of SVE-enabled processors - Neoverse V1
// (e.g. AWS Graviton3) have 256-bit vector registers (4x u64)
// This allows us to split the state into 3 vectors of 4 elements
// and process all 3 independent of each other.

// We see the biggest performance gains by leveraging both
// vector and scalar operations on parts of the state array.
// Due to high latency of vector operations, the processor is able
// to reorder and pipeline scalar instructions while we wait for
// vector results. This effectively gives us some 'free' scalar
// operations and masks vector latency.
//
// This also means that we can fully saturate all four arithmetic
// units of the processor (2x scalar, 2x SIMD)
//
// THIS ANALYSIS NEEDS TO BE PERFORMED AGAIN ONCE PROCESSORS
// GAIN WIDER REGISTERS. It's quite possible that with 8x u64
// vectors processing 2 partially filled vectors might
// be easier and faster than dealing with scalar operations
// on the remainder of the array.
//
// FOR NOW THIS IS ONLY ENABLED ON 4x u64 VECTORS! It falls back
// to the regular, already highly-optimized scalar version
// if the conditions are not met.

bool add_constants_and_apply_sbox(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = svcntd();   // number of u64 numbers in one SVE vector
    
    if (vl == 2) {
        return add_constants_and_apply_sbox_128(state, constants);
    } else if (vl == 4) {
        return add_constants_and_apply_sbox_256(state, constants);
    } else {
        return false;
    }
}

bool add_constants_and_apply_inv_sbox(uint64_t state[STATE_WIDTH], uint64_t constants[STATE_WIDTH]) {
    const uint64_t vl = svcntd();   // number of u64 numbers in one SVE vector

    if (vl == 2) {
        return add_constants_and_apply_inv_sbox_128(state, constants);
    } else if (vl == 4) {
        return add_constants_and_apply_inv_sbox_256(state, constants);
    } else {
        return false;
    }
}
