#ifndef MIDEN_CRYPTO_EIDOS_ARM_H
#define MIDEN_CRYPTO_EIDOS_ARM_H

#include <stddef.h>
#include <stdint.h>

// These pointer-only signatures are the ABI boundary between Rust dispatch and the ARM kernels.
// Packed operands are word-major arrays with a fixed logical width of 16 u32 lanes.
typedef void (*eidos_raw_kernel)(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out);
typedef void (*eidos_xof_kernel)(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out);
typedef void (*eidos_packed_kernel)(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out);
typedef void (*eidos_counted_kernel)(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out,
    size_t active_lanes);
typedef uint16_t (*eidos_pow_kernel)(
    const uint64_t *cv,
    const uint64_t *buffer,
    size_t buffer_len,
    uint64_t base,
    size_t count,
    uint64_t mask);

// Sequential complete blocks; mask odd CV lanes after each block. Zero count copies CV.
void eidos_compress_blocks_neon(const uint32_t *cv, const uint32_t *blocks, uint32_t *out, size_t count);
void eidos_compress_blocks_sve2(const uint32_t *cv, const uint32_t *blocks, uint32_t *out, size_t count);

void eidos_compress_raw_neon(const uint32_t *cv, const uint32_t *block, uint32_t *out);
void eidos_compress_xof_neon(const uint32_t *cv, const uint32_t *block, uint32_t *out);
// Word-major [4][16], [8][16], [4][16] u64 arrays. Counts 0..16 preserve inactive slots.
void eidos_compress16_u64_neon(const uint64_t *cv, const uint64_t *block, uint64_t *out, size_t active_lanes);
void eidos_compress16_u64_sve(const uint64_t *cv, const uint64_t *block, uint64_t *out, size_t active_lanes);
void eidos_compress16_u64_sve2(const uint64_t *cv, const uint64_t *block, uint64_t *out, size_t active_lanes);
void eidos_compress_raw_sve2(const uint32_t *cv, const uint32_t *block, uint32_t *out);
void eidos_compress_xof_sve2(const uint32_t *cv, const uint32_t *block, uint32_t *out);

void eidos_compress16_sve(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out,
    size_t active_lanes);
void eidos_compress16_sve2(
    const uint32_t *cv,
    const uint32_t *block,
    uint32_t *out,
    size_t active_lanes);

uint16_t eidos_check_witness_batch_neon(
    const uint64_t *cv,
    const uint64_t *buffer,
    size_t buffer_len,
    uint64_t base,
    size_t count,
    uint64_t mask);
uint16_t eidos_check_witness_batch_sve(
    const uint64_t *cv,
    const uint64_t *buffer,
    size_t buffer_len,
    uint64_t base,
    size_t count,
    uint64_t mask);
uint16_t eidos_check_witness_batch_sve2(
    const uint64_t *cv,
    const uint64_t *buffer,
    size_t buffer_len,
    uint64_t base,
    size_t count,
    uint64_t mask);

#endif // MIDEN_CRYPTO_EIDOS_ARM_H
