#! Loads a 128-bit little-endian chunk from memory as a canonical field value.
#! Input:  [ptr, ...]
#! Output: [FIELD_DIGEST, ...]
#! Memory layout: ptr[0..4] = chunk limbs; high field limbs are zero.
pub proc load_128_mem
    padw movup.4 mem_loadw_le
    # => [CHUNK_U32[4], ...]
    push.[0, 0, 0, 0] swapw
    # => [CHUNK_U32[4], ZERO_HI_U32[4], ...]
    exec.load
    # => [FIELD_DIGEST, ...]
end

#! Reduces a 512-bit little-endian u32 value from memory into this field.
#! Input:  [ptr, ...]
#! Output: [FIELD_DIGEST, ...]
#! Memory layout: ptr[0..16] = little-endian u32 limbs of the 512-bit value.
pub proc load_reduced_512_mem
    # h = c0. Keep ptr underneath the accumulator for the remaining chunks.
    dup
    # => [ptr, ptr, ...]
    exec.load_128_mem
    # => [H_DIGEST, ptr, ...]

    # h += c1 * 2^128.
    dup.4 add.4
    # => [ptr + 4, H_DIGEST, ptr, ...]
    exec.load_128_mem
    # => [C1_DIGEST, H_DIGEST, ptr, ...]
    exec.push_pow_2_128_digest
    # => [POW_2_128_DIGEST, C1_DIGEST, H_DIGEST, ptr, ...]
    exec.mul
    # => [TERM_DIGEST, H_DIGEST, ptr, ...]
    exec.add
    # => [H_DIGEST, ptr, ...]

    # h += c2 * 2^256.
    dup.4 add.8
    # => [ptr + 8, H_DIGEST, ptr, ...]
    exec.load_128_mem
    # => [C2_DIGEST, H_DIGEST, ptr, ...]
    exec.push_pow_2_256_digest
    # => [POW_2_256_DIGEST, C2_DIGEST, H_DIGEST, ptr, ...]
    exec.mul
    # => [TERM_DIGEST, H_DIGEST, ptr, ...]
    exec.add
    # => [H_DIGEST, ptr, ...]

    # h += c3 * 2^384.
    dup.4 add.12
    # => [ptr + 12, H_DIGEST, ptr, ...]
    exec.load_128_mem
    # => [C3_DIGEST, H_DIGEST, ptr, ...]
    exec.push_pow_2_384_digest
    # => [POW_2_384_DIGEST, C3_DIGEST, H_DIGEST, ptr, ...]
    exec.mul
    # => [TERM_DIGEST, H_DIGEST, ptr, ...]
    exec.add
    # => [H_DIGEST, ptr, ...]

    movup.4 drop
    # => [H_DIGEST, ...]
end

#! Computes the multiplicative inverse of a nonzero field element digest.
#! Input:  [X_DIGEST, ...]
#! Output: [INV_DIGEST, ...]
#!
#! The inverse limbs are untrusted host advice. This wrapper registers the advised limbs as a
#! canonical VALUE node, then proves correctness by logging `eq(mul(X_DIGEST, INV_DIGEST), one)`
#! into the deferred root using only existing MUL and EQ nodes.
pub proc inv
    emit.event("miden::precompiles::math::field::field_inv")
    # => [X_DIGEST, ...]

    adv_pushw
    adv_pushw
    # => [INV_HI, INV_LO, X_DIGEST, ...]
    swapw
    # => [INV_LO, INV_HI, X_DIGEST, ...]
    exec.load
    # => [INV_DIGEST, X_DIGEST, ...]

    dupw
    movupw.2
    # => [X_DIGEST, INV_DIGEST, INV_DIGEST, ...]
    exec.mul
    # => [PRODUCT_DIGEST, INV_DIGEST, ...]

    exec.push_one_digest
    # => [ONE_DIGEST, PRODUCT_DIGEST, INV_DIGEST, ...]
    exec.assert_eq
    # => [INV_DIGEST, ...]
end

#! Divides one field element digest by another nonzero field element digest.
#! Input:  [NUMERATOR_DIGEST, DENOMINATOR_DIGEST, ...]
#! Output: [QUOTIENT_DIGEST, ...]
pub proc div
    swapw
    # => [DENOMINATOR_DIGEST, NUMERATOR_DIGEST, ...]
    exec.inv
    # => [INV_DENOMINATOR_DIGEST, NUMERATOR_DIGEST, ...]
    swapw
    # => [NUMERATOR_DIGEST, INV_DENOMINATOR_DIGEST, ...]
    exec.mul
    # => [QUOTIENT_DIGEST, ...]
end
