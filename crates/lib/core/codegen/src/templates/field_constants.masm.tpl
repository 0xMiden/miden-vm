#! Pushes the registered digest of field constant -1.
pub proc push_minus_one_digest
    push.{{MINUS_ONE_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of field constant -1.
#! Output: [VALUE_U32[8], ...]
pub proc push_minus_one_value
    # Inline constant: raw canonical limbs for field constant -1.
    push.{{MINUS_ONE_HI_WORD}}
    push.{{MINUS_ONE_LO_WORD}}
end

#! Pushes the registered digest of field constant 1/2.
pub proc push_half_digest
    push.{{HALF_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of field constant 1/2.
#! Output: [VALUE_U32[8], ...]
pub proc push_half_value
    # Inline constant: raw canonical limbs for field constant 1/2.
    push.{{HALF_HI_WORD}}
    push.{{HALF_LO_WORD}}
end

#! Pushes the registered digest of field constant 2^128.
pub proc push_pow_2_128_digest
    push.{{POW_2_128_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of field constant 2^128.
#! Output: [VALUE_U32[8], ...]
pub proc push_pow_2_128_value
    # Inline constant: raw canonical limbs for field constant 2^128.
    push.{{POW_2_128_HI_WORD}}
    push.{{POW_2_128_LO_WORD}}
end

#! Pushes the registered digest of field constant 2^256.
pub proc push_pow_2_256_digest
    push.{{POW_2_256_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of field constant 2^256.
#! Output: [VALUE_U32[8], ...]
pub proc push_pow_2_256_value
    # Inline constant: raw canonical limbs for field constant 2^256.
    push.{{POW_2_256_HI_WORD}}
    push.{{POW_2_256_LO_WORD}}
end

#! Pushes the registered digest of field constant 2^384.
pub proc push_pow_2_384_digest
    push.{{POW_2_384_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of field constant 2^384.
#! Output: [VALUE_U32[8], ...]
pub proc push_pow_2_384_value
    # Inline constant: raw canonical limbs for field constant 2^384.
    push.{{POW_2_384_HI_WORD}}
    push.{{POW_2_384_LO_WORD}}
end
