#! Pushes the registered digest of maximum uint value, 2^256 - 1.
pub proc push_max_digest
    push.{{MAX_DIGEST}}
end

#! Pushes the raw little-endian u32 limbs of maximum uint value, 2^256 - 1.
#! Output: [VALUE_U32[8], ...]
pub proc push_max_value
    # Inline constant: raw canonical limbs for maximum uint value, 2^256 - 1.
    push.{{MAX_HI_WORD}}
    push.{{MAX_LO_WORD}}
end
