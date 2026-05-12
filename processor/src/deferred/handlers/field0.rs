use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{DeferredError, DeferredTag, FIELD, FIELD_0, Payload, ValueType},
};

use super::DeferredTypeHandler;

/// Handler for the first 256-bit non-native field, `Field0`.
///
/// A canonical leaf payload is eight felts, each holding a u32-canonical limb in little-endian
/// order. Arithmetic is performed on the 256-bit integer formed by those limbs.
///
/// **Modulus (v1 placeholder):** add and mul are computed *modulo 2^256* — i.e. a 256-bit ring,
/// not yet a prime field. The trait makes the concrete reduction pluggable; selecting the final
/// modulus (e.g. secp256k1 base, p25519) is out of scope for v1 and will be a one-file change
/// here. Tests pin the placeholder semantics explicitly.
pub struct Field0Handler;

impl DeferredTypeHandler for Field0Handler {
    fn value_type(&self) -> ValueType {
        ValueType::Field0
    }

    fn type_prefix(&self) -> [Felt; 2] {
        [FIELD, FIELD_0]
    }

    fn canonical_leaf_tag(&self) -> DeferredTag {
        DeferredTag::Field0Leaf
    }

    fn eval_op(
        &self,
        op_tag: DeferredTag,
        lhs: (DeferredTag, Payload),
        rhs: (DeferredTag, Payload),
    ) -> Result<(DeferredTag, Payload), DeferredError> {
        // Both operands must be canonical Field0 leaves. Anything else (an unevaluated op, a
        // foreign value type) is an InvalidPayload at the handler boundary — the caller is
        // expected to have evaluated children before invoking eval_op.
        if lhs.0 != DeferredTag::Field0Leaf || rhs.0 != DeferredTag::Field0Leaf {
            return Err(DeferredError::InvalidPayload);
        }
        let a = decode_limbs(&lhs.1)?;
        let b = decode_limbs(&rhs.1)?;
        let c = match op_tag {
            DeferredTag::Field0Add => add_mod_2_256(a, b),
            DeferredTag::Field0Mul => mul_mod_2_256(a, b),
            _ => return Err(DeferredError::Unsupported),
        };
        Ok((DeferredTag::Field0Leaf, encode_limbs(c)))
    }

    fn encode_advice(&self, payload: &Payload) -> Result<Vec<Felt>, DeferredError> {
        Ok(payload.0.to_vec())
    }
}

/// Decode a payload as eight u32-canonical limbs. A limb whose felt is outside `[0, u32::MAX]`
/// surfaces here, not at insertion time — consistent with v1's "validate at use" stance.
fn decode_limbs(payload: &Payload) -> Result<[u32; 8], DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in payload.0.iter().enumerate() {
        let v = felt.as_canonical_u64();
        if v > u32::MAX as u64 {
            return Err(DeferredError::InvalidPayload);
        }
        limbs[i] = v as u32;
    }
    Ok(limbs)
}

fn encode_limbs(limbs: [u32; 8]) -> Payload {
    Payload::new(limbs.map(Felt::from_u32))
}

/// 256-bit add with wraparound (mod 2^256). Limbs are little-endian u32.
fn add_mod_2_256(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    let mut out = [0u32; 8];
    let mut carry: u64 = 0;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    out
}

/// 256-bit schoolbook mul keeping the low 256 bits (mod 2^256). Limbs are little-endian u32.
fn mul_mod_2_256(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..(8 - i) {
            let cur = out[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
            out[i + j] = cur as u32;
            carry = cur >> 32;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use miden_core::Felt;

    use super::*;

    fn leaf_from_u32s(limbs: [u32; 8]) -> Payload {
        Payload::new(limbs.map(Felt::from_u32))
    }

    fn leaf_from_low_u64(value: u64) -> Payload {
        let mut limbs = [0u32; 8];
        limbs[0] = value as u32;
        limbs[1] = (value >> 32) as u32;
        leaf_from_u32s(limbs)
    }

    #[test]
    fn add_small_values() {
        let h = Field0Handler;
        let a = leaf_from_low_u64(3);
        let b = leaf_from_low_u64(5);
        let (tag, out) = h
            .eval_op(
                DeferredTag::Field0Add,
                (DeferredTag::Field0Leaf, a),
                (DeferredTag::Field0Leaf, b),
            )
            .unwrap();
        assert_eq!(tag, DeferredTag::Field0Leaf);
        assert_eq!(out, leaf_from_low_u64(8));
    }

    #[test]
    fn add_propagates_carry_across_limbs() {
        let h = Field0Handler;
        let mut a_limbs = [0u32; 8];
        a_limbs[0] = u32::MAX;
        let mut b_limbs = [0u32; 8];
        b_limbs[0] = 1;
        let (_, out) = h
            .eval_op(
                DeferredTag::Field0Add,
                (DeferredTag::Field0Leaf, leaf_from_u32s(a_limbs)),
                (DeferredTag::Field0Leaf, leaf_from_u32s(b_limbs)),
            )
            .unwrap();
        let mut expected = [0u32; 8];
        expected[1] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn add_wraps_at_2_to_256() {
        let h = Field0Handler;
        let max = leaf_from_u32s([u32::MAX; 8]);
        let one = leaf_from_low_u64(1);
        let (_, out) = h
            .eval_op(
                DeferredTag::Field0Add,
                (DeferredTag::Field0Leaf, max),
                (DeferredTag::Field0Leaf, one),
            )
            .unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn mul_small_values() {
        let h = Field0Handler;
        let a = leaf_from_low_u64(6);
        let b = leaf_from_low_u64(7);
        let (_, out) = h
            .eval_op(
                DeferredTag::Field0Mul,
                (DeferredTag::Field0Leaf, a),
                (DeferredTag::Field0Leaf, b),
            )
            .unwrap();
        assert_eq!(out, leaf_from_low_u64(42));
    }

    #[test]
    fn mul_propagates_across_limbs() {
        let h = Field0Handler;
        // (2^32) * (2^32) = 2^64 — should land entirely in limb[2].
        let mut a_limbs = [0u32; 8];
        a_limbs[1] = 1;
        let b_limbs = a_limbs;
        let (_, out) = h
            .eval_op(
                DeferredTag::Field0Mul,
                (DeferredTag::Field0Leaf, leaf_from_u32s(a_limbs)),
                (DeferredTag::Field0Leaf, leaf_from_u32s(b_limbs)),
            )
            .unwrap();
        let mut expected = [0u32; 8];
        expected[2] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn mul_truncates_overflow_above_2_to_256() {
        let h = Field0Handler;
        // 2^255 * 2 = 2^256 → 0 mod 2^256.
        let mut a_limbs = [0u32; 8];
        a_limbs[7] = 1 << 31;
        let two = leaf_from_low_u64(2);
        let (_, out) = h
            .eval_op(
                DeferredTag::Field0Mul,
                (DeferredTag::Field0Leaf, leaf_from_u32s(a_limbs)),
                (DeferredTag::Field0Leaf, two),
            )
            .unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn non_canonical_limb_errors() {
        let h = Field0Handler;
        // u32::MAX + 1 = 2^32 is outside the u32 range but still a valid Felt — must surface as
        // InvalidPayload when eval_op decodes the limbs.
        let bad = Payload::new([
            Felt::new_unchecked(1u64 << 32),
            Felt::from_u32(0),
            Felt::from_u32(0),
            Felt::from_u32(0),
            Felt::from_u32(0),
            Felt::from_u32(0),
            Felt::from_u32(0),
            Felt::from_u32(0),
        ]);
        let ok = leaf_from_low_u64(1);
        let err = h.eval_op(
            DeferredTag::Field0Add,
            (DeferredTag::Field0Leaf, bad),
            (DeferredTag::Field0Leaf, ok),
        );
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn non_leaf_operand_errors() {
        let h = Field0Handler;
        // Passing an op-tag as an operand tag means the caller didn't evaluate this side first.
        let a = leaf_from_low_u64(1);
        let b = leaf_from_low_u64(1);
        let err = h.eval_op(
            DeferredTag::Field0Add,
            (DeferredTag::Field0Add, a),
            (DeferredTag::Field0Leaf, b),
        );
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn unsupported_op_tag_errors() {
        let h = Field0Handler;
        let a = leaf_from_low_u64(1);
        let b = leaf_from_low_u64(1);
        let err = h.eval_op(
            DeferredTag::Field0Leaf,
            (DeferredTag::Field0Leaf, a),
            (DeferredTag::Field0Leaf, b),
        );
        assert!(matches!(err, Err(DeferredError::Unsupported)));
    }

    #[test]
    fn type_prefix_and_canonical_leaf() {
        let h = Field0Handler;
        assert_eq!(h.value_type(), ValueType::Field0);
        assert_eq!(h.type_prefix(), [FIELD, FIELD_0]);
        assert_eq!(h.canonical_leaf_tag(), DeferredTag::Field0Leaf);
    }

    #[test]
    fn encode_advice_returns_payload_felts() {
        let h = Field0Handler;
        let p = leaf_from_low_u64(0xabcd_ef01_2345_6789);
        let v = h.encode_advice(&p).unwrap();
        assert_eq!(v.len(), 8);
        assert_eq!(v.as_slice(), p.as_felts());
    }
}
