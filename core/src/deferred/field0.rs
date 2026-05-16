use crate::{
    Felt, ZERO,
    deferred::{
        BodyShape, ChildResolver, DeferredError, Digest, Node, Payload, Schema, SchemaError,
        TRUE_TAG, Tag, TagInfo, true_node,
    },
};

/// Handler for the first 256-bit non-native field, `Field0`.
///
/// A canonical leaf payload is eight felts, each holding a u32-canonical limb in little-endian
/// order. Arithmetic is performed on the 256-bit integer formed by those limbs.
///
/// **Modulus (v1 placeholder):** add and mul are computed *modulo 2^256* — i.e. a 256-bit ring,
/// not yet a prime field. Selecting the final modulus (e.g. secp256k1 base, p25519) is out of
/// scope for v1 and will be a one-file change here. Tests pin the placeholder semantics
/// explicitly.
///
/// **Tag layout (Field0-specific, opaque to the processor):**
/// - `[1, 0, op, 0]` where `op` selects the operation:
///   - `0` — canonical leaf (payload is 8 u32-limbs); self-evaluating.
///   - `1` — `add` op node (payload is `lhs_digest || rhs_digest`); reduces to `LEAF`.
///   - `2` — `mul` op node (payload is `lhs_digest || rhs_digest`); reduces to `LEAF`.
///   - `3` — equality predicate (payload is `lhs_digest || rhs_digest`); reduces to TRUE on
///     match, errors `AssertionFailed` on mismatch.
#[derive(Debug, Default, Clone, Copy)]
pub struct Field0Handler;

impl Field0Handler {
    /// Type-family prefix shared by every Field0 tag.
    const PREFIX: [Felt; 2] = [Felt::new_unchecked(1), Felt::new_unchecked(0)];

    /// Tag for a canonical Field0 leaf.
    pub const LEAF: Tag = [Self::PREFIX[0], Self::PREFIX[1], Felt::new_unchecked(0), ZERO];
    /// Tag for a Field0 `add` op node.
    pub const ADD: Tag = [Self::PREFIX[0], Self::PREFIX[1], Felt::new_unchecked(1), ZERO];
    /// Tag for a Field0 `mul` op node.
    pub const MUL: Tag = [Self::PREFIX[0], Self::PREFIX[1], Felt::new_unchecked(2), ZERO];
    /// Tag for a Field0 `assert_eq` marker.
    pub const ASSERT_EQ: Tag = [Self::PREFIX[0], Self::PREFIX[1], Felt::new_unchecked(3), ZERO];
}

impl Schema for Field0Handler {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        let kind = Field0TagKind::classify(tag).ok_or(SchemaError::InvalidNode)?;
        // Field0 has no chunk-bodied tags; everything is expression-shaped.
        let body = BodyShape::Expression;
        let evaluates_to = match kind {
            Field0TagKind::Leaf | Field0TagKind::BinaryOp(_) => Self::LEAF,
            Field0TagKind::AssertEq => TRUE_TAG,
        };
        Ok(TagInfo { body, evaluates_to })
    }

    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError> {
        match Field0Node::parse(node)? {
            // Leaf canonicality is checked at parse-time, deferred from register-time so that
            // malformed leaves are interned silently and only error out when used.
            Field0Node::Leaf => Ok(node.clone()),
            Field0Node::BinaryOp { op, lhs, rhs } => {
                let a = leaf_limbs(&children.resolve(lhs)?)?;
                let b = leaf_limbs(&children.resolve(rhs)?)?;
                Ok(Node::expression(Self::LEAF, encode_limbs(op.apply(a, b))))
            },
            Field0Node::AssertEq { lhs, rhs } => {
                if children.resolve(lhs)? != children.resolve(rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// TYPED TAG / NODE
// ================================================================================================

/// Decoded view of a recognized Field0 tag. Pure classification — variants carry no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field0TagKind {
    Leaf,
    BinaryOp(BinaryOp),
    AssertEq,
}

impl Field0TagKind {
    /// Classify `tag`, returning `None` for tags outside the Field0 family or with a
    /// malformed op-slot. The framework maps `None` to [`SchemaError::InvalidNode`].
    fn classify(tag: Tag) -> Option<Self> {
        if tag[0] != Field0Handler::PREFIX[0]
            || tag[1] != Field0Handler::PREFIX[1]
            || tag[3] != ZERO
        {
            return None;
        }
        match tag[2].as_canonical_u64() {
            0 => Some(Self::Leaf),
            1 => Some(Self::BinaryOp(BinaryOp::Add)),
            2 => Some(Self::BinaryOp(BinaryOp::Mul)),
            3 => Some(Self::AssertEq),
            _ => None,
        }
    }
}

/// Producing binary op on two canonical leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOp {
    Add,
    Mul,
}

impl BinaryOp {
    fn apply(self, a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        match self {
            Self::Add => add_mod_2_256(a, b),
            Self::Mul => mul_mod_2_256(a, b),
        }
    }
}

/// A Field0 node with both tag *and* payload decoded. Consumed by `reduce`'s match —
/// eliminates the tag-equality ladders in `decode` and `reduce` and folds leaf-canonicality
/// validation into a single `parse` step.
enum Field0Node {
    Leaf,
    BinaryOp { op: BinaryOp, lhs: Digest, rhs: Digest },
    AssertEq { lhs: Digest, rhs: Digest },
}

impl Field0Node {
    fn parse(node: &Node) -> Result<Self, SchemaError> {
        let kind = Field0TagKind::classify(node.tag).ok_or(SchemaError::InvalidNode)?;
        let payload = node.expression_payload().ok_or(DeferredError::InvalidPayload)?;
        Ok(match kind {
            Field0TagKind::Leaf => {
                // Canonicality check; limbs themselves are unused here — `reduce` returns the
                // node by-clone, and the binary-op arm decodes its operands via `leaf_limbs`.
                decode_limbs(payload)?;
                Self::Leaf
            },
            Field0TagKind::BinaryOp(op) => {
                let (lhs, rhs) = payload.binary_op_children();
                Self::BinaryOp { op, lhs, rhs }
            },
            Field0TagKind::AssertEq => {
                let (lhs, rhs) = payload.binary_op_children();
                Self::AssertEq { lhs, rhs }
            },
        })
    }
}

// HELPERS
// ================================================================================================

/// Extract `[u32; 8]` from a canonical-leaf child node, erroring if the resolved child is
/// not a Field0 leaf or has a non-canonical limb.
fn leaf_limbs(node: &Node) -> Result<[u32; 8], DeferredError> {
    if Field0TagKind::classify(node.tag) != Some(Field0TagKind::Leaf) {
        return Err(DeferredError::InvalidPayload);
    }
    decode_limbs(node.expression_payload().ok_or(DeferredError::InvalidPayload)?)
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
    use super::*;

    /// Apply a binary op to two already-canonical leaves. Mirrors the `BinaryOp` arm of
    /// `Schema::reduce` without going through a `ChildResolver`, so unit tests can exercise the
    /// arithmetic kernels and the leaf-operand guard directly.
    fn eval_binary(op: BinaryOp, lhs: Node, rhs: Node) -> Result<Node, DeferredError> {
        let a = leaf_limbs(&lhs)?;
        let b = leaf_limbs(&rhs)?;
        Ok(Node::expression(Field0Handler::LEAF, encode_limbs(op.apply(a, b))))
    }

    fn leaf_from_u32s(limbs: [u32; 8]) -> Node {
        Node::expression(Field0Handler::LEAF, Payload::new(limbs.map(Felt::from_u32)))
    }

    fn leaf_from_low_u64(value: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value as u32;
        limbs[1] = (value >> 32) as u32;
        leaf_from_u32s(limbs)
    }

    #[test]
    fn add_small_values() {
        let out = eval_binary(BinaryOp::Add, leaf_from_low_u64(3), leaf_from_low_u64(5)).unwrap();
        assert_eq!(out.tag, Field0Handler::LEAF);
        assert_eq!(out, leaf_from_low_u64(8));
    }

    #[test]
    fn add_propagates_carry_across_limbs() {
        let mut a_limbs = [0u32; 8];
        a_limbs[0] = u32::MAX;
        let mut b_limbs = [0u32; 8];
        b_limbs[0] = 1;
        let out =
            eval_binary(BinaryOp::Add, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        let mut expected = [0u32; 8];
        expected[1] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn add_wraps_at_2_to_256() {
        let max = leaf_from_u32s([u32::MAX; 8]);
        let one = leaf_from_low_u64(1);
        let out = eval_binary(BinaryOp::Add, max, one).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn mul_small_values() {
        let out = eval_binary(BinaryOp::Mul, leaf_from_low_u64(6), leaf_from_low_u64(7)).unwrap();
        assert_eq!(out, leaf_from_low_u64(42));
    }

    #[test]
    fn mul_propagates_across_limbs() {
        // (2^32) * (2^32) = 2^64 — should land entirely in limb[2].
        let mut a_limbs = [0u32; 8];
        a_limbs[1] = 1;
        let b_limbs = a_limbs;
        let out =
            eval_binary(BinaryOp::Mul, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        let mut expected = [0u32; 8];
        expected[2] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn mul_truncates_overflow_above_2_to_256() {
        // 2^255 * 2 = 2^256 → 0 mod 2^256.
        let mut a_limbs = [0u32; 8];
        a_limbs[7] = 1 << 31;
        let two = leaf_from_low_u64(2);
        let out = eval_binary(BinaryOp::Mul, leaf_from_u32s(a_limbs), two).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn non_canonical_limb_errors() {
        // u32::MAX + 1 = 2^32 is outside the u32 range but still a valid Felt — must surface as
        // InvalidPayload when the leaf is decoded as an operand.
        let bad = Node::expression(
            Field0Handler::LEAF,
            Payload::new([
                Felt::new_unchecked(1u64 << 32),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
            ]),
        );
        let ok = leaf_from_low_u64(1);
        let err = eval_binary(BinaryOp::Add, bad, ok);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn non_leaf_operand_errors() {
        // Passing an op-tag as an operand tag means the caller didn't evaluate this side first.
        let a = Node::expression(Field0Handler::ADD, Payload::new([Felt::from_u32(0); 8]));
        let b = leaf_from_low_u64(1);
        let err = eval_binary(BinaryOp::Add, a, b);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }
}
