use miden_core::{
    Felt, Word, ZERO,
    deferred::{DeferredError, Node, Payload, Tag},
};

use crate::deferred::{
    schema::{NodeType, SchemaError},
    state::DeferredState,
    Schema,
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
///   - `0` — canonical leaf (payload is 8 u32-limbs)
///   - `1` — `add` op node (payload is `lhs_digest || rhs_digest`)
///   - `2` — `mul` op node (payload is `lhs_digest || rhs_digest`)
///   - `3` — equality-assertion marker (not storable as a node body)
#[derive(Debug, Default, Clone, Copy)]
pub struct Field0Handler;

// FIELD0 TAG CONSTANTS
// ================================================================================================

/// Type-family prefix shared by every Field0 tag.
const FIELD0_PREFIX: [Felt; 2] = [Felt::new_unchecked(1), Felt::new_unchecked(0)];

/// Tag for a canonical Field0 leaf.
pub const FIELD0_LEAF: Tag = [FIELD0_PREFIX[0], FIELD0_PREFIX[1], Felt::new_unchecked(0), ZERO];
/// Tag for a Field0 `add` op node.
pub const FIELD0_ADD: Tag = [FIELD0_PREFIX[0], FIELD0_PREFIX[1], Felt::new_unchecked(1), ZERO];
/// Tag for a Field0 `mul` op node.
pub const FIELD0_MUL: Tag = [FIELD0_PREFIX[0], FIELD0_PREFIX[1], Felt::new_unchecked(2), ZERO];
/// Tag for a Field0 `assert_eq` marker.
pub const FIELD0_ASSERT_EQ: Tag = [FIELD0_PREFIX[0], FIELD0_PREFIX[1], Felt::new_unchecked(3), ZERO];

impl Field0Handler {
    /// Reduce a binary op on two already-evaluated leaf operands to a new canonical leaf.
    fn eval_op(
        &self,
        op_tag: Tag,
        lhs: Node,
        rhs: Node,
    ) -> Result<Node, DeferredError> {
        if lhs.tag != FIELD0_LEAF || rhs.tag != FIELD0_LEAF {
            return Err(DeferredError::InvalidPayload);
        }
        let a = decode_limbs(&lhs.payload)?;
        let b = decode_limbs(&rhs.payload)?;
        let c = if op_tag == FIELD0_ADD {
            add_mod_2_256(a, b)
        } else if op_tag == FIELD0_MUL {
            mul_mod_2_256(a, b)
        } else {
            return Err(DeferredError::Unsupported);
        };
        Ok(Node::new(FIELD0_LEAF, encode_limbs(c)))
    }

    /// Split a binary-op payload into its two child digests in `(lhs, rhs)` order.
    fn binary_op_children(payload: &Payload) -> (Word, Word) {
        let lhs = Word::new([payload.0[0], payload.0[1], payload.0[2], payload.0[3]]);
        let rhs = Word::new([payload.0[4], payload.0[5], payload.0[6], payload.0[7]]);
        (lhs, rhs)
    }
}

impl Schema for Field0Handler {
    fn is_valid(&self, node: &Node) -> Option<NodeType> {
        if node.tag[0] != FIELD0_PREFIX[0] || node.tag[1] != FIELD0_PREFIX[1] {
            return None;
        }
        if node.tag == FIELD0_LEAF {
            // Leaf payloads must have u32-canonical limbs so they can be reduced.
            decode_limbs(&node.payload).ok().map(|_| NodeType::Expression)
        } else if node.tag == FIELD0_ADD || node.tag == FIELD0_MUL {
            // Op-node payloads are two child digests — opaque from this handler's POV.
            Some(NodeType::Expression)
        } else if node.tag == FIELD0_ASSERT_EQ {
            // Assertion-node payloads are `lhs_digest || rhs_digest`.
            Some(NodeType::Assertion)
        } else {
            None
        }
    }

    fn eval(&mut self, graph: &DeferredState, node: Node) -> Result<Node, SchemaError> {
        if node.tag == FIELD0_LEAF {
            return Ok(node);
        }
        if node.tag == FIELD0_ADD || node.tag == FIELD0_MUL {
            let (lhs_digest, rhs_digest) = Self::binary_op_children(&node.payload);
            let lhs_node = *graph.get(&lhs_digest).ok_or(SchemaError::MissingNode)?;
            let rhs_node = *graph.get(&rhs_digest).ok_or(SchemaError::MissingNode)?;
            let lhs = self.eval(graph, lhs_node)?;
            let rhs = self.eval(graph, rhs_node)?;
            return Ok(self.eval_op(node.tag, lhs, rhs)?);
        }
        if node.tag == FIELD0_ASSERT_EQ {
            let (lhs_digest, rhs_digest) = Self::binary_op_children(&node.payload);
            let lhs_node = *graph.get(&lhs_digest).ok_or(SchemaError::MissingNode)?;
            let rhs_node = *graph.get(&rhs_digest).ok_or(SchemaError::MissingNode)?;
            let lhs = self.eval(graph, lhs_node)?;
            let rhs = self.eval(graph, rhs_node)?;
            if lhs != rhs {
                return Err(SchemaError::AssertionFailed);
            }
            return Ok(node);
        }
        Err(SchemaError::InvalidNode)
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
    use super::*;

    fn leaf_from_u32s(limbs: [u32; 8]) -> Node {
        Node::new(FIELD0_LEAF, Payload::new(limbs.map(Felt::from_u32)))
    }

    fn leaf_from_low_u64(value: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value as u32;
        limbs[1] = (value >> 32) as u32;
        leaf_from_u32s(limbs)
    }

    #[test]
    fn add_small_values() {
        let h = Field0Handler;
        let out = h.eval_op(FIELD0_ADD, leaf_from_low_u64(3), leaf_from_low_u64(5)).unwrap();
        assert_eq!(out.tag, FIELD0_LEAF);
        assert_eq!(out, leaf_from_low_u64(8));
    }

    #[test]
    fn add_propagates_carry_across_limbs() {
        let h = Field0Handler;
        let mut a_limbs = [0u32; 8];
        a_limbs[0] = u32::MAX;
        let mut b_limbs = [0u32; 8];
        b_limbs[0] = 1;
        let out = h.eval_op(FIELD0_ADD, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        let mut expected = [0u32; 8];
        expected[1] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn add_wraps_at_2_to_256() {
        let h = Field0Handler;
        let max = leaf_from_u32s([u32::MAX; 8]);
        let one = leaf_from_low_u64(1);
        let out = h.eval_op(FIELD0_ADD, max, one).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn mul_small_values() {
        let h = Field0Handler;
        let out = h.eval_op(FIELD0_MUL, leaf_from_low_u64(6), leaf_from_low_u64(7)).unwrap();
        assert_eq!(out, leaf_from_low_u64(42));
    }

    #[test]
    fn mul_propagates_across_limbs() {
        let h = Field0Handler;
        // (2^32) * (2^32) = 2^64 — should land entirely in limb[2].
        let mut a_limbs = [0u32; 8];
        a_limbs[1] = 1;
        let b_limbs = a_limbs;
        let out = h.eval_op(FIELD0_MUL, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
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
        let out = h.eval_op(FIELD0_MUL, leaf_from_u32s(a_limbs), two).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn non_canonical_limb_errors() {
        let h = Field0Handler;
        // u32::MAX + 1 = 2^32 is outside the u32 range but still a valid Felt — must surface as
        // InvalidPayload when eval_op decodes the limbs.
        let bad = Node::new(
            FIELD0_LEAF,
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
        let err = h.eval_op(FIELD0_ADD, bad, ok);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn non_leaf_operand_errors() {
        let h = Field0Handler;
        // Passing an op-tag as an operand tag means the caller didn't evaluate this side first.
        let a = Node::new(FIELD0_ADD, leaf_from_low_u64(1).payload);
        let b = leaf_from_low_u64(1);
        let err = h.eval_op(FIELD0_ADD, a, b);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn unsupported_op_tag_errors() {
        let h = Field0Handler;
        let a = leaf_from_low_u64(1);
        let b = leaf_from_low_u64(1);
        // Passing FIELD0_LEAF as the op-tag is meaningless.
        let err = h.eval_op(FIELD0_LEAF, a, b);
        assert!(matches!(err, Err(DeferredError::Unsupported)));
    }
}
