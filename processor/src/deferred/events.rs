//! Helpers and integration tests for the deferred-DAG event flow.
//!
//! The actual register-and-classify flow lives on
//! [`DeferredState::register`](super::DeferredState::register). This module just exposes a
//! payload-construction helper and integration tests for the unified register path.

use miden_core::{Felt, deferred::{Digest, Payload}};

// PAYLOAD HELPERS
// ================================================================================================

/// Build the payload of a binary-op node from two child digests in `(lhs, rhs)` order.
///
/// Same convention is reused by assertion-kind nodes, which encode `lhs_digest || rhs_digest`
/// in their 8-felt payload.
pub fn binary_op_payload(lhs: Digest, rhs: Digest) -> Payload {
    let mut felts: [Felt; 8] = [Felt::from_u32(0); 8];
    felts[0..4].copy_from_slice(lhs.as_elements());
    felts[4..8].copy_from_slice(rhs.as_elements());
    Payload::new(felts)
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt, Word,
        deferred::{Node, Payload, Tag, hash_node},
    };

    use super::*;
    use crate::deferred::{
        DeferredState,
        handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler},
        schema::SchemaError,
    };

    fn field0_leaf(low: u64) -> (Tag, Payload) {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        (FIELD0_LEAF, Payload::new(limbs))
    }

    #[test]
    fn register_leaf_stores_node_and_returns_correct_digest() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (tag, payload) = field0_leaf(7);

        let digest = state.register(&mut schema, tag, payload).unwrap();

        assert_eq!(digest, hash_node(tag, &payload));
        assert_eq!(state.get(&digest).unwrap(), &Node::new(tag, payload));
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        // A tag in Field0's prefix but with an unknown op-suffix: rejected as InvalidNode.
        let payload = Payload::new([Felt::from_u32(0); 8]);
        let bad_tag: Tag = [
            FIELD0_LEAF[0],
            FIELD0_LEAF[1],
            Felt::from_u32(99),
            miden_core::ZERO,
        ];
        let err = state.register(&mut schema, bad_tag, payload);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();

        let op_payload = binary_op_payload(a, b);
        let digest = state.register(&mut schema, FIELD0_ADD, op_payload).unwrap();

        assert!(state.contains(&digest));
    }

    #[test]
    fn assert_eq_succeeds_when_values_match() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (sum_tag, sum_payload) = field0_leaf(7);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();
        let sum = state.register(&mut schema, sum_tag, sum_payload).unwrap();
        let add =
            state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();

        // Assert (a + b) == sum. Registered as an assertion-tagged node.
        state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(add, sum))
            .unwrap();
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn assert_eq_fails_on_mismatch() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (wrong_tag, wrong_payload) = field0_leaf(99);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();
        let wrong = state.register(&mut schema, wrong_tag, wrong_payload).unwrap();
        let add =
            state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();

        let err =
            state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(add, wrong));
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
        // The assertion is still recorded (transcript folds eagerly; the mismatch is the only
        // observable consequence at this cycle).
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn assert_eq_missing_node_errors() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(1);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);

        let err =
            state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(a, dangling));
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then assert equal to a leaf holding (a + b) * c precomputed.
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (c_tag, c_payload) = field0_leaf(5);
        let (expected_tag, expected_payload) = field0_leaf(35); // (3 + 4) * 5
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();
        let c = state.register(&mut schema, c_tag, c_payload).unwrap();
        let expected =
            state.register(&mut schema, expected_tag, expected_payload).unwrap();
        let add =
            state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
        let mul =
            state.register(&mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();

        state
            .register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(mul, expected))
            .unwrap();
        assert_eq!(state.assertions().len(), 1);
    }
}
