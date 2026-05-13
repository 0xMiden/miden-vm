//! Schema-driven helpers backing the deferred-DAG system event handlers.
//!
//! [`register_node`] and [`assert_eq`] are called from the
//! [`SystemEvent::DeferredRegisterLeaf`](miden_core::events::SystemEvent::DeferredRegisterLeaf) /
//! `DeferredRegisterOp` / `DeferredAssertEq` dispatch arms in
//! `processor::fast::basic_block::sys_event_handlers`. They are exposed as free functions so the
//! handlers can split-borrow the deferred state and the schema from the processor.
//!
//! v1 stack layout (position 0 is top, event_id already consumed by the caller):
//! - `RegisterLeaf` / `RegisterOp`: positions `1..5` hold tag felts, positions `5..13` hold
//!   payload felts.
//! - `AssertEq`: positions `1..5` hold tag felts, `5..9` hold `lhs_digest`, `9..13` hold
//!   `rhs_digest`.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{Digest, Node, Payload, Tag, hash_node},
};

use super::{
    schema::{Schema, SchemaError},
    state::DeferredState,
    transaction::{DeferredMutation, HandlerTransaction},
};

// REGISTER
// ================================================================================================

/// Decode a (tag, payload) from the stack, ask the schema to validate it, insert the resulting
/// node into the DAG, and return its digest.
///
/// The schema's `is_valid` is the only semantic gate. Tag-kind routing is no longer the
/// processor's concern — the schema knows what tags it claims and what payload shapes are
/// well-formed for each.
pub fn register_node(
    state: &mut DeferredState,
    schema: &mut dyn Schema,
    tag: Tag,
    payload: Payload,
) -> Result<Digest, SchemaError> {
    let node = Node::new(tag, payload);
    if !schema.is_valid(&node) {
        return Err(SchemaError::InvalidNode);
    }
    let digest = hash_node(tag, &payload);

    let txn = HandlerTransaction {
        deferred: alloc::vec![DeferredMutation::InsertNode { digest, node }],
        vm: Vec::new(),
    };
    state.apply(&txn)?;
    Ok(digest)
}

// ASSERT-EQ
// ================================================================================================

/// Drives an `AssertEq` event: pull both nodes from the DAG, ask the schema whether they
/// disagree, and record the assertion on success. A schema-reported mismatch surfaces as
/// [`SchemaError::AssertionFailed`]; evaluation failures propagate as the schema returned them.
pub fn assert_eq(
    state: &mut DeferredState,
    schema: &mut dyn Schema,
    tag: Tag,
    lhs_digest: Digest,
    rhs_digest: Digest,
) -> Result<(), SchemaError> {
    let lhs_node = *state.get(&lhs_digest).ok_or(SchemaError::MissingNode)?;
    let rhs_node = *state.get(&rhs_digest).ok_or(SchemaError::MissingNode)?;

    if schema.assert(state, lhs_node, rhs_node)? {
        return Err(SchemaError::AssertionFailed);
    }

    let txn = HandlerTransaction {
        deferred: alloc::vec![DeferredMutation::AppendAssertion(
            miden_core::deferred::Assertion::new(tag, lhs_digest, rhs_digest),
        )],
        vm: Vec::new(),
    };
    state.apply(&txn)?;
    Ok(())
}

// PAYLOAD HELPERS
// ================================================================================================

/// Build the payload of a binary-op node from two child digests in `(lhs, rhs)` order.
pub fn binary_op_payload(lhs: Digest, rhs: Digest) -> Payload {
    let mut felts: [Felt; 8] = [Felt::from_u32(0); 8];
    felts[0..4].copy_from_slice(lhs.as_elements());
    felts[4..8].copy_from_slice(rhs.as_elements());
    Payload::new(felts)
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word, deferred::Payload};

    use super::*;
    use crate::deferred::handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler};

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

        let digest = register_node(&mut state, &mut schema, tag, payload).unwrap();

        assert_eq!(digest, hash_node(tag, &payload));
        assert_eq!(state.get(&digest), Some(&Node::new(tag, payload)));
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        // The AssertEq tag is in Field0's prefix but is_valid rejects it for storage.
        let payload = Payload::new([Felt::from_u32(0); 8]);
        let err = register_node(&mut state, &mut schema, FIELD0_ASSERT_EQ, payload);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();

        let op_payload = binary_op_payload(a, b);
        let digest = register_node(&mut state, &mut schema, FIELD0_ADD, op_payload).unwrap();

        assert!(state.contains(&digest));
    }

    #[test]
    fn assert_eq_succeeds_when_values_match() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (sum_tag, sum_payload) = field0_leaf(7);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        let sum = register_node(&mut state, &mut schema, sum_tag, sum_payload).unwrap();
        let add =
            register_node(&mut state, &mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();

        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, add, sum).unwrap();
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn assert_eq_fails_on_mismatch() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (wrong_tag, wrong_payload) = field0_leaf(99);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        let wrong = register_node(&mut state, &mut schema, wrong_tag, wrong_payload).unwrap();
        let add =
            register_node(&mut state, &mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();

        let err = assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, add, wrong);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
        // Failed assertion is not recorded.
        assert!(state.assertions().is_empty());
    }

    #[test]
    fn assert_eq_missing_node_errors() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(1);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);

        let err = assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, a, dangling);
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
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        let c = register_node(&mut state, &mut schema, c_tag, c_payload).unwrap();
        let expected =
            register_node(&mut state, &mut schema, expected_tag, expected_payload).unwrap();
        let add =
            register_node(&mut state, &mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
        let mul =
            register_node(&mut state, &mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();

        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, mul, expected).unwrap();
        assert_eq!(state.assertions().len(), 1);
    }
}
