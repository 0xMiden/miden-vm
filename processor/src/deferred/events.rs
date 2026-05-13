//! Schema-driven helper backing the single deferred-DAG system event handler.
//!
//! [`register_node`] is called from the [`SystemEvent::DeferredRegister`](
//! miden_core::events::SystemEvent::DeferredRegister) dispatch arm in
//! `processor::fast::basic_block::sys_event_handlers`. It is exposed as a free function so the
//! handler can split-borrow the deferred state and the schema from the processor.
//!
//! Stack layout (position 0 is top, event_id already consumed by the caller):
//! positions `1..5` hold the tag felts, positions `5..13` hold the payload felts. The schema's
//! `is_valid` classifies the resulting node as either an [`NodeType::Expression`] (inserted
//! into the DAG) or an [`NodeType::Assertion`] (appended to the assertion list, folded into the
//! transcript, and verified via [`Schema::assert`]).

use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{Digest, Node, Payload, Tag, hash_node},
};

use super::{
    schema::{NodeType, Schema, SchemaError},
    state::DeferredState,
    transaction::{DeferredMutation, HandlerTransaction},
};

// REGISTER
// ================================================================================================

/// Decode a `(tag, payload)` pair, ask the schema to classify the node, and route it accordingly.
///
/// - `Some(NodeType::Expression)` inserts the node into the DAG and returns its digest.
/// - `Some(NodeType::Assertion)` appends the node to the assertion list (folding it into the
///   running transcript), then asks the schema to verify it. A schema-reported mismatch
///   surfaces as [`SchemaError::AssertionFailed`]; the assertion stays recorded (the
///   transcript is committed regardless — execution dies on mismatch and post-mismatch state
///   isn't observable).
/// - `None` is rejected as [`SchemaError::InvalidNode`].
pub fn register_node(
    state: &mut DeferredState,
    schema: &mut dyn Schema,
    tag: Tag,
    payload: Payload,
) -> Result<Digest, SchemaError> {
    let node = Node::new(tag, payload);
    let digest = hash_node(tag, &payload);

    match schema.is_valid(&node) {
        None => Err(SchemaError::InvalidNode),
        Some(NodeType::Expression) => {
            state.apply(&HandlerTransaction {
                deferred: alloc::vec![DeferredMutation::InsertNode { digest, node }],
                vm: Vec::new(),
            })?;
            Ok(digest)
        },
        Some(NodeType::Assertion) => {
            state.apply(&HandlerTransaction {
                deferred: alloc::vec![DeferredMutation::AppendAssertion(node)],
                vm: Vec::new(),
            })?;
            if schema.assert(state, tag, node)? {
                return Err(SchemaError::AssertionFailed);
            }
            Ok(digest)
        },
    }
}

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
        // A tag in Field0's prefix but with an unknown op-suffix: rejected as InvalidNode.
        let payload = Payload::new([Felt::from_u32(0); 8]);
        let bad_tag: Tag = [
            FIELD0_LEAF[0],
            FIELD0_LEAF[1],
            Felt::from_u32(99),
            miden_core::ZERO,
        ];
        let err = register_node(&mut state, &mut schema, bad_tag, payload);
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

        // Assert (a + b) == sum. Registered as an assertion-tagged node.
        register_node(&mut state, &mut schema, FIELD0_ASSERT_EQ, binary_op_payload(add, sum))
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
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        let wrong = register_node(&mut state, &mut schema, wrong_tag, wrong_payload).unwrap();
        let add =
            register_node(&mut state, &mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();

        let err = register_node(
            &mut state,
            &mut schema,
            FIELD0_ASSERT_EQ,
            binary_op_payload(add, wrong),
        );
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
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);

        let err = register_node(
            &mut state,
            &mut schema,
            FIELD0_ASSERT_EQ,
            binary_op_payload(a, dangling),
        );
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

        register_node(
            &mut state,
            &mut schema,
            FIELD0_ASSERT_EQ,
            binary_op_payload(mul, expected),
        )
        .unwrap();
        assert_eq!(state.assertions().len(), 1);
    }
}
