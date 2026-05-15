//! Canary integration test for the deferred-DAG public API.
//!
//! The [`Field0Handler`] reference schema is the canonical demonstration that
//! `miden_core::deferred`'s public surface is sufficient to build a real schema. Any breaking
//! change to that surface will break this test — exactly the early-warning signal we want.

use miden_core::{
    Felt, Word, ZERO,
    crypto::hash::Poseidon2,
    deferred::{DeferredState, Field0Handler, Node, NoopSchema, Payload, SchemaError},
};

fn leaf(low: u64) -> Node {
    let mut limbs = [Felt::from_u32(0); 8];
    limbs[0] = Felt::from_u32(low as u32);
    limbs[1] = Felt::from_u32((low >> 32) as u32);
    Node::expression(Field0Handler::LEAF, Payload::new(limbs))
}

#[test]
fn end_to_end_register_evaluate_assert_extract() {
    let schema = Field0Handler;
    let mut state = DeferredState::new();

    let a = state.register(&schema, leaf(3)).unwrap();
    let b = state.register(&schema, leaf(4)).unwrap();
    let c = state.register(&schema, leaf(5)).unwrap();
    let expected = state.register(&schema, leaf(35)).unwrap();
    let add = state
        .register(&schema, Node::expression(Field0Handler::ADD, Payload::binary_op(a, b)))
        .unwrap();
    let mul = state
        .register(&schema, Node::expression(Field0Handler::MUL, Payload::binary_op(add, c)))
        .unwrap();

    let canonical = state.evaluate(&schema, state.get(&mul).unwrap().clone()).unwrap();
    assert_eq!(canonical, leaf(35));

    state
        .register(
            &schema,
            Node::assertion(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected)),
        )
        .unwrap();

    assert_eq!(state.assertions().len(), 1);
    let witness = state.extract_witness();
    // 6 registered expression nodes + 1 interned intermediate canonical(add) = leaf(7).
    // canonical(mul) collides with the pre-registered `expected` (both leaf(35)), so net new = 1.
    assert_eq!(witness.nodes.len(), 7);
    assert!(witness.nodes.iter().any(|(d, _)| *d == leaf(7).digest()));
}

#[test]
fn assertion_mismatch_surfaces_as_error() {
    let schema = Field0Handler;
    let mut state = DeferredState::new();
    let a = state.register(&schema, leaf(7)).unwrap();
    let b = state.register(&schema, leaf(8)).unwrap();
    let err = state
        .register(&schema, Node::assertion(Field0Handler::ASSERT_EQ, Payload::binary_op(a, b)));
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn transcript_folds_assertion_digests_in_order() {
    let schema = Field0Handler;
    let mut state = DeferredState::new();
    assert_eq!(state.transcript(), Word::new([ZERO; 4]));

    let a = state.register(&schema, leaf(1)).unwrap();
    let a_eq_a = Node::assertion(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a));
    state.register(&schema, a_eq_a.clone()).unwrap();
    let after_first = Poseidon2::merge(&[Word::new([ZERO; 4]), a_eq_a.digest()]);
    assert_eq!(state.transcript(), after_first);

    let b = state.register(&schema, leaf(2)).unwrap();
    let b_eq_b = Node::assertion(Field0Handler::ASSERT_EQ, Payload::binary_op(b, b));
    state.register(&schema, b_eq_b.clone()).unwrap();
    assert_eq!(state.transcript(), Poseidon2::merge(&[after_first, b_eq_b.digest()]));
}

#[test]
fn noop_schema_rejects_all_field0_nodes() {
    let schema = NoopSchema;
    let mut state = DeferredState::new();
    let err = state.register(&schema, leaf(0));
    assert!(matches!(err, Err(SchemaError::NoSchemaInstalled)));
}
