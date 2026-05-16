//! Canary integration test for the deferred-DAG public API.
//!
//! The [`Field0Handler`] reference schema is the canonical demonstration that
//! `miden_core::deferred`'s public surface is sufficient to build a real schema. Any breaking
//! change to that surface will break this test — exactly the early-warning signal we want.

use miden_core::{
    Felt,
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

    // Predicate verification: register interns the ASSERT_EQ node; evaluate returns true_node().
    let assertion =
        Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected));
    state.register(&schema, assertion.clone()).unwrap();
    let result = state.evaluate(&schema, assertion).unwrap();
    assert!(result.is_true_node());

    // 6 registered expression nodes + 1 ASSERT_EQ predicate node + 1 interned intermediate
    // canonical(add) = leaf(7). canonical(mul) collides with the pre-registered `expected`
    // (both leaf(35)), so net new from evaluate is 1 (leaf(7)).
    assert_eq!(state.nodes().len(), 8);
    assert!(state.contains(&leaf(7).digest()));
}

#[test]
fn predicate_mismatch_surfaces_as_error_on_evaluate() {
    let schema = Field0Handler;
    let mut state = DeferredState::new();
    let a = state.register(&schema, leaf(7)).unwrap();
    let b = state.register(&schema, leaf(8)).unwrap();
    let assertion = Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(a, b));
    // Register is a pure hint — succeeds even when the predicate doesn't hold.
    state.register(&schema, assertion.clone()).unwrap();
    // The mismatch surfaces only when we explicitly verify.
    let err = state.evaluate(&schema, assertion);
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn noop_schema_rejects_all_field0_nodes() {
    let schema = NoopSchema;
    let mut state = DeferredState::new();
    let err = state.register(&schema, leaf(0));
    assert!(matches!(err, Err(SchemaError::NoSchemaInstalled)));
}
