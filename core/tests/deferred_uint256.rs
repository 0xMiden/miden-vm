//! Canary integration test for the deferred-DAG public API.
//!
//! The [`Uint256`] reference app and the [`PrecompileSchema`] composite are the canonical
//! demonstration that `miden_core::deferred`'s public surface is sufficient to build a real
//! schema. Any breaking change to that surface will break this test — exactly the early-warning
//! signal we want.

use miden_core::deferred::{
    DeferredState, Node, NoopSchema, Payload, PrecompileSchema, SchemaError, Uint256,
};

fn leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint256::leaf_node(limbs)
}

#[test]
fn end_to_end_register_evaluate_assert_extract() {
    let schema = PrecompileSchema::single(Uint256);
    let mut state = DeferredState::new();

    let a = state.register(&schema, leaf(3)).unwrap();
    let b = state.register(&schema, leaf(4)).unwrap();
    let c = state.register(&schema, leaf(5)).unwrap();
    let expected = state.register(&schema, leaf(35)).unwrap();
    let add = state
        .register(&schema, Node::expression(Uint256::add_tag(), Payload::binary_op(a, b)))
        .unwrap();
    let mul = state
        .register(&schema, Node::expression(Uint256::mul_tag(), Payload::binary_op(add, c)))
        .unwrap();

    let canonical = state.evaluate(&schema, state.get(&mul).unwrap().clone()).unwrap();
    assert_eq!(canonical, leaf(35));

    // Predicate verification: register interns the eq node; evaluate returns true_node().
    let assertion = Node::expression(Uint256::eq_tag(), Payload::binary_op(mul, expected));
    state.register(&schema, assertion.clone()).unwrap();
    let result = state.evaluate(&schema, assertion).unwrap();
    assert!(result.is_true_node());

    // 6 registered expression nodes + 1 eq predicate node + 1 interned intermediate
    // canonical(add) = leaf(7). canonical(mul) collides with the pre-registered `expected`
    // (both leaf(35)), so net new from evaluate is 1 (leaf(7)).
    assert_eq!(state.nodes().len(), 8);
    assert!(state.contains(&leaf(7).digest()));
}

#[test]
fn predicate_mismatch_surfaces_as_error_on_evaluate() {
    let schema = PrecompileSchema::single(Uint256);
    let mut state = DeferredState::new();
    let a = state.register(&schema, leaf(7)).unwrap();
    let b = state.register(&schema, leaf(8)).unwrap();
    let assertion = Node::expression(Uint256::eq_tag(), Payload::binary_op(a, b));
    // Register is a pure hint — succeeds even when the predicate doesn't hold.
    state.register(&schema, assertion.clone()).unwrap();
    // The mismatch surfaces only when we explicitly verify.
    let err = state.evaluate(&schema, assertion);
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn noop_schema_rejects_all_uint256_nodes() {
    let schema = NoopSchema;
    let mut state = DeferredState::new();
    let err = state.register(&schema, leaf(0));
    assert!(matches!(err, Err(SchemaError::NoSchemaInstalled)));
}

#[test]
fn boot_pre_registers_uint256_constants() {
    let schema = PrecompileSchema::single(Uint256);
    let mut state = DeferredState::new();
    schema.boot(&mut state);
    // Three constants: ZERO, ONE, P_MINUS_1.
    assert_eq!(state.nodes().len(), 3);
    assert!(state.contains(&leaf(0).digest()));
    assert!(state.contains(&leaf(1).digest()));
    assert!(state.contains(&Uint256::leaf_node([u32::MAX; 8]).digest()));
}
