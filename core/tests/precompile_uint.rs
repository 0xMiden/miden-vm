//! Integration coverage for value, op, and predicate flows in the mock uint precompile.

mod common;

use std::sync::Arc;

use common::value;
use miden_core::{
    deferred::{DeferredState, Node, PrecompileError, PrecompileRegistry},
    testing::precompile::Uint,
};

// PUBLIC-API CANARY
// ================================================================================================

#[test]
fn end_to_end_register_evaluate_assert_extract() {
    let registry = Arc::new(PrecompileRegistry::default().with_precompile(Uint));
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();

    let a = state.register(value(3)).unwrap();
    let b = state.register(value(4)).unwrap();
    let c = state.register(value(5)).unwrap();
    let expected = state.register(value(35)).unwrap();
    let add = state.register(Node::join(Uint::add_tag(), a, b).unwrap()).unwrap();
    let mul = state.register(Node::join(Uint::mul_tag(), add, c).unwrap()).unwrap();

    let canonical = state.evaluate(mul).unwrap();
    assert_eq!(canonical, value(35));

    // Predicate verification: register materializes the eq node; evaluate returns Node::TRUE.
    let assertion = Node::join(Uint::eq_tag(), mul, expected).unwrap();
    let assertion_digest = state.register(assertion).unwrap();
    let result = state.evaluate(assertion_digest).unwrap();
    assert!(result.is_true_node());

    // Evaluating the tree materializes canonical(add)=value(7) into the durable node store.
    assert_eq!(state.evaluate(value(7).digest()).unwrap(), value(7));

    // Log the proven equality and round-trip the whole transcript.
    common::log_and_verify(
        &registry,
        &mut state,
        Node::join(Uint::eq_tag(), mul, expected).unwrap(),
    );
}

#[test]
fn empty_registry_rejects_all_uint_nodes() {
    let registry = Arc::new(PrecompileRegistry::default());
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    let err = state.register(value(0));
    assert!(matches!(err, Err(PrecompileError::InvalidNode)));
}

#[test]
fn new_state_pre_registers_uint_constants() {
    let registry = Arc::new(PrecompileRegistry::default().with_precompile(Uint));
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    // TRUE plus three uint constants: ZERO, ONE, P_MINUS_1.
    assert_eq!(state.evaluate(value(0).digest()).unwrap(), value(0));
    assert_eq!(state.evaluate(value(1).digest()).unwrap(), value(1));
    let p_minus_1 = Uint::value_node([u32::MAX; 8]);
    assert_eq!(state.evaluate(p_minus_1.digest()).unwrap(), p_minus_1);
}
