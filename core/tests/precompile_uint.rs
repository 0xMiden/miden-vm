//! Integration coverage for value, op, and predicate flows in the mock uint precompile.

mod common;

use common::leaf;
use miden_core::{
    deferred::{DeferredState, Node, PrecompileError, PrecompileRegistry},
    testing::precompile::Uint,
};

// PUBLIC-API CANARY
// ================================================================================================

#[test]
fn end_to_end_register_evaluate_assert_extract() {
    let registry = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();

    let a = state.register(&registry, leaf(3)).unwrap();
    let b = state.register(&registry, leaf(4)).unwrap();
    let c = state.register(&registry, leaf(5)).unwrap();
    let expected = state.register(&registry, leaf(35)).unwrap();
    let add = state.register(&registry, Node::join(Uint::add_tag(), a, b)).unwrap();
    let mul = state.register(&registry, Node::join(Uint::mul_tag(), add, c)).unwrap();

    let canonical = state.evaluate_digest(&registry, mul).unwrap();
    assert_eq!(canonical, leaf(35));

    // Predicate verification: register interns the eq node; evaluate returns Node::TRUE.
    let assertion = Node::join(Uint::eq_tag(), mul, expected);
    state.register(&registry, assertion.clone()).unwrap();
    let result = state.evaluate_node(&registry, assertion).unwrap();
    assert!(result.is_true_node());

    // 6 registered expression nodes + 1 registered eq predicate, plus canonicals interned by
    // evaluate: canonical(add)=leaf(7) and canonical(assertion)=TRUE.
    assert_eq!(state.nodes().len(), 9);
    assert!(state.contains(&leaf(7).digest()));

    // Log the proven equality and round-trip the whole transcript.
    common::log_and_verify(&registry, &mut state, Node::join(Uint::eq_tag(), mul, expected));
}

#[test]
fn empty_registry_rejects_all_uint_nodes() {
    let registry = PrecompileRegistry::default();
    let mut state = DeferredState::new();
    let err = state.register(&registry, leaf(0));
    assert!(matches!(err, Err(PrecompileError::InvalidNode)));
}

#[test]
fn init_pre_registers_uint_constants() {
    let registry = PrecompileRegistry::default().with_precompile(Uint);
    let mut state = DeferredState::new();
    registry.init(&mut state).unwrap();
    // TRUE plus three uint constants: ZERO, ONE, P_MINUS_1.
    assert_eq!(state.nodes().len(), 4);
    assert!(state.contains(&leaf(0).digest()));
    assert!(state.contains(&leaf(1).digest()));
    assert!(state.contains(&Uint::leaf_node([u32::MAX; 8]).digest()));
}
