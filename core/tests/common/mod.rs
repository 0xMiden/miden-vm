//! Shared helpers for deferred precompile integration tests.
//!
//! These keep each suite focused on the precompile behavior it is proving, while centralizing the
//! wire round-trip checks that guard transcript verification.
#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use miden_core::{
    deferred::{DeferredState, Node, Payload, PrecompileRegistry, Tag},
    testing::precompile::Uint,
};

/// Builds a uint value carrying `low` in its least-significant limbs.
pub fn value(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::value_node(limbs)
}

/// Registers, verifies, logs, and round-trips a predicate expected to evaluate to TRUE.
pub fn log_and_verify(
    registry: &Arc<PrecompileRegistry>,
    state: &mut DeferredState,
    predicate: Node,
) {
    let stmt_digest = state.register(predicate).unwrap();
    let root = state.log_statement(stmt_digest).unwrap();
    assert_ne!(root, miden_core::deferred::TRUE_DIGEST);
    assert_round_trips(state, registry);
}

/// Asserts that wire round-tripping preserves the verified root and canonical wire nodes.
pub fn assert_round_trips(state: &DeferredState, registry: &Arc<PrecompileRegistry>) {
    let wire = state.to_wire().unwrap();
    let rehydrated = DeferredState::from_wire(Arc::clone(registry), &wire, usize::MAX).unwrap();
    assert_eq!(rehydrated.root(), state.root());
    assert_eq!(rehydrated.to_wire().unwrap(), wire, "wire round-trip changed canonical output",);
}

/// Registers a node and evaluates it by digest.
pub fn register_and_evaluate(
    _registry: &Arc<PrecompileRegistry>,
    state: &mut DeferredState,
    node: Node,
) -> Node {
    let digest = state.register(node).unwrap();
    state.evaluate(digest).unwrap()
}
