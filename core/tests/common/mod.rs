//! Shared helpers for deferred precompile integration tests.
//!
//! These keep each suite focused on the precompile behavior it is proving, while centralizing the
//! wire round-trip checks that guard transcript verification.
#![allow(dead_code, unused_imports)]

use miden_core::{
    deferred::{DeferredState, Node, Payload, PrecompileRegistry, Tag},
    testing::precompile::Uint,
};

/// Builds a uint leaf carrying `low` in its least-significant limbs.
pub fn leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::leaf_node(limbs)
}

/// Registers, verifies, logs, and round-trips a predicate expected to reduce to TRUE.
pub fn log_and_verify(registry: &PrecompileRegistry, state: &mut DeferredState, predicate: Node) {
    let stmt_digest = state.register(registry, predicate).unwrap();
    let root = state.append_statement(registry, stmt_digest).unwrap();
    assert_ne!(root, miden_core::deferred::TRUE_DIGEST);
    assert_round_trips(state, registry);
}

/// Asserts that wire round-tripping preserves the verified transcript root and nodes.
pub fn assert_round_trips(state: &DeferredState, registry: &PrecompileRegistry) {
    let wire = state.to_wire(registry).unwrap();
    let rehydrated = DeferredState::from_wire(&wire, registry, usize::MAX).unwrap();
    assert_eq!(rehydrated.root(), state.root());
    assert_eq!(
        rehydrated.to_wire(registry).unwrap(),
        wire,
        "wire round-trip changed canonical output",
    );
}

/// Registers a node and evaluates it by digest.
pub fn register_and_evaluate(
    registry: &PrecompileRegistry,
    state: &mut DeferredState,
    node: Node,
) -> Node {
    let digest = state.register(registry, node).unwrap();
    state.evaluate(registry, digest).unwrap()
}
