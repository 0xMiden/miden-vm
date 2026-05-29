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
    let stmt_digest = state.register(registry, predicate.clone()).unwrap();
    assert!(
        state.evaluate_node(registry, predicate).unwrap().is_true_node(),
        "log_and_verify expects a predicate that reduces to the TRUE node",
    );
    let new_root = Node::and(state.root(), stmt_digest).digest();
    state.log(stmt_digest, new_root).unwrap();
    assert_round_trips(state, registry);
}

/// Asserts that wire round-tripping preserves the verified transcript root and nodes.
pub fn assert_round_trips(state: &DeferredState, registry: &PrecompileRegistry) {
    let wire = state.to_wire(registry).unwrap();
    let rehydrated = DeferredState::rehydrate(&wire, registry).unwrap();
    assert_eq!(rehydrated.root(), state.root());
    assert!(
        rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
        "wire round-trip changed a reachable node",
    );
}
