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
pub fn log_and_verify(schema: &PrecompileRegistry, state: &mut DeferredState, predicate: Node) {
    let stmt_digest = state.register(schema, predicate.clone()).unwrap();
    assert!(
        state.evaluate_node(schema, predicate).unwrap().is_true_node(),
        "log_and_verify expects a predicate that reduces to the TRUE node",
    );
    let new_root = Node::and(state.root(), stmt_digest).digest();
    state.log(stmt_digest, new_root).unwrap();
    assert_round_trips(state, schema);
}

/// Asserts that wire round-tripping preserves the verified transcript root and nodes.
pub fn assert_round_trips(state: &DeferredState, schema: &PrecompileRegistry) {
    let wire = state.to_wire(schema).unwrap();
    let rehydrated = DeferredState::rehydrate(&wire, schema).unwrap();
    assert_eq!(rehydrated.root(), state.root());
    assert!(
        rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
        "wire round-trip changed a reachable node",
    );
}
