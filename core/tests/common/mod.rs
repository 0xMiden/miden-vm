//! Shared scaffolding for the deferred-DAG precompile integration tests.
//!
//! Houses the reference precompile implementations (`Uint`, `Group`, `Hash`, `Sig`) that
//! exercise `miden_core::deferred`'s public surface. These are not production precompiles
//! (those live in `miden-core-lib::precompiles`); they are deliberately minimal vehicles for
//! testing the framework itself. Each `core/tests/precompile_*.rs` integration test pulls
//! this in via `mod common;` and uses only the slice it needs.
#![allow(dead_code, unused_imports)]

pub mod precompile;

use miden_core::deferred::{DeferredState, Node, Payload, PrecompileRegistry, Tag};

/// Round-trip helper for the `precompile_*` suites.
///
/// Drives the precompile lifecycle — register `predicate`, evaluate it (it must reduce to the TRUE
/// sentinel), and log it as a transcript step — then asserts via [`assert_round_trips`] that the
/// accumulated state survives `to_wire` + `rehydrate` (which re-evaluates the predicate through
/// the precompile's own `reduce`).
pub fn log_and_verify(schema: &PrecompileRegistry, state: &mut DeferredState, predicate: Node) {
    let stmt_digest = state.register(schema, predicate.clone()).unwrap();
    assert!(
        state.evaluate(schema, predicate).unwrap().is_true_node(),
        "log_and_verify expects a predicate that reduces to the TRUE node",
    );
    let new_root = Node::and(state.root(), stmt_digest).digest();
    state.log(stmt_digest, new_root).unwrap();
    assert_round_trips(state, schema);
}

/// Assert that `state` survives a `to_wire` → `rehydrate` round-trip: the root matches and every
/// reproduced node agrees with the source. `rehydrate` already rejects danglers and re-evaluates
/// each predicate, so a dropped reachable node fails inside it before we compare.
pub fn assert_round_trips(state: &DeferredState, schema: &PrecompileRegistry) {
    let rehydrated = DeferredState::rehydrate(&state.to_wire(), schema).unwrap();
    assert_eq!(rehydrated.root(), state.root());
    assert!(
        rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
        "wire round-trip changed a reachable node",
    );
}
