//! Framework state effects exercised through the reference precompiles.
//!
//! These tests use the mock precompiles as fixtures to prove deferred *framework* behavior — eager
//! registration, canonicalization, eval memos, minted helper nodes, and wire reconstruction — not
//! the precompiles' own arithmetic/hash/signature semantics.

use std::sync::Arc;

use miden_core::{
    Felt,
    deferred::{
        DataChunk, DeferredState, Digest, Node, PrecompileError, PrecompileRegistry, TRUE_DIGEST,
    },
    testing::precompile::{Group, Hash, Uint, mock_precompile_registry},
};

// HELPERS
// ================================================================================================

fn registry() -> Arc<PrecompileRegistry> {
    Arc::new(mock_precompile_registry())
}

fn state() -> (Arc<PrecompileRegistry>, DeferredState) {
    let registry = registry();
    let state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    (registry, state)
}

/// Builds a uint value carrying `low` in its least-significant limbs.
fn uint_value(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint::value_node(limbs)
}

/// Builds `n` distinct 8-felt data chunks.
fn hash_chunks(n: u32) -> Vec<DataChunk> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

/// Registers two coordinate values and the group element committing to them.
fn register_group(state: &mut DeferredState, x: u64, y: u64) -> Digest {
    let h_x = state.register(uint_value(x)).unwrap();
    let h_y = state.register(uint_value(y)).unwrap();
    state.register(Group::new_node(h_x, h_y)).unwrap()
}

/// Asserts eager registration stored the original node, its canonical form, and the memo linking
/// them.
fn assert_eval_effect(state: &DeferredState, original: &Node, canonical: &Node) {
    assert_eq!(state.node(&original.digest()), Some(original), "original node is durable");
    assert_eq!(state.node(&canonical.digest()), Some(canonical), "canonical node is durable");
    assert_eq!(state.eval(&original.digest()), Some(canonical.digest()), "eval memo links them");
}

/// Round-trips the root-reachable closure through wire, checking root equality and canonical
/// determinism.
fn assert_state_round_trips(state: &DeferredState, registry: &Arc<PrecompileRegistry>) {
    let wire = state.to_wire().unwrap();
    let rehydrated = DeferredState::from_wire(Arc::clone(registry), &wire, usize::MAX).unwrap();
    assert_eq!(rehydrated.root(), state.root(), "wire round-trip preserves the verified root");
    assert_eq!(rehydrated.to_wire().unwrap(), wire, "canonical wire output is deterministic");
}

/// Logs a TRUE-evaluating predicate into the root and proves the witness reconstructs from wire.
fn log_and_assert_round_trips(
    registry: &Arc<PrecompileRegistry>,
    state: &mut DeferredState,
    predicate: Node,
) {
    let stmt_digest = state.register(predicate).unwrap();
    let root = state.log_statement(stmt_digest).unwrap();
    assert_ne!(root, TRUE_DIGEST, "logging a statement advances the root past TRUE");
    assert_state_round_trips(state, registry);
}

// STATE EFFECTS
// ================================================================================================

#[test]
fn registering_value_op_stores_original_canonical_and_eval_memo() {
    // Registering an op node eagerly evaluates it: the original op, its canonical value, and the
    // memo linking them are all durable immediately, without an explicit `evaluate` call.
    let (_registry, mut state) = state();
    let a = state.register(uint_value(3)).unwrap();
    let b = state.register(uint_value(4)).unwrap();
    let add = Node::join(Uint::add_tag(), a, b).unwrap();
    let add_digest = state.register(add.clone()).unwrap();

    assert_eq!(add_digest, add.digest(), "register returns the original op digest");
    assert_eval_effect(&state, &add, &uint_value(7));
}

#[test]
fn registering_data_node_stores_original_canonical_and_eval_memo() {
    // A multi-chunk data node evaluates to a single canonical value; the original data node, the
    // canonical value, and the memo persist after registration.
    let (_registry, mut state) = state();
    let chunks = hash_chunks(2);
    let preimage = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks.clone());
    state.register(preimage.clone()).unwrap();

    assert_eval_effect(&state, &preimage, &Hash::digest_node(Hash::hash(&chunks)));
}

#[test]
fn registering_predicate_is_eager_for_success_and_failure() {
    // Predicate validation happens at registration time, not lazily at evaluation.
    let (_registry, mut state) = state();
    let a = state.register(uint_value(7)).unwrap();

    // A satisfied predicate memoizes to the seeded TRUE node.
    let ok = state.register(Node::join(Uint::eq_tag(), a, a).unwrap()).unwrap();
    assert_eq!(state.eval(&ok), Some(TRUE_DIGEST));
    assert_eq!(state.node(&TRUE_DIGEST), Some(&Node::TRUE));

    // A violated predicate is rejected eagerly; post-failure state is not inspected.
    let b = state.register(uint_value(8)).unwrap();
    let err = state.register(Node::join(Uint::eq_tag(), a, b).unwrap());
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn compound_canonical_mints_helper_nodes() {
    // `Group::add` mints new coordinate values during evaluation; the canonical group element
    // references those minted digests, and the minted values are durable helper nodes.
    let (_registry, mut state) = state();
    let g1 = register_group(&mut state, 3, 4);
    let g2 = register_group(&mut state, 10, 20);
    let add = Group::add_node(g1, g2);
    state.register(add.clone()).unwrap();

    let minted_x = uint_value(13);
    let minted_y = uint_value(24);
    assert_eval_effect(&state, &add, &Group::new_node(minted_x.digest(), minted_y.digest()));
    assert_eq!(
        state.node(&minted_x.digest()),
        Some(&minted_x),
        "minted x coordinate is durable"
    );
    assert_eq!(
        state.node(&minted_y.digest()),
        Some(&minted_y),
        "minted y coordinate is durable"
    );
}

#[test]
fn logged_predicate_round_trips_through_wire() {
    // The canonical integration check: a logged predicate built from mock precompile nodes produces
    // a deferred witness that fully reconstructs from wire.
    let (registry, mut state) = state();
    let g1 = register_group(&mut state, 3, 4);
    let g2 = register_group(&mut state, 10, 20);
    let sum = state.register(Group::add_node(g1, g2)).unwrap();
    let expected = register_group(&mut state, 13, 24);

    log_and_assert_round_trips(&registry, &mut state, Group::eq_node(sum, expected));
}
