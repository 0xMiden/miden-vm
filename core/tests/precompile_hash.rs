//! Integration coverage for the `Hash` reference precompile: chunk-bodied preimage → digest
//! leaf, the `eq` predicate, and multi-precompile composition with `Uint`.

mod common;

use miden_core::{
    Felt, ZERO,
    deferred::{DeferredState, NodeType, Precompile, PrecompileError, PrecompileRegistry},
    testing::precompile::{Hash, Uint},
};

fn chunks(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

fn fresh() -> (PrecompileRegistry, DeferredState) {
    (PrecompileRegistry::default().with_precompile(Hash), DeferredState::new())
}

#[test]
fn preimage_reduces_to_known_digest_and_eq_predicate_passes() {
    let schema = PrecompileRegistry::default().with_precompile(Uint).with_precompile(Hash);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();

    // Build a 64-byte preimage (two 32-byte chunks) and the digest the mock hash should yield.
    let preimage_chunks = chunks(2);
    let expected_digest_felts = Hash::hash(&preimage_chunks);
    let expected_digest = Hash::digest_node(expected_digest_felts);

    let h_expected = state.register(&schema, expected_digest.clone()).unwrap();
    let h_preimage = state.register(&schema, Hash::preimage_node(64, preimage_chunks)).unwrap();

    // Evaluating the preimage produces the digest leaf.
    let canonical = state.evaluate_digest(&schema, h_preimage).unwrap();
    assert_eq!(canonical, expected_digest);

    // eq predicate ties the preimage's hash to the pre-registered expected digest.
    let result = state.evaluate(&schema, Hash::eq_node(h_preimage, h_expected)).unwrap();
    assert!(result.is_true_node());

    // Log the proven equality and round-trip the transcript (chunk-bodied preimage included).
    common::log_and_verify(&schema, &mut state, Hash::eq_node(h_preimage, h_expected));
}

#[test]
fn preimage_with_partial_last_chunk_is_handled_by_caller_padding() {
    // n_bytes=40 → ceil(40/32)=2 chunks. The framework just sees 2 chunks; whether the second
    // chunk is partially zero-padded is the caller's convention.
    let (schema, mut state) = fresh();
    let last_chunk: [Felt; 8] =
        [Felt::from_u32(0xab), Felt::from_u32(0xcd), ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];
    let preimage_chunks = vec![[Felt::from_u32(1); 8], last_chunk];
    let expected = Hash::digest_node(Hash::hash(&preimage_chunks));
    let canonical = state.evaluate(&schema, Hash::preimage_node(40, preimage_chunks)).unwrap();
    assert_eq!(canonical, expected);
}

#[test]
fn n_chunks_rounds_up() {
    // `n_chunks` is the raw `div_ceil` helper; a 0 result is what `decode` rejects downstream.
    assert_eq!(Hash::n_chunks(0), 0);
    assert_eq!(Hash::n_chunks(1), 1);
    assert_eq!(Hash::n_chunks(31), 1);
    assert_eq!(Hash::n_chunks(32), 1);
    assert_eq!(Hash::n_chunks(33), 2);
    assert_eq!(Hash::n_chunks(64), 2);
    assert_eq!(Hash::n_chunks(65), 3);
}

#[test]
fn decode_classifies_each_discriminant() {
    assert!(matches!(
        Hash.decode([Felt::from_u32(Hash::PREIMAGE_TAG_ID), Felt::from_u32(65), ZERO]),
        Some(NodeType::Chunks(n)) if n.get() == 3
    ));
    assert!(matches!(
        Hash.decode([Felt::from_u32(Hash::DIGEST_TAG_ID), ZERO, ZERO]),
        Some(NodeType::Value)
    ));
    assert!(matches!(
        Hash.decode([Felt::from_u32(Hash::EQ_TAG_ID), ZERO, ZERO]),
        Some(NodeType::Join)
    ));
    assert!(Hash.decode([Felt::from_u32(99), ZERO, ZERO]).is_none());
}

#[test]
fn preimage_reduces_to_digest_leaf() {
    let (schema, mut state) = fresh();
    let data = chunks(2);
    let expected = Hash::digest_node(Hash::hash(&data));
    let node = Hash::preimage_node(64, data);
    let canonical = state.evaluate(&schema, node).unwrap();
    assert_eq!(canonical, expected);
}

#[test]
fn digest_leaf_is_self_evaluating() {
    let (schema, mut state) = fresh();
    let leaf = Hash::digest_node([Felt::from_u32(7); 8]);
    let h = state.register(&schema, leaf.clone()).unwrap();
    let canonical = state.evaluate_digest(&schema, h).unwrap();
    assert_eq!(canonical, leaf);
}

#[test]
fn eq_predicate_matches_preimage_against_known_digest() {
    let (schema, mut state) = fresh();
    let data = chunks(2);
    let known = Hash::digest_node(Hash::hash(&data));
    let h_known = state.register(&schema, known).unwrap();
    let h_preimage = state.register(&schema, Hash::preimage_node(64, data)).unwrap();
    let result = state.evaluate(&schema, Hash::eq_node(h_preimage, h_known)).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn eq_predicate_errors_on_mismatch() {
    let (schema, mut state) = fresh();
    let data = chunks(1);
    let wrong = Hash::digest_node([Felt::from_u32(0xdead); 8]);
    let h_wrong = state.register(&schema, wrong).unwrap();
    let h_preimage = state.register(&schema, Hash::preimage_node(32, data)).unwrap();
    let err = state.evaluate(&schema, Hash::eq_node(h_preimage, h_wrong));
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn zero_byte_preimage_decodes_to_none() {
    // n_bytes=0 derives zero chunks; `NonZeroU32` makes that unrepresentable, so decode rejects
    // the tag rather than producing a `Chunks(0)`. An empty preimage can never be registered.
    assert!(Hash.decode([Felt::from_u32(Hash::PREIMAGE_TAG_ID), ZERO, ZERO]).is_none());
}

#[test]
fn composite_with_hash_dispatches() {
    // Sanity: id-based routing works in a composite holding only Hash.
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();
    let data = chunks(1);
    let canonical = state.evaluate(&schema, Hash::preimage_node(32, data.clone())).unwrap();
    assert_eq!(canonical, Hash::digest_node(Hash::hash(&data)));
}
