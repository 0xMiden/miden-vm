//! Integration coverage for the `Hash` reference precompile: chunk-bodied preimage → digest
//! leaf, the `eq` predicate, and multi-app composition with `Uint`.

mod common;

use common::precompile::{hash::Hash, uint::Uint};
use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredState, NodeType, Precompile, PrecompileSchema, PrecompileTag, SchemaError, TRUE_TAG,
    },
};

fn chunks(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

fn fresh() -> (PrecompileSchema, DeferredState) {
    (PrecompileSchema::single(Hash), DeferredState::new())
}

// END-TO-END (relocated from deferred_mock_hash.rs)
// ================================================================================================

#[test]
fn preimage_reduces_to_known_digest_and_eq_predicate_passes() {
    let schema = PrecompileSchema::new([
        Box::new(Uint) as Box<dyn Precompile>,
        Box::new(Hash) as Box<dyn Precompile>,
    ]);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();

    // Build a 64-byte preimage (two 32-byte chunks) and the digest the mock hash should yield.
    let preimage_chunks = chunks(2);
    let expected_digest_felts = Hash::hash(&preimage_chunks);
    let expected_digest = Hash::digest_node(expected_digest_felts);

    let h_expected = state.register(&schema, expected_digest.clone()).unwrap();
    let h_preimage = state
        .register(&schema, Hash::preimage_node(64, preimage_chunks.clone()))
        .unwrap();

    // Evaluating the preimage produces the digest leaf.
    let canonical = state.evaluate(&schema, state.get(&h_preimage).unwrap().clone()).unwrap();
    assert_eq!(canonical, expected_digest);

    // eq predicate ties the preimage's hash to the pre-registered expected digest.
    let result = state.evaluate(&schema, Hash::eq_node(h_preimage, h_expected)).unwrap();
    assert!(result.is_true_node());
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

// CAPABILITY UNIT TESTS (relocated from the old in-lib `mock_hash` unit tests)
// ================================================================================================

#[test]
fn n_chunks_rounds_up() {
    assert_eq!(Hash::n_chunks(0), 0);
    assert_eq!(Hash::n_chunks(1), 1);
    assert_eq!(Hash::n_chunks(31), 1);
    assert_eq!(Hash::n_chunks(32), 1);
    assert_eq!(Hash::n_chunks(33), 2);
    assert_eq!(Hash::n_chunks(64), 2);
    assert_eq!(Hash::n_chunks(65), 3);
}

#[test]
fn decode_preimage_extracts_chunk_count_from_imm() {
    let info = Hash
        .decode(PrecompileTag([Felt::from_u32(Hash::PREIMAGE_TAG_ID), Felt::from_u32(65), ZERO]))
        .unwrap();
    assert!(matches!(info.node_type, NodeType::Chunks(3)));
    assert_eq!(info.evaluates_to, Hash::digest_tag());
}

#[test]
fn decode_digest_is_self_evaluating_value() {
    let info = Hash
        .decode(PrecompileTag([Felt::from_u32(Hash::DIGEST_TAG_ID), ZERO, ZERO]))
        .unwrap();
    assert!(matches!(info.node_type, NodeType::Value));
    assert_eq!(info.evaluates_to, Hash::digest_tag());
}

#[test]
fn decode_eq_is_binary_predicate() {
    let info = Hash
        .decode(PrecompileTag([Felt::from_u32(Hash::EQ_TAG_ID), ZERO, ZERO]))
        .unwrap();
    assert!(matches!(info.node_type, NodeType::Binary));
    assert_eq!(info.evaluates_to, TRUE_TAG);
}

#[test]
fn decode_unknown_discriminant_rejected() {
    let err = Hash.decode(PrecompileTag([Felt::from_u32(99), ZERO, ZERO]));
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
}

#[test]
fn decode_rejects_imm_on_non_preimage() {
    let err =
        Hash.decode(PrecompileTag([Felt::from_u32(Hash::DIGEST_TAG_ID), Felt::from_u32(1), ZERO]));
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
    let err =
        Hash.decode(PrecompileTag([Felt::from_u32(Hash::EQ_TAG_ID), Felt::from_u32(1), ZERO]));
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
}

#[test]
fn preimage_reduces_to_digest_leaf() {
    let (schema, mut state) = fresh();
    let data = chunks(2);
    let expected = Hash::digest_node(Hash::hash(&data));
    let node = Hash::preimage_node(64, data);
    let canonical = state.evaluate(&schema, node).unwrap();
    assert_eq!(canonical, expected);
    assert!(state.contains(&expected.digest()));
}

#[test]
fn digest_leaf_is_self_evaluating() {
    let (schema, mut state) = fresh();
    let leaf = Hash::digest_node([Felt::from_u32(7); 8]);
    let h = state.register(&schema, leaf.clone()).unwrap();
    let canonical = state.evaluate(&schema, state.get(&h).unwrap().clone()).unwrap();
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
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn empty_preimage_reduces_to_zero_digest() {
    // n_bytes=0 means n_chunks=0; mock-hash of zero chunks is the zero accumulator.
    let (schema, mut state) = fresh();
    let node = Hash::preimage_node(0, Vec::new());
    let canonical = state.evaluate(&schema, node).unwrap();
    assert_eq!(canonical, Hash::digest_node([ZERO; 8]));
}

#[test]
fn composite_with_hash_dispatches() {
    // Sanity: app_id-based routing works in a composite holding only Hash.
    let schema = PrecompileSchema::new([Box::new(Hash) as Box<dyn Precompile>]);
    let mut state = DeferredState::new();
    let data = chunks(1);
    let canonical = state.evaluate(&schema, Hash::preimage_node(32, data.clone())).unwrap();
    assert_eq!(canonical, Hash::digest_node(Hash::hash(&data)));
}
