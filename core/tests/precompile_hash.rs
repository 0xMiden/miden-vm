//! Integration coverage for chunk reduction and digest equality in the mock hash precompile.

mod common;

use common::register_and_evaluate;
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
    (
        PrecompileRegistry::default().with_precompile(Hash),
        DeferredState::new(usize::MAX),
    )
}

#[test]
fn preimage_reduces_to_known_digest_and_eq_predicate_passes() {
    let registry = PrecompileRegistry::default().with_precompile(Uint).with_precompile(Hash);
    let mut state = DeferredState::new(usize::MAX);
    registry.init(&mut state).unwrap();

    // Build a 64-byte preimage (two 32-byte chunks) and the digest the mock hash should yield.
    let preimage_chunks = chunks(2);
    let expected_digest_felts = Hash::hash(&preimage_chunks);
    let expected_digest = Hash::digest_node(expected_digest_felts);

    let h_expected = state.register(&registry, expected_digest.clone()).unwrap();
    let h_preimage = state.register(&registry, Hash::preimage_node(64, preimage_chunks)).unwrap();

    // Evaluating the preimage produces the digest leaf.
    let canonical = state.evaluate(&registry, h_preimage).unwrap();
    assert_eq!(canonical, expected_digest);

    // eq predicate ties the preimage's hash to the pre-registered expected digest.
    let result =
        register_and_evaluate(&registry, &mut state, Hash::eq_node(h_preimage, h_expected));
    assert!(result.is_true_node());

    // Log the proven equality and round-trip the transcript (chunk-bodied preimage included).
    common::log_and_verify(&registry, &mut state, Hash::eq_node(h_preimage, h_expected));
}

#[test]
fn preimage_with_partial_last_chunk_is_handled_by_caller_padding() {
    // n_bytes=40 → ceil(40/32)=2 chunks. The framework just sees 2 chunks; whether the second
    // chunk is partially zero-padded is the caller's convention.
    let (registry, mut state) = fresh();
    let last_chunk: [Felt; 8] =
        [Felt::from_u32(0xab), Felt::from_u32(0xcd), ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];
    let preimage_chunks = vec![[Felt::from_u32(1); 8], last_chunk];
    let expected = Hash::digest_node(Hash::hash(&preimage_chunks));
    let canonical =
        register_and_evaluate(&registry, &mut state, Hash::preimage_node(40, preimage_chunks));
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
    assert!(Hash.decode([Felt::from_u32(Hash::PREIMAGE_TAG_ID), ZERO, ZERO]).is_none());
    assert!(Hash.decode([Felt::from_u32(99), ZERO, ZERO]).is_none());
}

#[test]
fn eq_predicate_errors_on_mismatch() {
    let (registry, mut state) = fresh();
    let data = chunks(1);
    let wrong = Hash::digest_node([Felt::from_u32(0xdead); 8]);
    let h_wrong = state.register(&registry, wrong).unwrap();
    let h_preimage = state.register(&registry, Hash::preimage_node(32, data)).unwrap();
    let eq_digest = state.register(&registry, Hash::eq_node(h_preimage, h_wrong)).unwrap();
    let err = state.evaluate(&registry, eq_digest);
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}
