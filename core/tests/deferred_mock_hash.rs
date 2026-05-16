//! End-to-end integration: exercise `MockHash` alongside `Uint256` in a two-app
//! `PrecompileSchema`. Validates that chunk-bodied preimages reduce to digest leaves and that
//! the `eq` predicate ties an unknown preimage to a known digest.

use miden_core::{
    Felt, ZERO,
    deferred::{App, DeferredState, MockHash, PrecompileSchema, Uint256},
};

fn chunks(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

#[test]
fn preimage_reduces_to_known_digest_and_eq_predicate_passes() {
    let schema = PrecompileSchema::new([
        Box::new(Uint256) as Box<dyn App>,
        Box::new(MockHash) as Box<dyn App>,
    ]);
    let mut state = DeferredState::new();
    schema.boot(&mut state);

    // Build a 64-byte preimage (two 32-byte chunks) and the digest the mock hash should yield.
    let preimage_chunks = chunks(2);
    let expected_digest_felts = MockHash::hash(&preimage_chunks);
    let expected_digest = MockHash::digest_node(expected_digest_felts);

    let h_expected = state.register(&schema, expected_digest.clone()).unwrap();
    let h_preimage = state
        .register(&schema, MockHash::preimage_node(64, preimage_chunks.clone()))
        .unwrap();

    // Evaluating the preimage produces the digest leaf.
    let canonical = state.evaluate(&schema, state.get(&h_preimage).unwrap().clone()).unwrap();
    assert_eq!(canonical, expected_digest);

    // eq predicate ties the preimage's hash to the pre-registered expected digest.
    let result = state.evaluate(&schema, MockHash::eq_node(h_preimage, h_expected)).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn preimage_with_partial_last_chunk_is_handled_by_caller_padding() {
    // n_bytes=40 → ceil(40/32)=2 chunks. The framework just sees 2 chunks; whether the second
    // chunk is partially zero-padded is the caller's convention. Use a deliberately
    // partial-looking second chunk.
    let schema = PrecompileSchema::single(MockHash);
    let mut state = DeferredState::new();
    let last_chunk: [Felt; 8] = [
        Felt::from_u32(0xab),
        Felt::from_u32(0xcd),
        ZERO,
        ZERO,
        ZERO,
        ZERO,
        ZERO,
        ZERO,
    ];
    let preimage_chunks = vec![[Felt::from_u32(1); 8], last_chunk];
    let expected = MockHash::digest_node(MockHash::hash(&preimage_chunks));
    let canonical = state
        .evaluate(&schema, MockHash::preimage_node(40, preimage_chunks))
        .unwrap();
    assert_eq!(canonical, expected);
}
