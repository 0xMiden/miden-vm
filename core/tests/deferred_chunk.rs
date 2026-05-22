//! Canary integration test for the chunk-node variant of the deferred-DAG public API, driven
//! through the [`Hash`] reference precompile (chunk-bodied preimage → digest leaf, plus an `eq`
//! predicate over two digests).

use miden_core::{
    Felt,
    deferred::{DeferredState, Node, PrecompileError, PrecompileRegistry, Tag},
    testing::precompile::Hash,
};

// HASH-PRECOMPILE TAG HELPERS
// ================================================================================================

/// Tag for an `n`-chunk preimage. `Hash` derives the chunk count from a byte length, so a chunk
/// count of `n` is requested as `n * BYTES_PER_CHUNK` bytes.
fn preimage_tag(n: u32) -> Tag {
    Hash::preimage_tag(n * Hash::BYTES_PER_CHUNK)
}

// HELPERS
// ================================================================================================

fn chunk_data(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

// TESTS
// ================================================================================================

#[test]
fn chunk_digest_for_n1_matches_equivalent_expression() {
    // Sanity check: an `n=1` chunk and an expression with the same tag and same 8 felts should
    // have identical digests. The chunk-digest body reduces to "fill rate, one permutation" for
    // n=1, which is exactly the standard expression digest body.
    let tag = preimage_tag(1);
    let data = chunk_data(1);
    let chunk = Node::chunk(tag, data.clone());
    let expr = Node::leaf(tag, data[0]);
    assert_eq!(chunk.digest(), expr.digest());
}

#[test]
fn register_chunk_stores_node() {
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();
    let chunk = Node::chunk(preimage_tag(3), chunk_data(3));
    let digest = state.register(&schema, chunk.clone()).unwrap();
    assert_eq!(digest, chunk.digest());
    assert_eq!(state.get(&digest).unwrap(), &chunk);
}

#[test]
fn register_chunk_with_mismatched_length_fails() {
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();
    // Tag declares n=3 but we hand it 2 chunks of data.
    let bad = Node::chunk(preimage_tag(3), chunk_data(2));
    assert!(matches!(state.register(&schema, bad), Err(PrecompileError::InvalidNode)));
}

#[test]
fn predicate_preimage_equals_digest_succeeds() {
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();

    // Register a 3-chunk preimage.
    let chunks = chunk_data(3);
    let preimage = Node::chunk(preimage_tag(3), chunks.clone());
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // Pre-compute and register the matching digest leaf.
    let digest_leaf = Node::leaf(Hash::digest_tag(), Hash::hash(&chunks));
    let digest_leaf_digest = state.register(&schema, digest_leaf).unwrap();

    // Predicate: preimage's digest == precomputed digest leaf. Reduce drives the chunk's hash
    // and compares against the precomputed leaf, returning the TRUE node on match.
    let assertion = Node::join(Hash::eq_tag(), preimage_digest, digest_leaf_digest);
    state.register(&schema, assertion.clone()).unwrap();
    let result = state.evaluate(&schema, assertion).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn predicate_preimage_mismatch_fails_on_evaluate() {
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();

    let chunks = chunk_data(2);
    let preimage = Node::chunk(preimage_tag(2), chunks);
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // A digest leaf with the wrong content — predicate must fail when verified.
    let wrong_leaf = Node::leaf(Hash::digest_tag(), [Felt::from_u32(99); 8]);
    let wrong_leaf_digest = state.register(&schema, wrong_leaf).unwrap();

    let assertion = Node::join(Hash::eq_tag(), preimage_digest, wrong_leaf_digest);
    // Register is a pure hint — succeeds even when the predicate doesn't hold.
    state.register(&schema, assertion.clone()).unwrap();
    let err = state.evaluate(&schema, assertion);
    // The registry name-wraps the precompile's failure; assert the root cause.
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn zero_byte_preimage_tag_is_rejected() {
    // A 0-byte preimage derives zero chunks, which the framework forbids: `Hash::decode` returns
    // None for the tag, so registering any node under it fails before the body is even inspected.
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();
    let node = Node::chunk(preimage_tag(0), chunk_data(1));
    assert!(matches!(
        state.register(&schema, node).unwrap_err().root(),
        PrecompileError::InvalidNode
    ));
}

#[test]
fn deferred_state_includes_chunk_nodes() {
    let schema = PrecompileRegistry::default().with_precompile(Hash);
    let mut state = DeferredState::new();

    let preimage = Node::chunk(preimage_tag(2), chunk_data(2));
    let preimage_digest = state.register(&schema, preimage.clone()).unwrap();

    assert_eq!(
        state.get(&preimage_digest).unwrap(),
        &preimage,
        "chunk node must be present in the deferred state"
    );
}
