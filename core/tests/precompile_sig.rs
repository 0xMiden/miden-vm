//! Integration coverage for the `Sig` reference precompile: single chunk-bodied predicate,
//! standalone and inside a multi-precompile `PrecompileRegistry` (alongside `Uint` and `Hash`).

mod common;

use common::precompile::{hash::Hash, sig::Sig, uint::Uint};
use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredState, Node, NodeType, Precompile, PrecompileError, PrecompileRegistry, TRUE_TAG,
    },
};
use proptest::prelude::*;

fn three_chunks(first_first_felt: Felt) -> Vec<[Felt; 8]> {
    let mut c0 = [Felt::from_u32(0xaa); 8];
    c0[0] = first_first_felt;
    vec![c0, [Felt::from_u32(0xbb); 8], [Felt::from_u32(0xcc); 8]]
}

// END-TO-END (relocated from deferred_mock_sig.rs)
// ================================================================================================

#[test]
fn verify_passes_in_multi_precompile_schema() {
    let schema = PrecompileRegistry::default()
        .with_precompile(Uint)
        .with_precompile(Hash)
        .with_precompile(Sig);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();

    let node = Sig::verify_node(three_chunks(Felt::from_u32(7)));
    let result = state.evaluate(&schema, node).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn verify_fails_for_zeroed_placeholder_sig() {
    let schema = PrecompileRegistry::default().with_precompile(Sig);
    let mut state = DeferredState::new();
    let node = Sig::verify_node(three_chunks(ZERO));
    let err = state.evaluate(&schema, node);
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

// CAPABILITY UNIT TESTS (relocated from the old in-lib `mock_sig` unit tests)
// ================================================================================================

#[test]
fn decode_verify_is_chunk3_predicate() {
    let info = Sig.decode([Felt::from_u32(Sig::VERIFY_TAG_ID), ZERO, ZERO]).unwrap();
    assert!(matches!(info.node_type, NodeType::Chunks(3)));
    assert_eq!(info.evaluates_to, TRUE_TAG);
}

#[test]
fn decode_unknown_discriminant_rejected() {
    let info = Sig.decode([Felt::from_u32(1), ZERO, ZERO]);
    assert!(info.is_none());
}

proptest! {
    /// `Sig::verify` is a stub predicate: it succeeds iff the very first felt of the first
    /// chunk is non-zero. The property holds over arbitrary 3-chunk content and subsumes the
    /// old concrete nonzero/zero pair.
    #[test]
    fn verify_succeeds_iff_first_felt_nonzero(
        f0 in any::<u32>(),
        rest in proptest::collection::vec(any::<u32>(), 23),
    ) {
        let mut flat = [Felt::from_u32(0); 24];
        flat[0] = Felt::from_u32(f0);
        for (slot, v) in flat[1..].iter_mut().zip(rest) {
            *slot = Felt::from_u32(v);
        }
        let chunks: Vec<[Felt; 8]> = vec![
            flat[0..8].try_into().unwrap(),
            flat[8..16].try_into().unwrap(),
            flat[16..24].try_into().unwrap(),
        ];
        let schema = PrecompileRegistry::default().with_precompile(Sig);
        let mut state = DeferredState::new();
        let result = state.evaluate(&schema, Sig::verify_node(chunks));
        if f0 != 0 {
            prop_assert!(result.unwrap().is_true_node());
        } else {
            prop_assert!(matches!(result.unwrap_err().root(), PrecompileError::AssertionFailed));
        }
    }

    /// Any chunk count other than the fixed `SIG_CHUNKS = 3` is rejected at register-time by
    /// the framework's `payload_matches_type` gate, before reduce runs.
    #[test]
    fn verify_rejects_wrong_chunk_count(
        n in (0usize..=8).prop_filter("must differ from SIG_CHUNKS", |n| *n != 3),
    ) {
        let chunks: Vec<[Felt; 8]> = vec![[Felt::from_u32(1); 8]; n];
        let schema = PrecompileRegistry::default().with_precompile(Sig);
        let mut state = DeferredState::new();
        let node = Node::chunk(Sig::verify_tag(), chunks);
        prop_assert!(matches!(
            state.register(&schema, node),
            Err(PrecompileError::InvalidNode)
        ));
    }
}
