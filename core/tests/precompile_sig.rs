//! Integration coverage for fixed-size chunk predicates in the mock signature precompile.

mod common;

use miden_core::{
    Felt, ZERO,
    deferred::{DeferredState, Node, NodeType, Precompile, PrecompileError, PrecompileRegistry},
    testing::precompile::{Hash, Sig, Uint},
};
use proptest::prelude::*;

fn three_chunks(first_first_felt: Felt) -> Vec<[Felt; 8]> {
    let mut c0 = [Felt::from_u32(0xaa); 8];
    c0[0] = first_first_felt;
    vec![c0, [Felt::from_u32(0xbb); 8], [Felt::from_u32(0xcc); 8]]
}

#[test]
fn verify_passes_in_multi_precompile_schema() {
    let schema = PrecompileRegistry::default()
        .with_precompile(Uint)
        .with_precompile(Hash)
        .with_precompile(Sig);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();

    let node = Sig::verify_node(three_chunks(Felt::from_u32(7)));
    let result = state.evaluate_node(&schema, node).unwrap();
    assert!(result.is_true_node());

    // Log the proven signature predicate and round-trip the transcript.
    common::log_and_verify(&schema, &mut state, Sig::verify_node(three_chunks(Felt::from_u32(7))));
}

#[test]
fn verify_fails_for_zeroed_placeholder_sig() {
    let schema = PrecompileRegistry::default().with_precompile(Sig);
    let mut state = DeferredState::new();
    let node = Sig::verify_node(three_chunks(ZERO));
    let err = state.evaluate_node(&schema, node);
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn decode_verify_is_chunk3() {
    let node_type = Sig.decode([Felt::from_u32(Sig::VERIFY_TAG_ID), ZERO, ZERO]).unwrap();
    assert!(matches!(node_type, NodeType::Chunks(n) if n.get() == 3));
}

#[test]
fn decode_unknown_discriminant_rejected() {
    let node_type = Sig.decode([Felt::from_u32(1), ZERO, ZERO]);
    assert!(node_type.is_none());
}

proptest! {
    /// The mock verifier accepts exactly the non-zero first-felt cases across arbitrary blobs.
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
        let result = state.evaluate_node(&schema, Sig::verify_node(chunks));
        if f0 != 0 {
            prop_assert!(result.unwrap().is_true_node());
        } else {
            prop_assert!(matches!(result.unwrap_err().root(), PrecompileError::AssertionFailed));
        }
    }

    /// Wrong non-empty chunk counts are rejected before reducer logic can observe them.
    #[test]
    fn verify_rejects_wrong_chunk_count(
        n in (1usize..=8).prop_filter("must differ from SIG_CHUNKS", |n| *n != 3),
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
