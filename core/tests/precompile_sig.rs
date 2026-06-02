//! Integration coverage for fixed-size chunk predicates in the mock signature precompile.

mod common;

use std::sync::Arc;

use common::register_and_evaluate;
use miden_core::{
    Felt, ZERO,
    deferred::{DeferredState, Node, NodeType, Precompile, PrecompileError, PrecompileRegistry},
    testing::precompile::{Hash, Sig, Uint},
};

fn three_chunks(first_first_felt: Felt) -> Vec<[Felt; 8]> {
    let mut c0 = [Felt::from_u32(0xaa); 8];
    c0[0] = first_first_felt;
    vec![c0, [Felt::from_u32(0xbb); 8], [Felt::from_u32(0xcc); 8]]
}

#[test]
fn verify_passes_in_multi_precompile_registry() {
    let registry = Arc::new(
        PrecompileRegistry::default()
            .with_precompile(Uint)
            .with_precompile(Hash)
            .with_precompile(Sig),
    );
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();

    let node = Sig::verify_node(three_chunks(Felt::from_u32(7)));
    let result = register_and_evaluate(&registry, &mut state, node);
    assert!(result.is_true_node());

    // Log the proven signature predicate and round-trip the transcript.
    common::log_and_verify(
        &registry,
        &mut state,
        Sig::verify_node(three_chunks(Felt::from_u32(7))),
    );
}

#[test]
fn verify_fails_for_zeroed_placeholder_sig() {
    let registry = Arc::new(PrecompileRegistry::default().with_precompile(Sig));
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    let node = Sig::verify_node(three_chunks(ZERO));
    let digest = state.register(node).unwrap();
    let err = state.evaluate(digest);
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn decode_classifies_verify_tag_only() {
    let node_type = Sig.decode([Felt::from_u32(Sig::VERIFY_TAG_ID), ZERO, ZERO]).unwrap();
    assert!(matches!(node_type, NodeType::Chunks(n) if n.get() == 3));
    assert!(Sig.decode([Felt::from_u32(1), ZERO, ZERO]).is_none());
}

#[test]
fn verify_rejects_wrong_chunk_count() {
    let registry = Arc::new(PrecompileRegistry::default().with_precompile(Sig));
    let mut state = DeferredState::new(Arc::clone(&registry), usize::MAX).unwrap();
    let node = Node::chunk(Sig::verify_tag(), vec![[Felt::from_u32(1); 8]; 2]);
    assert!(matches!(state.register(node), Err(PrecompileError::InvalidNode)));
}
