//! Integration coverage for the `Sig` reference precompile: single chunk-bodied predicate,
//! standalone and inside a multi-precompile `PrecompileSchema` (alongside `Uint` and `Hash`).

mod common;

use common::precompile::{hash::Hash, sig::Sig, uint::Uint};
use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredState, Node, NodeType, Precompile, PrecompileSchema, PrecompileTag, SchemaError,
        TRUE_TAG,
    },
};

fn three_chunks(first_first_felt: Felt) -> Vec<[Felt; 8]> {
    let mut c0 = [Felt::from_u32(0xaa); 8];
    c0[0] = first_first_felt;
    vec![c0, [Felt::from_u32(0xbb); 8], [Felt::from_u32(0xcc); 8]]
}

fn non_zero_chunks() -> [[Felt; 8]; 3] {
    [[Felt::from_u32(1); 8], [Felt::from_u32(2); 8], [Felt::from_u32(3); 8]]
}

// END-TO-END (relocated from deferred_mock_sig.rs)
// ================================================================================================

#[test]
fn verify_passes_in_multi_app_schema() {
    let schema = PrecompileSchema::new([
        Box::new(Uint) as Box<dyn Precompile>,
        Box::new(Hash) as Box<dyn Precompile>,
        Box::new(Sig) as Box<dyn Precompile>,
    ]);
    let mut state = DeferredState::new();
    schema.init(&mut state).unwrap();

    let node = Sig::verify_node(three_chunks(Felt::from_u32(7)));
    let result = state.evaluate(&schema, node).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn verify_fails_for_zeroed_placeholder_sig() {
    let schema = PrecompileSchema::single(Sig);
    let mut state = DeferredState::new();
    let node = Sig::verify_node(three_chunks(ZERO));
    let err = state.evaluate(&schema, node);
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

// CAPABILITY UNIT TESTS (relocated from the old in-lib `mock_sig` unit tests)
// ================================================================================================

#[test]
fn decode_verify_is_chunk3_predicate() {
    let info = Sig
        .decode(PrecompileTag([Felt::from_u32(Sig::VERIFY_TAG_ID), ZERO, ZERO]))
        .unwrap();
    assert!(matches!(info.node_type, NodeType::Chunks(3)));
    assert_eq!(info.evaluates_to, TRUE_TAG);
}

#[test]
fn decode_rejects_imm() {
    let err =
        Sig.decode(PrecompileTag([Felt::from_u32(Sig::VERIFY_TAG_ID), Felt::from_u32(1), ZERO]));
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
}

#[test]
fn decode_unknown_discriminant_rejected() {
    let err = Sig.decode(PrecompileTag([Felt::from_u32(1), ZERO, ZERO]));
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
}

#[test]
fn verify_passes_when_first_felt_nonzero() {
    let schema = PrecompileSchema::single(Sig);
    let mut state = DeferredState::new();
    let node = Sig::verify_node(non_zero_chunks().to_vec());
    let result = state.evaluate(&schema, node).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn verify_fails_when_first_felt_is_zero() {
    let schema = PrecompileSchema::single(Sig);
    let mut state = DeferredState::new();
    let mut chunks = non_zero_chunks();
    chunks[0][0] = ZERO;
    let node = Sig::verify_node(chunks.to_vec());
    let err = state.evaluate(&schema, node);
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn verify_with_wrong_chunk_count_rejected() {
    // Hand-built chunk node with the wrong number of chunks. Register's payload_matches_body
    // check catches this before reduce ever runs.
    let schema = PrecompileSchema::single(Sig);
    let mut state = DeferredState::new();
    let too_few = vec![[Felt::from_u32(1); 8], [Felt::from_u32(2); 8]];
    let node = Node::chunk(Sig::verify_tag(), too_few);
    let err = state.register(&schema, node);
    assert!(matches!(err, Err(SchemaError::InvalidNode)));
}
