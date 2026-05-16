//! End-to-end: `MockSig` as a single-discriminant chunk-bodied predicate inside a
//! multi-app `PrecompileSchema` (alongside `Uint256` and `MockHash`).

use miden_core::{
    Felt, ZERO,
    deferred::{App, DeferredState, MockHash, MockSig, PrecompileSchema, SchemaError, Uint256},
};

fn three_chunks(first_first_felt: Felt) -> Vec<[Felt; 8]> {
    let mut c0 = [Felt::from_u32(0xaa); 8];
    c0[0] = first_first_felt;
    vec![c0, [Felt::from_u32(0xbb); 8], [Felt::from_u32(0xcc); 8]]
}

#[test]
fn verify_passes_in_multi_app_schema() {
    let schema = PrecompileSchema::new([
        Box::new(Uint256) as Box<dyn App>,
        Box::new(MockHash) as Box<dyn App>,
        Box::new(MockSig) as Box<dyn App>,
    ]);
    let mut state = DeferredState::new();
    schema.boot(&mut state);

    let node = MockSig::verify_node(three_chunks(Felt::from_u32(7)));
    let result = state.evaluate(&schema, node).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn verify_fails_for_zeroed_placeholder_sig() {
    let schema = PrecompileSchema::single(MockSig);
    let mut state = DeferredState::new();
    let node = MockSig::verify_node(three_chunks(ZERO));
    let err = state.evaluate(&schema, node);
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}
