//! Checks of uint VALUE bindings across the PVM chiplets.

use miden_core::{
    Felt,
    deferred::{EidosFrame, PrecompileError},
    program::domain::PvmUintPinClaimDomain,
};
use miden_precompiles::UintDomain;

use super::Session;
use crate::prover::{math::U256, transcript::eidos::trace::EidosRequires};

#[test]
#[should_panic(expected = "external assertion")]
fn nested_uint_value_cannot_supply_a_truth_binding() {
    let mut session = Session::new();
    let value = session.uint_leaf(U256::from(9u8), UintDomain::U256.bound_ptr());
    let equality = session.uint_is(&value, &value);
    let tampered_truth = session.eval.issue(value.hash());
    let branch = session.assert_and(equality, tampered_truth);
    let zero = session.zero();
    let root = session.assert_and(zero, branch);
    session.finish(root).check();
}

#[test]
#[should_panic(expected = "external assertion")]
fn equality_cannot_relabel_a_uint_value_with_a_pin_digest() {
    let mut session = Session::new();
    let bound_ptr = UintDomain::U256.bound_ptr();
    let mut value = session.uint_leaf(U256::from(9u8), bound_ptr);
    let frame = EidosFrame::for_domain(PvmUintPinClaimDomain, [bound_ptr, value.ptr.addr(), 0]);
    value.hash = EidosRequires::digest_of(
        frame,
        &[([Felt::from(9u8), Felt::ZERO, Felt::ZERO, Felt::ZERO], [Felt::ZERO; 4])],
    );
    let equality = session.uint_is(&value, &value);
    let zero = session.zero();
    let root = session.assert_and(zero, equality);
    session.finish(root).check();
}

#[test]
fn native_registry_rejects_pin_claim_frame() {
    let frame =
        EidosFrame::for_domain(PvmUintPinClaimDomain, [UintDomain::U256.bound_ptr(), 1000, 0]);
    assert!(matches!(
        miden_precompiles::registry().decode_precompile_frame(frame),
        Err(PrecompileError::InvalidNode)
    ));
}
