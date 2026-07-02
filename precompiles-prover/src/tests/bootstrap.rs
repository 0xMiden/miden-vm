//! Fixed-manifest bootstrap tests.

use miden_precompiles::UintDomain;

use crate::{
    math::U256, session::Session, transcript::poseidon2::P2Digest, uint::trace::PIN_NAMESPACE_END,
};

#[test]
fn bootstrap_fixed_pins_emit_no_default_transcript_claims() {
    let mut session = Session::new();
    let claims = session.bootstrap_fixed_pins();
    assert!(claims.is_empty(), "fixed manifest must not enter the public root by default");

    let root = session.assert_and_fold(claims);
    assert_eq!(root.hash(), P2Digest::default());

    let traces = session.finish(root);
    assert_eq!(traces.public_root(), P2Digest::default());
    traces.check();
}

#[test]
fn fixed_manifest_external_uintvals_prove_and_verify_with_empty_root() {
    let mut session = Session::new();
    let claims = session.bootstrap_fixed_pins();
    assert!(claims.is_empty(), "fixed manifest is verifier-constrained, not root-folded");

    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    assert_eq!(traces.public_root(), P2Digest::default());

    let proof = traces.prove();
    assert_eq!(proof.public_root(), P2Digest::default());
    proof.verify().expect("fixed uint external manifest proof should verify");
}

#[test]
fn non_fixed_runtime_constants_allocate_transient_ptrs() {
    let mut session = Session::new();
    let claims = session.bootstrap_fixed_pins();
    assert!(claims.is_empty());

    for domain in UintDomain::ALL {
        let bound_ptr = domain.bound_ptr();
        for value in [U256::from(42u8), U256::from(123u8)] {
            let node = session.uint_leaf(value, bound_ptr);
            assert!(
                node.ptr.addr() >= PIN_NAMESPACE_END,
                "ordinary constant {value} under {domain:?} reused a fixed ptr {}",
                node.ptr.addr(),
            );
            assert_ne!(node.ptr.addr(), bound_ptr);
        }
    }
}
