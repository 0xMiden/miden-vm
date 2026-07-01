//! Fixed-pin bootstrap tests.

use miden_core::{
    Felt,
    deferred::{Digest, fold_deferred_root},
};
use miden_precompiles::UintDomain;

use crate::{
    math::{U256, from_limbs32, to_limbs32},
    session::Session,
    transcript::poseidon2::{P2Cap, P2Digest, trace::Poseidon2Requires},
    uint::trace::PIN_NAMESPACE_END,
};

fn fold_truthy_hashes(hashes: impl IntoIterator<Item = P2Digest>) -> P2Digest {
    let mut acc = P2Digest::default();
    for hash in hashes {
        acc = P2Digest::from(fold_deferred_root(
            Digest::new(acc.as_array()),
            Digest::new(hash.as_array()),
        ));
    }
    acc
}

fn bound_value(domain: UintDomain) -> U256 {
    from_limbs32(&domain.minus_one())
}

fn bound_pin_claim_digest(domain: UintDomain) -> P2Digest {
    let ptr = domain.bound_ptr();
    let limbs = to_limbs32(bound_value(domain));
    let lo = core::array::from_fn(|i| Felt::from(limbs[i]));
    let hi = core::array::from_fn(|i| Felt::from(limbs[4 + i]));
    Poseidon2Requires::digest_of(P2Cap::uint_pin_claim(ptr, ptr), &[(lo, hi)])
}

#[test]
fn bootstrap_root_folds_fixed_bound_pin_claims() {
    let expected = fold_truthy_hashes(UintDomain::ALL.into_iter().map(bound_pin_claim_digest));

    let mut session = Session::new();
    let claims = session.bootstrap_fixed_pins();
    let root = session.assert_and_fold(claims);
    assert_eq!(root.hash(), expected);

    let traces = session.finish(root);
    assert_eq!(traces.public_root(), expected);
    traces.check();
}

#[test]
fn bootstrap_keeps_common_runtime_constants_dynamic() {
    let mut session = Session::new();
    let _claims = session.bootstrap_fixed_pins();

    for domain in UintDomain::ALL {
        let bound_ptr = domain.bound_ptr();
        for value in [U256::ZERO, U256::ONE, U256::from(2u8)] {
            let node = session.uint_leaf(value, bound_ptr);
            assert!(
                node.ptr.addr() >= PIN_NAMESPACE_END,
                "ordinary constant {value} under {domain:?} reused a fixed pin ptr {}",
                node.ptr.addr(),
            );
            assert_ne!(node.ptr.addr(), bound_ptr);
        }
    }
}
