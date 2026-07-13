//! Fixed-boundary tests.

use std::{collections::HashMap, string::String};

use miden_air::lookup::Challenges;
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_precompiles::{CurveId, UintDomain};

use crate::{
    ec::groups::{
        COL_SBOUND_PTR as G_COL_SBOUND_PTR, EcGroupsAir, NUM_MAIN_COLS as G_NUM_MAIN_COLS,
    },
    math::U256,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{Session, SessionTraces},
    tests::bus_balance::{fold_balance, fold_fixed_group_external_balance},
    transcript::poseidon2::P2Digest,
    uint::trace::PIN_NAMESPACE_END,
};

fn empty_root_traces() -> SessionTraces {
    let mut session = Session::new();
    let root = session.zero();
    session.finish(root)
}

fn fixed_group_residual(groups: &RowMajorMatrix<Felt>) -> usize {
    let challenges = Challenges::new(
        QuadFelt::new([Felt::from(17u32), Felt::from(23u32)]),
        QuadFelt::new([Felt::from(31u32), Felt::from(43u32)]),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&EcGroupsAir, groups, &challenges, &mut net);
    fold_fixed_group_external_balance(&challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).count()
}

fn fixed_group_row(curve: CurveId) -> usize {
    CurveId::ALL
        .into_iter()
        .position(|fixed| fixed == curve)
        .expect("fixed curve is in CurveId::ALL")
        * G_NUM_MAIN_COLS
}

#[test]
fn fixed_environment_emits_no_default_transcript_claims() {
    let traces = empty_root_traces();
    assert_eq!(traces.public_root(), P2Digest::default());
    traces.check();
}

#[test]
fn tampered_fixed_group_scalar_bound_ptr_unbalances() {
    let curve = CurveId::ALL[0];
    let traces = empty_root_traces();
    let mut forged = traces.mains()[10].clone();
    forged.values[fixed_group_row(curve) + G_COL_SBOUND_PTR] =
        Felt::from(curve.base_domain().bound_ptr());

    crate::tests::check_local(EcGroupsAir, &forged);
    assert_ne!(fixed_group_residual(&forged), 0);
}

#[test]
fn non_fixed_runtime_constants_allocate_transient_ptrs() {
    let mut session = Session::new();

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
