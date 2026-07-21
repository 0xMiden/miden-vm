use miden_core::{chiplets::hasher::Hasher, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MidenAirBuilder,
    constraints::poseidon2_permutation::columns::{
        Poseidon2PermutationCols, Poseidon2PermutationPeriodicCols,
    },
    trace::chiplets::hasher::STATE_WIDTH,
};

pub fn enforce_permutation_steps<AB>(
    builder: &mut AB,
    cols: &Poseidon2PermutationCols<AB::Var>,
    cols_next: &Poseidon2PermutationCols<AB::Var>,
    periodic: &Poseidon2PermutationPeriodicCols<AB::PeriodicVar>,
) where
    AB: MidenAirBuilder,
{
    let h: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| cols.state[i].into());
    let h_next: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| cols_next.state[i].into());
    let ark1: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| periodic.ark1[i].into());
    let ark2: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| periodic.ark2[i].into());
    let mds: [[AB::Expr; STATE_WIDTH]; STATE_WIDTH] =
        core::array::from_fn(|r| core::array::from_fn(|c| Hasher::MDS[r][c].into()));

    let is_cycle_start: AB::Expr = periodic.is_cycle_start.into();
    let is_round: AB::Expr = periodic.is_round.into();

    builder.when(is_round.clone() - is_cycle_start).assert_zero(cols.witnesses[0]);

    let expected = transition_rhs(&h, &ark1, &ark2, &mds);
    let builder = &mut builder.when(is_round);
    for i in 0..STATE_WIDTH {
        builder.assert_eq(h_next[i].clone().exp_const_u64::<7>(), expected[i].clone());
    }
}

fn transition_rhs<E: PrimeCharacteristicRing>(
    current: &[E; STATE_WIDTH],
    ark1: &[E; STATE_WIDTH],
    ark2: &[E; STATE_WIDTH],
    mds: &[[E; STATE_WIDTH]; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let mut state = apply_mds(current, mds);
    for (s, a) in state.iter_mut().zip(ark1) {
        *s += a.clone();
    }
    for s in state.iter_mut() {
        *s = s.exp_const_u64::<7>();
    }
    state = apply_mds(&state, mds);
    for (s, a) in state.iter_mut().zip(ark2) {
        *s += a.clone();
    }
    state
}

fn apply_mds<E: PrimeCharacteristicRing>(
    state: &[E; STATE_WIDTH],
    mds: &[[E; STATE_WIDTH]; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    core::array::from_fn(|r| {
        let mut acc = E::ZERO;
        for (c, value) in state.iter().enumerate() {
            acc += value.clone() * mds[r][c].clone();
        }
        acc
    })
}
