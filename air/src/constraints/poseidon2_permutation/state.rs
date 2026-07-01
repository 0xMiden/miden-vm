//! Poseidon2 permutation AIR state transition constraints.
//!
//! The trace uses one 16-row cycle per unique permutation input:
//!
//! - row 0: initial linear layer plus the first initial external round
//! - rows 1..=3: initial external rounds 2, 3, and 4
//! - rows 4..=10: internal rounds, packed three per row through `witnesses`
//! - row 11: final internal round plus the first terminal external round
//! - rows 12..=14: terminal external rounds 2, 3, and 4
//! - row 15: output row; no transition constraint is active
//!
//! The direct x^7 S-box constraints have degree 8: one periodic row selector times a
//! degree-7 expression.

use miden_core::{chiplets::hasher::Hasher, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MidenAirBuilder,
    constraints::poseidon2_permutation::columns::{
        NUM_SBOX_WITNESSES, Poseidon2PermutationCols, Poseidon2PermutationPeriodicCols,
    },
    trace::chiplets::hasher::STATE_WIDTH,
};

const LAST_INTERNAL_ROUND_ARK_IDX: usize = 21;

/// Enforces the 16-row packed Poseidon2 cycle.
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
    let w: [AB::Expr; NUM_SBOX_WITNESSES] = core::array::from_fn(|i| cols.witnesses[i].into());

    let is_init_ext: AB::Expr = periodic.is_init_ext.into();
    let is_ext: AB::Expr = periodic.is_ext.into();
    let is_packed_int: AB::Expr = periodic.is_packed_int.into();
    let is_int_ext: AB::Expr = periodic.is_int_ext.into();

    let ark: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| periodic.ark[i].into());
    let mat_diag: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| Hasher::MAT_DIAG[i].into());
    let last_internal_ark: AB::Expr = Hasher::ARK_INT[LAST_INTERNAL_ROUND_ARK_IDX].into();

    // Witness columns are only meaningful on packed internal rows and on the mixed
    // internal/external row. Force unused witness cells to zero so padding cycles and
    // row-kind mistakes cannot hide extra degrees of freedom.
    builder
        .when(AB::Expr::ONE - is_packed_int.clone() - is_int_ext.clone())
        .assert_zero(w[0].clone());
    {
        let builder = &mut builder.when(AB::Expr::ONE - is_packed_int.clone());
        builder.assert_zero(w[1].clone());
        builder.assert_zero(w[2].clone());
    }

    // Row 0: h' = M_E(S(M_E(h) + ark)).
    {
        let expected = apply_init_plus_ext(&h, &ark);
        let builder = &mut builder.when(is_init_ext);
        for i in 0..STATE_WIDTH {
            builder.assert_eq(h_next[i].clone(), expected[i].clone());
        }
    }

    // Rows 1..=3 and 12..=14: h' = M_E(S(h + ark)).
    {
        let ext_with_rc: [AB::Expr; STATE_WIDTH] =
            core::array::from_fn(|i| h[i].clone() + ark[i].clone());
        let ext_with_sbox: [AB::Expr; STATE_WIDTH] =
            core::array::from_fn(|i| ext_with_rc[i].clone().exp_const_u64::<7>());
        let expected = apply_matmul_external(&ext_with_sbox);

        let builder = &mut builder.when(is_ext);
        for i in 0..STATE_WIDTH {
            builder.assert_eq(h_next[i].clone(), expected[i].clone());
        }
    }

    // Rows 4..=10: three internal rounds. Each witness is the S-box output of one
    // internal round, keeping the next internal S-box input affine.
    {
        let ark_int_3: [AB::Expr; NUM_SBOX_WITNESSES] = core::array::from_fn(|i| ark[i].clone());
        let (expected, witness_checks) = apply_packed_internals(&h, &w, &ark_int_3, &mat_diag);

        let builder = &mut builder.when(is_packed_int);
        for wc in &witness_checks {
            builder.assert_zero(wc.clone());
        }
        for i in 0..STATE_WIDTH {
            builder.assert_eq(h_next[i].clone(), expected[i].clone());
        }
    }

    // Row 11: final internal round followed by the first terminal external round.
    {
        let (expected, witness_check) =
            apply_internal_plus_ext(&h, &w[0], last_internal_ark, &ark, &mat_diag);

        let builder = &mut builder.when(is_int_ext);
        builder.assert_zero(witness_check);
        for i in 0..STATE_WIDTH {
            builder.assert_eq(h_next[i].clone(), expected[i].clone());
        }
    }
}

fn apply_matmul_external<E: PrimeCharacteristicRing>(state: &[E; STATE_WIDTH]) -> [E; STATE_WIDTH] {
    let b0 = matmul_m4(core::array::from_fn(|i| state[i].clone()));
    let b1 = matmul_m4(core::array::from_fn(|i| state[4 + i].clone()));
    let b2 = matmul_m4(core::array::from_fn(|i| state[8 + i].clone()));

    let stored0 = b0[0].clone() + b1[0].clone() + b2[0].clone();
    let stored1 = b0[1].clone() + b1[1].clone() + b2[1].clone();
    let stored2 = b0[2].clone() + b1[2].clone() + b2[2].clone();
    let stored3 = b0[3].clone() + b1[3].clone() + b2[3].clone();

    [
        b0[0].clone() + stored0.clone(),
        b0[1].clone() + stored1.clone(),
        b0[2].clone() + stored2.clone(),
        b0[3].clone() + stored3.clone(),
        b1[0].clone() + stored0.clone(),
        b1[1].clone() + stored1.clone(),
        b1[2].clone() + stored2.clone(),
        b1[3].clone() + stored3.clone(),
        b2[0].clone() + stored0,
        b2[1].clone() + stored1,
        b2[2].clone() + stored2,
        b2[3].clone() + stored3,
    ]
}

fn matmul_m4<E: PrimeCharacteristicRing>(input: [E; 4]) -> [E; 4] {
    let [a, b, c, d] = input;

    let t01 = a.clone() + b.clone();
    let t23 = c.clone() + d.clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + b;
    let t01233 = t0123 + d;

    let out0 = t01123.clone() + t01;
    let out1 = t01123 + c.double();
    let out2 = t01233.clone() + t23;
    let out3 = t01233 + a.double();

    [out0, out1, out2, out3]
}

fn apply_matmul_internal<E: PrimeCharacteristicRing>(
    state: &[E; STATE_WIDTH],
    mat_diag: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let sum = E::sum_array::<STATE_WIDTH>(state);
    core::array::from_fn(|i| state[i].clone() * mat_diag[i].clone() + sum.clone())
}

fn apply_init_plus_ext<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    ark_ext: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let pre = apply_matmul_external(h);
    let with_rc: [E; STATE_WIDTH] = core::array::from_fn(|i| pre[i].clone() + ark_ext[i].clone());
    let with_sbox: [E; STATE_WIDTH] =
        core::array::from_fn(|i| with_rc[i].clone().exp_const_u64::<7>());
    apply_matmul_external(&with_sbox)
}

fn apply_packed_internals<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    w: &[E; NUM_SBOX_WITNESSES],
    ark_int: &[E; NUM_SBOX_WITNESSES],
    mat_diag: &[E; STATE_WIDTH],
) -> ([E; STATE_WIDTH], [E; NUM_SBOX_WITNESSES]) {
    let mut state = h.clone();
    let mut witness_checks: [E; NUM_SBOX_WITNESSES] = core::array::from_fn(|_| E::ZERO);

    for k in 0..NUM_SBOX_WITNESSES {
        let sbox_input = state[0].clone() + ark_int[k].clone();
        witness_checks[k] = w[k].clone() - sbox_input.exp_const_u64::<7>();

        state[0] = w[k].clone();
        state = apply_matmul_internal(&state, mat_diag);
    }

    (state, witness_checks)
}

fn apply_internal_plus_ext<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    w0: &E,
    ark_int_const: E,
    ark_ext: &[E; STATE_WIDTH],
    mat_diag: &[E; STATE_WIDTH],
) -> ([E; STATE_WIDTH], E) {
    let sbox_input = h[0].clone() + ark_int_const;
    let witness_check = w0.clone() - sbox_input.exp_const_u64::<7>();

    let mut int_state = h.clone();
    int_state[0] = w0.clone();
    let intermediate = apply_matmul_internal(&int_state, mat_diag);

    let with_rc: [E; STATE_WIDTH] =
        core::array::from_fn(|i| intermediate[i].clone() + ark_ext[i].clone());
    let with_sbox: [E; STATE_WIDTH] =
        core::array::from_fn(|i| with_rc[i].clone().exp_const_u64::<7>());
    let next_state = apply_matmul_external(&with_sbox);

    (next_state, witness_check)
}
