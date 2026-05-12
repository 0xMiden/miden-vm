//! End-to-end prove+verify tests for the per-AIR quotient-degree optimization.
//!
//! Exercises the branch in the prover loop where an AIR's native quotient degree
//! `D_j` is strictly less than the global `D_max`, so the prover divides on the
//! native domain and then `upsample_evals` lifts the resulting quotient evaluations.
//! The unit tests on `upsample_evals` itself verify the helper matches a direct
//! coset DFT; the tests here verify the **integration** path: that a proof built
//! via the upsample branch round-trips correctly through the verifier.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    AirWitness,
    air::{AirBuilder, AuxBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess},
    testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, prove_and_verify_instances},
};

// ---------------------------------------------------------------------------
// PowerAir: single-column AIR with `next[0] = local[0]^power`.
//
// Powers {2, 5, 9} give natural `log_qd` of {0, 2, 3}.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PowerAir {
    power: u64,
}

impl BaseAir<Felt> for PowerAir {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for PowerAir {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.current_slice().to_vec(), main.next_slice().to_vec());

        let x: AB::Expr = local[0].into();
        let x_power: AB::Expr = match self.power {
            2 => x.clone() * x,
            5 => x.clone().exp_power_of_2(2) * x,
            9 => x.clone().exp_power_of_2(3) * x,
            _ => unreachable!("tests only use power in {{2, 5, 9}}"),
        };
        builder.when_transition().assert_eq(next[0].into(), x_power);

        // Trivial aux: aux_local == challenge (extension-field identity, degree 1).
        let aux = builder.permutation();
        let aux_local = aux.current_slice().to_vec();
        let challenge = builder.permutation_randomness()[0];
        let aux_expr: AB::ExprEF = aux_local[0].into();
        let challenge_expr: AB::ExprEF = challenge.into();
        builder.assert_eq_ext(aux_expr, challenge_expr);
    }
}

// ---------------------------------------------------------------------------
// PeriodicPowerAir: same recurrence as PowerAir plus a single period-2 periodic
// column with a first-row boundary constraint. Used to exercise
// `PeriodicLde::build` on the native quotient domain alongside the upsample
// path.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PeriodicPowerAir {
    power: u64,
}

impl BaseAir<Felt> for PeriodicPowerAir {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for PeriodicPowerAir {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        // Period 2: entries [1, 0] repeat across the trace.
        vec![vec![Felt::ONE, Felt::ZERO]]
    }

    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.current_slice().to_vec(), main.next_slice().to_vec());
        let periodic = builder.periodic_values().to_vec();

        let x: AB::Expr = local[0].into();
        let x_power: AB::Expr = match self.power {
            3 => x.clone().exp_power_of_2(1) * x,
            5 => x.clone().exp_power_of_2(2) * x,
            _ => unreachable!("periodic test uses power in {{3, 5}}"),
        };
        builder.when_transition().assert_eq(next[0].into(), x_power);

        // Periodic column starts at 1 on the first trace row.
        let p: AB::Expr = periodic[0].into();
        builder.when_first_row().assert_one(p);

        // Trivial aux: aux_local == challenge.
        let aux = builder.permutation();
        let aux_local = aux.current_slice().to_vec();
        let challenge = builder.permutation_randomness()[0];
        let aux_expr: AB::ExprEF = aux_local[0].into();
        let challenge_expr: AB::ExprEF = challenge.into();
        builder.assert_eq_ext(aux_expr, challenge_expr);
    }
}

// ---------------------------------------------------------------------------
// Aux builder (trivial constant-challenge column).
// ---------------------------------------------------------------------------

struct TrivialAuxBuilder;

impl AuxBuilder<Felt, QuadFelt> for TrivialAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let height = main.height();
        let column = vec![challenges[0]; height];
        (RowMajorMatrix::new(column, 1), vec![])
    }
}

// ---------------------------------------------------------------------------
// Trace generator for `next = local^power`.
// ---------------------------------------------------------------------------

fn generate_pow_trace(power: u64, start: Felt, height: usize) -> RowMajorMatrix<Felt> {
    let mut data = Vec::with_capacity(height);
    let mut cur = start;
    for _ in 0..height {
        data.push(cur);
        cur = cur.exp_u64(power);
    }
    RowMajorMatrix::new(data, 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Runs a two-AIR prove+verify round-trip with a `PowerAir` of each given power
/// and trace height. Shared body for the `PowerAir` upsample-path tests below.
fn run_upsample_case(low_power: u64, low_height: usize, high_power: u64, high_height: usize) {
    let low = PowerAir { power: low_power };
    let high = PowerAir { power: high_power };

    let t_low = generate_pow_trace(low_power, Felt::from_u64(7), low_height);
    let t_high = generate_pow_trace(high_power, Felt::from_u64(11), high_height);

    let w_low = AirWitness::new(&t_low, &[], &[]);
    let w_high = AirWitness::new(&t_high, &[], &[]);

    let builder = TrivialAuxBuilder;
    prove_and_verify_instances(&[(&low, w_low, &builder), (&high, w_high, &builder)]);
}

/// `d = 5` (log_qd = 2) upsampled to log_qd = 3 alongside a `d = 9` AIR at
/// equal trace heights.
#[test]
fn upsample_fires_on_d5_under_d9() {
    run_upsample_case(5, 16, 9, 16);
}

/// Low-degree AIR on the taller trace. The `log_qd = 0` AIR is processed last
/// (tallest) and gets upsampled by 3 bits onto the final accumulator height.
#[test]
fn upsample_fires_low_degree_on_taller_trace() {
    run_upsample_case(2, 64, 9, 16);
}

/// Complementary: high-degree AIR on the taller trace. Upsample fires on the
/// shorter, lower-degree one; the tall AIR skips upsample.
#[test]
fn upsample_fires_high_degree_on_taller_trace() {
    run_upsample_case(2, 16, 9, 64);
}

/// Mixed-degree upsample path with periodic columns on both AIRs. Exercises
/// `PeriodicLde::build` on the native quotient domain.
#[test]
fn upsample_fires_with_periodic_columns() {
    let low = PeriodicPowerAir { power: 3 };
    let high = PeriodicPowerAir { power: 5 };

    let t_low = generate_pow_trace(3, Felt::from_u64(7), 16);
    let t_high = generate_pow_trace(5, Felt::from_u64(11), 16);

    let w_low = AirWitness::new(&t_low, &[], &[]);
    let w_high = AirWitness::new(&t_high, &[], &[]);

    let builder = TrivialAuxBuilder;
    prove_and_verify_instances(&[(&low, w_low, &builder), (&high, w_high, &builder)]);
}
