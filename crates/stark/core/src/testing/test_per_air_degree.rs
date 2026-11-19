//! End-to-end prove+verify tests for the per-AIR quotient-degree optimization.
//!
//! Exercises the branch in the prover loop where an AIR's native quotient degree
//! `D_j` is strictly less than the global `D_max`, so the prover divides on the
//! native domain and then `upsample_evals` lifts the resulting quotient evaluations.

extern crate alloc;

use alloc::{borrow::Cow, vec, vec::Vec};
use core::convert::Infallible;

use p3_field::{Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    air,
    air::{LiftedAirBuilder as _, ProverStatement, Statement},
    domain::log_quotient_degree,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, TestMultiAir, prove_and_verify_statement,
    },
};

// ---------------------------------------------------------------------------
// PowerAir: single-column AIR with `next[0] = local[0]^power`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PowerAir {
    power: u64,
}

impl air::LiftedAir for PowerAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let x = frame.main.current[0].dup();
        let x_power = match self.power {
            2 => x.clone() * x,
            5 => x.clone().exp_power_of_2(2) * x,
            9 => x.clone().exp_power_of_2(3) * x,
            _ => unreachable!("tests only use power in {{2, 5, 9}}"),
        };
        builder.when(frame.transition()).assert_eq(frame.main.next[0].dup(), x_power);

        // Trivial aux: aux_local == challenge (extension-field identity, degree 1).
        builder.assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl air::ProverAir<QuadFelt> for PowerAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        Ok(air::AuxTrace {
            columns: RowMajorMatrix::new(vec![inputs.challenges[0]; inputs.main.height()], 1),
            exports: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// PeriodicPowerAir
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PeriodicPowerAir {
    power: u64,
}

impl air::LiftedAir for PeriodicPowerAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::ZERO]]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let x = frame.main.current[0].dup();
        let x_power = match self.power {
            3 => x.clone().exp_power_of_2(1) * x,
            5 => x.clone().exp_power_of_2(2) * x,
            _ => unreachable!("periodic test uses power in {{3, 5}}"),
        };
        builder.when(frame.transition()).assert_eq(frame.main.next[0].dup(), x_power);

        // Periodic column starts at 1 on the first trace row.
        builder.when(frame.first_row()).assert_one(frame.periodic[0].dup());

        // Trivial aux: aux_local == challenge (extension-field identity, degree 1).
        builder.assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl air::ProverAir<QuadFelt> for PeriodicPowerAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        Ok(air::AuxTrace {
            columns: RowMajorMatrix::new(vec![inputs.challenges[0]; inputs.main.height()], 1),
            exports: vec![],
        })
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

#[test]
fn one_chunk_quadratic_quotient_proves() {
    let kernel = air::DirectKernel::new(PowerAir { power: 2 }).unwrap();
    assert_eq!(log_quotient_degree(&kernel).unwrap(), 0);
    let trace = generate_pow_trace(2, Felt::from_u64(7), 16);
    let statement = Statement::new(TestMultiAir::new(vec![kernel]), vec![], vec![]).unwrap();
    let prover_statement = ProverStatement::new(statement, vec![trace]).unwrap();
    prove_and_verify_statement(prover_statement);
}

fn run_upsample_case(low_power: u64, low_height: usize, high_power: u64, high_height: usize) {
    let low = PowerAir { power: low_power };
    let high = PowerAir { power: high_power };

    let t_low = generate_pow_trace(low_power, Felt::from_u64(7), low_height);
    let t_high = generate_pow_trace(high_power, Felt::from_u64(11), high_height);

    let statement = Statement::new(
        TestMultiAir::new(vec![
            air::DirectKernel::new(low).unwrap(),
            air::DirectKernel::new(high).unwrap(),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![t_low, t_high]).unwrap();
    prove_and_verify_statement(prover_statement);
}

#[test]
fn quotient_upsampling_handles_mixed_degrees_and_heights() {
    for (low_power, low_height, high_height) in [(5, 16, 16), (2, 64, 16), (2, 16, 64)] {
        run_upsample_case(low_power, low_height, 9, high_height);
    }
}

#[test]
fn upsample_fires_with_periodic_columns() {
    let low = PeriodicPowerAir { power: 3 };
    let high = PeriodicPowerAir { power: 5 };

    let t_low = generate_pow_trace(3, Felt::from_u64(7), 16);
    let t_high = generate_pow_trace(5, Felt::from_u64(11), 16);

    let statement = Statement::new(
        TestMultiAir::new(vec![
            air::DirectKernel::new(low).unwrap(),
            air::DirectKernel::new(high).unwrap(),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![t_low, t_high]).unwrap();
    prove_and_verify_statement(prover_statement);
}
