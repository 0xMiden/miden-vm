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

use crate::air::native::LiftedAirBuilder as _;
use crate::{
    air::{MultiAir, ProverStatement, Statement, native},
    domain::log_quotient_degree,
    testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, prove_and_verify_statement},
};

// ---------------------------------------------------------------------------
// PowerAir: single-column AIR with `next[0] = local[0]^power`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PowerAir {
    power: u64,
}

impl native::LiftedAir for PowerAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
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

impl native::ProverAir<QuadFelt> for PowerAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        Ok(native::AuxTrace {
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

impl native::LiftedAir for PeriodicPowerAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::ZERO]]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
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

impl native::ProverAir<QuadFelt> for PeriodicPowerAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        Ok(native::AuxTrace {
            columns: RowMajorMatrix::new(vec![inputs.challenges[0]; inputs.main.height()], 1),
            exports: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// MultiAir: trivial constant-challenge aux column for each trace.
// ---------------------------------------------------------------------------

struct TwoTraceMultiAir<A> {
    airs: Vec<A>,
}

impl<A> TwoTraceMultiAir<A> {
    fn new(airs: Vec<A>) -> Self {
        Self { airs }
    }
}

impl<A> MultiAir<Felt, QuadFelt> for TwoTraceMultiAir<A>
where
    A: native::AirKernel<F = Felt>,
{
    type Air = A;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
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
fn quadratic_air_uses_one_quotient_chunk() {
    assert_eq!(
        log_quotient_degree(&native::DirectKernel::new(PowerAir { power: 2 }).unwrap()).unwrap(),
        0
    );
}

#[test]
fn one_chunk_quadratic_quotient_proves() {
    let air = PowerAir { power: 2 };
    let trace = generate_pow_trace(2, Felt::from_u64(7), 16);

    let statement = Statement::new(
        TwoTraceMultiAir::new(vec![native::DirectKernel::new(air).unwrap()]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![trace]).unwrap();
    prove_and_verify_statement(prover_statement);
}

fn run_upsample_case(low_power: u64, low_height: usize, high_power: u64, high_height: usize) {
    let low = PowerAir { power: low_power };
    let high = PowerAir { power: high_power };

    let t_low = generate_pow_trace(low_power, Felt::from_u64(7), low_height);
    let t_high = generate_pow_trace(high_power, Felt::from_u64(11), high_height);

    let statement = Statement::new(
        TwoTraceMultiAir::new(vec![
            native::DirectKernel::new(low).unwrap(),
            native::DirectKernel::new(high).unwrap(),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![t_low, t_high]).unwrap();
    prove_and_verify_statement(prover_statement);
}

#[test]
fn upsample_fires_on_d5_under_d9() {
    run_upsample_case(5, 16, 9, 16);
}

#[test]
fn upsample_fires_low_degree_on_taller_trace() {
    run_upsample_case(2, 64, 9, 16);
}

#[test]
fn upsample_fires_high_degree_on_taller_trace() {
    run_upsample_case(2, 16, 9, 64);
}

#[test]
fn upsample_fires_with_periodic_columns() {
    let low = PeriodicPowerAir { power: 3 };
    let high = PeriodicPowerAir { power: 5 };

    let t_low = generate_pow_trace(3, Felt::from_u64(7), 16);
    let t_high = generate_pow_trace(5, Felt::from_u64(11), 16);

    let statement = Statement::new(
        TwoTraceMultiAir::new(vec![
            native::DirectKernel::new(low).unwrap(),
            native::DirectKernel::new(high).unwrap(),
        ]),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![t_low, t_high]).unwrap();
    prove_and_verify_statement(prover_statement);
}

#[test]
fn native_power_sources_preserve_witness_and_direct_symbolic_order() {
    use native::AirKernel;

    for power in [2, 5, 9] {
        let source = PowerAir { power };
        let expected = native::capture_with::<_, QuadFelt>(&source).unwrap();
        assert_eq!(expected.descriptor.analysis().layout().base_indices(), &[0]);
        assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[1]);
        let kernel = native::DirectKernel::new(source).unwrap();
        let main = generate_pow_trace(power, Felt::from_u64(2), 4);
        let challenges = [QuadFelt::from_u64(7)];
        let aux = native::ProverAir::build_aux_trace(
            &kernel,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        assert_eq!(aux.columns.values, vec![QuadFelt::from_u64(7); 4]);
        assert!(aux.exports.is_empty());
        let observed = native::capture_from_spec::<Felt, QuadFelt>(
            kernel.descriptor().spec().as_borrowed(),
            |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
        )
        .unwrap();
        assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
        assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
    }

    for power in [3, 5] {
        let source = PeriodicPowerAir { power };
        let expected = native::capture_with::<_, QuadFelt>(&source).unwrap();
        assert_eq!(
            expected.descriptor.spec().periodic_columns.as_ref(),
            &[vec![Felt::ONE, Felt::ZERO]]
        );
        assert_eq!(expected.descriptor.analysis().layout().base_indices(), &[0, 1]);
        assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[2]);
        let kernel = native::DirectKernel::new(source).unwrap();
        let main = generate_pow_trace(power, Felt::from_u64(2), 4);
        let challenges = [QuadFelt::from_u64(7)];
        let aux = native::ProverAir::build_aux_trace(
            &kernel,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        assert_eq!(aux.columns.values, vec![QuadFelt::from_u64(7); 4]);
        assert!(aux.exports.is_empty());
        let observed = native::capture_from_spec::<Felt, QuadFelt>(
            kernel.descriptor().spec().as_borrowed(),
            |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
        )
        .unwrap();
        assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
        assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
    }
}
