//! Integration tests for the lifted STARK prove/verify cycle using a minimal
//! single-column AIR with periodic columns and auxiliary traces.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    VerifierError,
    air::{
        AirBuilder, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
        WindowAccess, log2_strict_u8,
    },
    prove_single,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, generate_pow4_trace, prove_and_verify, test_challenger, test_config,
    },
    transcript::TranscriptData,
    verify_single,
};

// ---------------------------------------------------------------------------
// TinyAir: main[0] starts at public_values[0], each row is previous^4.
// Optional periodic columns with pattern [1, 0, ..., 0, 1] per period.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct TinyAir {
    /// Pre-computed periodic column data.
    periodic_cols: Vec<Vec<Felt>>,
}

impl TinyAir {
    fn new(periods: Vec<usize>) -> Self {
        let periodic_cols = periods
            .iter()
            .map(|&p| {
                let mut col = vec![Felt::ZERO; p];
                col[0] = Felt::ONE;
                col[p - 1] = Felt::ONE;
                col
            })
            .collect();
        Self { periodic_cols }
    }
}

impl BaseAir<Felt> for TinyAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for TinyAir {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        self.periodic_cols.clone()
    }

    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let start = builder.public_values()[0];
        let periodic = builder.periodic_values().to_vec();
        let (local, next) = (main.current_slice(), main.next_slice());

        // First row: main[0] = public_values[0]
        builder.when_first_row().assert_eq(local[0], start);

        // Transition: main_next = main^4
        let main_pow4: AB::Expr = local[0].into().exp_power_of_2(2);
        builder.when_transition().assert_eq(next[0], main_pow4);

        // Periodic column constraints: first and last row see 1
        for p in &periodic {
            let p_expr: AB::Expr = (*p).into();
            builder.when_first_row().assert_one(p_expr.clone());
            builder.when_last_row().assert_one(p_expr);
        }

        // Aux trace constraints
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();

        let aux_local_ef: AB::ExprEF = aux_local[0].into();
        builder.when_first_row().assert_eq_ext(aux_local_ef.clone(), challenge);

        let aux_pow4: AB::ExprEF = aux_local_ef.exp_power_of_2(2);
        builder.when_transition().assert_eq_ext(aux_next[0].into(), aux_pow4);
    }
}

/// AuxBuilder for TinyAir: aux column = challenge^{4^row}.
struct TinyAuxBuilder;

impl AuxBuilder<Felt, QuadFelt> for TinyAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let height = main.height();
        let challenge = challenges[0];

        let mut col_values = Vec::with_capacity(height);
        let mut current = challenge;
        for _ in 0..height {
            col_values.push(current);
            current = current.exp_power_of_2(2);
        }

        let aux_trace = RowMajorMatrix::new(col_values.clone(), 1);
        let aux_values = vec![col_values[height - 1]];
        (aux_trace, aux_values)
    }
}

/// Build a (trace, public_values) pair for instance `idx`.
fn instance(idx: usize, height: usize) -> (RowMajorMatrix<Felt>, Vec<Felt>) {
    let start = Felt::from_u64((idx + 2) as u64);
    (generate_pow4_trace(start, height), vec![start])
}

// ---------------------------------------------------------------------------
// Single-trace tests
// ---------------------------------------------------------------------------

#[test]
fn single_trace() {
    prove_and_verify(&TinyAir::new(vec![]), &TinyAuxBuilder, &[instance(0, 8)]);
}

#[test]
fn malformed_transcript_is_rejected() {
    let config = test_config();
    let air = TinyAir::new(vec![]);

    let (trace, public_values) = instance(0, 4);
    let log_trace_height = log2_strict_u8(trace.height());

    let output = prove_single(
        &config,
        &air,
        &trace,
        &public_values,
        &[],
        &TinyAuxBuilder,
        test_challenger(),
    )
    .expect("proving should succeed");

    // Baseline should verify
    let _digest = verify_single(
        &config,
        &air,
        log_trace_height,
        &public_values,
        &[],
        &output.proof,
        test_challenger(),
    )
    .expect("baseline proof should verify");

    // Extra field element should cause rejection
    let (mut fields, commitments) = output.proof.clone().into_parts();
    fields.push(Felt::ONE);
    let bad_transcript = TranscriptData::new(fields, commitments);

    let err = verify_single(
        &config,
        &air,
        log_trace_height,
        &public_values,
        &[],
        &bad_transcript,
        test_challenger(),
    )
    .expect_err("extra transcript data should fail verification");
    assert!(matches!(
        err,
        VerifierError::Transcript(crate::transcript::TranscriptError::TrailingData)
    ));
}

// ---------------------------------------------------------------------------
// Multi-trace tests
// ---------------------------------------------------------------------------

#[test]
fn two_traces_same_height() {
    prove_and_verify(&TinyAir::new(vec![]), &TinyAuxBuilder, &[instance(0, 8), instance(1, 8)]);
}

#[test]
fn two_traces_different_heights() {
    prove_and_verify(&TinyAir::new(vec![]), &TinyAuxBuilder, &[instance(0, 4), instance(1, 8)]);
}

#[test]
fn three_traces_ascending_heights() {
    prove_and_verify(
        &TinyAir::new(vec![]),
        &TinyAuxBuilder,
        &[instance(0, 4), instance(1, 8), instance(2, 16)],
    );
}

// ---------------------------------------------------------------------------
// Periodic column tests
// ---------------------------------------------------------------------------

#[test]
fn single_periodic_column() {
    prove_and_verify(&TinyAir::new(vec![2]), &TinyAuxBuilder, &[instance(0, 8)]);
}

#[test]
fn periodic_column_period_4() {
    prove_and_verify(&TinyAir::new(vec![4]), &TinyAuxBuilder, &[instance(0, 8)]);
}

#[test]
fn multiple_periodic_columns() {
    prove_and_verify(&TinyAir::new(vec![2, 4]), &TinyAuxBuilder, &[instance(0, 8)]);
}

#[test]
fn periodic_columns_multi_trace_same_height() {
    prove_and_verify(&TinyAir::new(vec![2]), &TinyAuxBuilder, &[instance(0, 8), instance(1, 8)]);
}

#[test]
fn periodic_columns_multi_trace_different_heights() {
    prove_and_verify(&TinyAir::new(vec![2, 4]), &TinyAuxBuilder, &[instance(0, 4), instance(1, 8)]);
}

#[test]
fn periodic_columns_three_traces() {
    prove_and_verify(
        &TinyAir::new(vec![2, 4]),
        &TinyAuxBuilder,
        &[instance(0, 4), instance(1, 8), instance(2, 16)],
    );
}
