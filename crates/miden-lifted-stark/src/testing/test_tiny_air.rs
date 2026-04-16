//! Integration tests for the lifted STARK prove/verify cycle using a minimal
//! single-column AIR with periodic columns and auxiliary traces.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    AirWitness, InstanceValidationError, ProverError, VerifierError,
    air::{
        AirBuilder, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
        WindowAccess,
    },
    prove_multi, prove_single,
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
    let _digest =
        verify_single(&config, &air, &public_values, &[], &output.proof, test_challenger())
            .expect("baseline proof should verify");

    // Extra field element should cause rejection
    let mut bad_proof = output.proof;
    let (mut fields, commitments) = bad_proof.transcript.into_parts();
    fields.push(Felt::ONE);
    bad_proof.transcript = TranscriptData::new(fields, commitments);

    let err = verify_single(&config, &air, &public_values, &[], &bad_proof, test_challenger())
        .expect_err("extra transcript data should fail verification");
    assert!(matches!(
        err,
        VerifierError::Transcript(crate::transcript::TranscriptError::TrailingData)
    ));
}

#[test]
fn malformed_log_trace_heights_is_rejected() {
    let config = test_config();
    let air = TinyAir::new(vec![]);

    let (trace, public_values) = instance(0, 4);

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

    // Push straight to the `pub(crate)` field to bypass
    // `InstanceShapes::from_trace_heights` and exercise the verifier-path
    // bound check in `validate_inputs`.
    let mut bad_proof = output.proof.clone();
    bad_proof.instance_shapes.log_trace_heights.push(2);
    bad_proof.instance_shapes.air_order.push(1);
    let err = verify_single(&config, &air, &public_values, &[], &bad_proof, test_challenger())
        .expect_err("extra log trace height should fail verification");
    assert!(matches!(
        err,
        VerifierError::Instance(InstanceValidationError::HeightCountMismatch {
            instances: 1,
            log_trace_heights: 2,
        })
    ));

    // Empty heights → air_order / instance count mismatch.
    let mut bad_proof = output.proof.clone();
    bad_proof.instance_shapes.log_trace_heights.clear();
    bad_proof.instance_shapes.air_order.clear();
    let err = verify_single(&config, &air, &public_values, &[], &bad_proof, test_challenger())
        .expect_err("empty log trace heights should fail verification");
    assert!(matches!(
        err,
        VerifierError::Instance(InstanceValidationError::HeightCountMismatch {
            instances: 1,
            log_trace_heights: 0,
        })
    ));

    // Out-of-range log height must surface as an error, not panic on
    // `1usize << log_h` or `two_adic_generator(log_h + log_blowup)`.
    let mut bad_proof = output.proof.clone();
    bad_proof.instance_shapes.log_trace_heights = vec![200];
    let err = verify_single(&config, &air, &public_values, &[], &bad_proof, test_challenger())
        .expect_err("oversized log trace height should fail verification");
    assert!(matches!(
        err,
        VerifierError::Instance(InstanceValidationError::LdeDomainExceedsTwoAdicity {
            log_h: 200,
            ..
        })
    ));

    // Boundary case: `log_h` fits the raw bound (`log_h ≤ TWO_ADICITY`) but
    // the LDE domain `log_h + log_blowup` does not. With `log_blowup = 2`
    // from `TEST_PCS_PARAMS` and `Felt::TWO_ADICITY = 32`, `31 + 2 = 33 > 32`
    // must be rejected before any `two_adic_generator` call on the LDE domain.
    let mut bad_proof = output.proof;
    bad_proof.instance_shapes.log_trace_heights = vec![31];
    let err = verify_single(&config, &air, &public_values, &[], &bad_proof, test_challenger())
        .expect_err("log_h + log_blowup exceeding two-adicity should fail verification");
    assert!(matches!(
        err,
        VerifierError::Instance(InstanceValidationError::LdeDomainExceedsTwoAdicity {
            log_h: 31,
            log_blowup: 2,
            ..
        })
    ));
}

#[test]
fn prover_rejects_non_power_of_two_trace_height() {
    // Build the witness directly (via `pub` fields) to skip the
    // power-of-two assertion in `AirWitness::new`. `InstanceShapes::from_trace_heights`
    // must reject it rather than panicking inside `log2_strict_u8`.
    let config = test_config();
    let air = TinyAir::new(vec![]);

    let trace =
        RowMajorMatrix::new(vec![Felt::from_u64(2), Felt::from_u64(16), Felt::from_u64(65536)], 1);
    let public_values = vec![Felt::from_u64(2)];
    let bad_witness = AirWitness {
        trace: &trace,
        public_values: &public_values,
        var_len_public_inputs: &[],
    };

    let result = prove_multi(&config, &[(&air, bad_witness, &TinyAuxBuilder)], test_challenger());
    match result {
        Err(ProverError::Instance(InstanceValidationError::InvalidTraceHeight { height: 3 })) => {},
        Err(other) => panic!("expected InvalidTraceHeight {{ height: 3 }}, got {other:?}"),
        Ok(_) => panic!("non-power-of-two trace height should fail proving"),
    }
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
// Unordered multi-trace tests (instances not in ascending height order)
// ---------------------------------------------------------------------------

#[test]
fn two_traces_reversed_order() {
    prove_and_verify(&TinyAir::new(vec![]), &TinyAuxBuilder, &[instance(1, 8), instance(0, 4)]);
}

#[test]
fn three_traces_descending_heights() {
    prove_and_verify(
        &TinyAir::new(vec![]),
        &TinyAuxBuilder,
        &[instance(2, 16), instance(1, 8), instance(0, 4)],
    );
}

#[test]
fn three_traces_shuffled_order() {
    prove_and_verify(
        &TinyAir::new(vec![]),
        &TinyAuxBuilder,
        &[instance(1, 8), instance(2, 16), instance(0, 4)],
    );
}

#[test]
fn periodic_columns_reversed_order() {
    prove_and_verify(&TinyAir::new(vec![2, 4]), &TinyAuxBuilder, &[instance(1, 8), instance(0, 4)]);
}

#[test]
fn air_order_reflects_caller_order() {
    let config = test_config();
    let air = TinyAir::new(vec![]);

    // Pass instances in reverse height order: [height=8, height=4].
    let (t0, pv0) = instance(0, 8);
    let (t1, pv1) = instance(1, 4);

    let w0 = AirWitness::new(&t0, &pv0, &[]);
    let w1 = AirWitness::new(&t1, &pv1, &[]);

    let output = prove_multi(
        &config,
        &[(&air, w0, &TinyAuxBuilder), (&air, w1, &TinyAuxBuilder)],
        test_challenger(),
    )
    .expect("proving should succeed");

    // Proof ordering is ascending height: [height=4, height=8].
    // Caller index 1 (height=4) is at position 0 in the proof's ordering.
    // Caller index 0 (height=8) is at position 1 in the proof's ordering.
    let air_order = output.proof.instance_shapes.air_order();
    assert_eq!(
        air_order,
        &[1, 0],
        "air_order should map ascending-height position → caller index"
    );

    // Log trace heights should be in ascending order.
    let log_heights = output.proof.instance_shapes.log_trace_heights();
    assert_eq!(log_heights, &[2, 3], "log heights should be ascending (4=2^2, 8=2^3)");
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
