//! Integration tests for the lifted STARK prove/verify cycle using a minimal
//! single-column AIR with periodic columns and auxiliary traces.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    DomainError, InstanceError, MultiAir, ProverStatement, ShapeError, Statement, VerifierError,
    air::{AirBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder, WindowAccess},
    order::TraceOrder,
    prove,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, generate_pow4_trace, prove_and_verify, test_challenger, test_config,
    },
    transcript::{TranscriptData, TranscriptError},
    verify,
};

// ---------------------------------------------------------------------------
// TinyAir: main[0] starts at public_values[0], each row is previous^4.
// Optional periodic columns with pattern [1, 0, ..., 0, 1] per period.
//
// All AIRs in a proof share the same public_values, so multi-trace tests
// give every instance an identical starting value.
// ---------------------------------------------------------------------------

const START: u64 = 2;

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

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        tiny_aux(main, challenges)
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

/// Aux build for TinyAir: aux column = challenge^{4^row}.
fn tiny_aux(
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

    let aux_values = vec![col_values[height - 1]];
    let aux_trace = RowMajorMatrix::new(col_values, 1);
    (aux_trace, aux_values)
}

struct TinyMultiAir {
    airs: Vec<TinyAir>,
}

impl MultiAir<Felt, QuadFelt> for TinyMultiAir {
    type Air = TinyAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

/// Build a [`ProverStatement`] for tests.
///
/// Returns `Err` if validation fails (so callers can exercise error paths).
fn tiny_prover_statement(
    airs: Vec<TinyAir>,
    traces: Vec<RowMajorMatrix<Felt>>,
    air_inputs: Vec<Felt>,
) -> Result<ProverStatement<Felt, QuadFelt, TinyMultiAir>, InstanceError> {
    let statement = Statement::new(TinyMultiAir { airs }, air_inputs, Vec::new())?;
    ProverStatement::new(statement, traces)
}

fn trace_of_height(height: usize) -> RowMajorMatrix<Felt> {
    generate_pow4_trace(Felt::from_u64(START), height)
}

// ---------------------------------------------------------------------------
// Single-trace tests
// ---------------------------------------------------------------------------

#[test]
fn single_trace() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![]), &pv, &[trace_of_height(8)]);
}

#[test]
fn malformed_transcript_is_rejected() {
    let config = test_config();
    let prover_statement = tiny_prover_statement(
        vec![TinyAir::new(vec![])],
        vec![trace_of_height(4)],
        vec![Felt::from_u64(START)],
    )
    .expect("valid");

    let output =
        prove(&config, &prover_statement, test_challenger()).expect("proving should succeed");

    // Baseline should verify
    let _digest = verify(&config, prover_statement.statement(), &output.proof, test_challenger())
        .expect("baseline proof should verify");

    // Extra field element should cause rejection
    let mut bad_proof = output.proof;
    let (mut fields, commitments) = bad_proof.transcript.into_parts();
    fields.push(Felt::ONE);
    bad_proof.transcript = TranscriptData::new(fields, commitments);

    let err = verify(&config, prover_statement.statement(), &bad_proof, test_challenger())
        .expect_err("extra transcript data should fail verification");
    assert!(matches!(err, VerifierError::Transcript(TranscriptError::TrailingData)));
}

#[test]
fn malformed_log_trace_heights_is_rejected() {
    let config = test_config();
    let prover_statement = tiny_prover_statement(
        vec![TinyAir::new(vec![])],
        vec![trace_of_height(4)],
        vec![Felt::from_u64(START)],
    )
    .expect("valid");
    let statement = prover_statement.statement();

    let output =
        prove(&config, &prover_statement, test_challenger()).expect("proving should succeed");

    // Poke the `pub(crate)` `log_trace_heights` directly to feed the verifier
    // malformed shapes that bypass `ProverStatement` construction — the cases
    // that would otherwise panic or overflow rather than return a clean error.

    // log_h = 200 trips the `usize` overflow guard in `TraceOrder::from_log_heights`,
    // before `1usize << log_h` could overflow.
    let mut bad_proof = output.proof.clone();
    bad_proof.log_trace_heights = vec![200];
    let err = verify(&config, statement, &bad_proof, test_challenger())
        .expect_err("oversized log trace height should fail verification");
    assert!(matches!(
        err,
        VerifierError::Shape(ShapeError::LogTraceHeightTooLarge { log_h: 200, .. })
    ));

    // log_h = 30 with log_blowup = 3 and Felt::TWO_ADICITY = 32 overflows the LDE
    // domain (33 > 32), rejected by `try_canonical` before any generator lookup.
    let mut bad_proof = output.proof;
    bad_proof.log_trace_heights = vec![30];
    let err = verify(&config, statement, &bad_proof, test_challenger())
        .expect_err("log_h + log_blowup exceeding two-adicity should fail verification");
    assert!(matches!(err, VerifierError::Domain(DomainError::LdeOrderTooLarge { .. })));
}

// ---------------------------------------------------------------------------
// Multi-trace tests
// ---------------------------------------------------------------------------

#[test]
fn two_traces_same_height() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![]), &pv, &[trace_of_height(8), trace_of_height(8)]);
}

#[test]
fn two_traces_different_heights() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![]), &pv, &[trace_of_height(4), trace_of_height(8)]);
}

#[test]
fn three_traces_ascending_heights() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(
        &TinyAir::new(vec![]),
        &pv,
        &[trace_of_height(4), trace_of_height(8), trace_of_height(16)],
    );
}

// ---------------------------------------------------------------------------
// Unordered multi-trace tests (instances not in ascending height order)
// ---------------------------------------------------------------------------

#[test]
fn two_traces_reversed_order() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![]), &pv, &[trace_of_height(8), trace_of_height(4)]);
}

#[test]
fn three_traces_descending_heights() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(
        &TinyAir::new(vec![]),
        &pv,
        &[trace_of_height(16), trace_of_height(8), trace_of_height(4)],
    );
}

#[test]
fn three_traces_shuffled_order() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(
        &TinyAir::new(vec![]),
        &pv,
        &[trace_of_height(8), trace_of_height(16), trace_of_height(4)],
    );
}

#[test]
fn periodic_columns_reversed_order() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![2, 4]), &pv, &[trace_of_height(8), trace_of_height(4)]);
}

#[test]
fn air_order_reflects_caller_order() {
    let config = test_config();
    let prover_statement = tiny_prover_statement(
        vec![TinyAir::new(vec![]), TinyAir::new(vec![])],
        // Pass traces in reverse height order: [height=8, height=4].
        vec![trace_of_height(8), trace_of_height(4)],
        vec![Felt::from_u64(START)],
    )
    .expect("valid");

    let output =
        prove(&config, &prover_statement, test_challenger()).expect("proving should succeed");

    // The proof carries heights in instance order: [height=8, height=4]
    // → [log_h=3, log_h=2]. The proof's AIR ordering itself is implicit
    // (recomputed from the heights via TraceOrder).
    assert_eq!(
        output.proof.log_trace_heights.as_slice(),
        &[3, 2],
        "log heights should be in instance order (8=2^3, 4=2^2)"
    );

    // The derived proof ordering is ascending height: instance index 1
    // (log_h=2) ends up at proof position 0, instance index 0 (log_h=3) at
    // position 1.
    let trace_order = TraceOrder::from_log_heights::<Felt, QuadFelt, _>(
        prover_statement.statement().airs(),
        output.proof.log_trace_heights,
    )
    .expect("valid heights");
    assert_eq!(
        trace_order.instance_indices(),
        &[1, 0],
        "trace order should map ascending-height position → instance index"
    );
}

// ---------------------------------------------------------------------------
// Periodic column tests
// ---------------------------------------------------------------------------

#[test]
fn single_periodic_column() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![2]), &pv, &[trace_of_height(8)]);
}

#[test]
fn periodic_column_period_4() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![4]), &pv, &[trace_of_height(8)]);
}

#[test]
fn multiple_periodic_columns() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![2, 4]), &pv, &[trace_of_height(8)]);
}

#[test]
fn periodic_columns_multi_trace_same_height() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![2]), &pv, &[trace_of_height(8), trace_of_height(8)]);
}

#[test]
fn periodic_columns_multi_trace_different_heights() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(&TinyAir::new(vec![2, 4]), &pv, &[trace_of_height(4), trace_of_height(8)]);
}

#[test]
fn periodic_columns_three_traces() {
    let pv = vec![Felt::from_u64(START)];
    prove_and_verify(
        &TinyAir::new(vec![2, 4]),
        &pv,
        &[trace_of_height(4), trace_of_height(8), trace_of_height(16)],
    );
}
