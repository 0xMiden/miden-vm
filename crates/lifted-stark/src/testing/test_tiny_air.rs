//! Integration tests for the lifted STARK prove/verify cycle using a minimal
//! single-column AIR with periodic columns and auxiliary traces.

use alloc::{borrow::Cow, vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    ProverInstance, VerifierError, VerifierInstance,
    air::{
        AirBuilder, BaseAir, ExtensionBuilder, InstanceError, LiftedAir, LiftedAirBuilder,
        ProverStatement, Statement, WindowAccess,
    },
    domain::DomainError,
    order::{ShapeError, TraceOrder},
    proof::{TranscriptData, TranscriptError},
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, TestMultiAir, generate_pow4_trace, prove_and_verify, test_challenger,
        test_config,
    },
};

// ---------------------------------------------------------------------------
// TinyAir: main[0] starts at the sum of this AIR's public values; each row is previous^4.
// Optional periodic columns with pattern [1, 0, ..., 0, 1] per period.
// ---------------------------------------------------------------------------

const START: u64 = 2;

#[derive(Clone, Debug)]
struct TinyAir {
    /// Pre-computed periodic column data.
    periodic_cols: Vec<Vec<Felt>>,
    num_public_values: usize,
    /// Offset the first auxiliary witness value without changing its constraint.
    aux_offset: Felt,
}

impl TinyAir {
    fn new(periods: impl IntoIterator<Item = usize>) -> Self {
        let periodic_cols = periods
            .into_iter()
            .map(|p| {
                let mut col = vec![Felt::ZERO; p];
                col[0] = Felt::ONE;
                col[p - 1] = Felt::ONE;
                col
            })
            .collect();
        Self {
            periodic_cols,
            num_public_values: 1,
            aux_offset: Felt::ZERO,
        }
    }
}

impl BaseAir<Felt> for TinyAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        self.num_public_values
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(self.periodic_cols.clone())
    }
}

impl LiftedAir<Felt, QuadFelt> for TinyAir {
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
        air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let (mut trace, values) = tiny_aux(
            main,
            challenges[0] + QuadFelt::from(air_inputs.iter().copied().sum::<Felt>()),
        );
        trace.values[0] += QuadFelt::from(self.aux_offset);
        (trace, values)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let public_sum = builder
            .public_values()
            .iter()
            .fold(AB::Expr::ZERO, |sum, &value| sum + Into::<AB::Expr>::into(value));
        let periodic = builder.periodic_values().to_vec();
        let (local, next) = (main.current_slice(), main.next_slice());

        // First row: main[0] is the sum of this AIR's public values.
        builder.when_first_row().assert_eq(local[0], public_sum.clone());

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
        let public_sum_ext: AB::ExprEF = public_sum.into();
        builder
            .when_first_row()
            .assert_eq_ext(aux_local_ef.clone(), challenge + public_sum_ext);

        let aux_pow4: AB::ExprEF = aux_local_ef.exp_power_of_2(2);
        builder.when_transition().assert_eq_ext(aux_next[0].into(), aux_pow4);
    }
}

/// Aux build for TinyAir: aux column = challenge^{4^row}.
fn tiny_aux(
    main: &RowMajorMatrix<Felt>,
    challenge: QuadFelt,
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    let height = main.height();

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

/// Build a [`ProverStatement`] for tests.
///
/// Returns `Err` if validation fails (so callers can exercise error paths).
fn tiny_prover_statement(
    airs: Vec<TinyAir>,
    traces: Vec<RowMajorMatrix<Felt>>,
    air_inputs: Vec<(usize, Vec<Felt>)>,
) -> Result<ProverStatement<Felt, QuadFelt, TestMultiAir<TinyAir>>, InstanceError> {
    let statement = Statement::new(TestMultiAir::new(airs), air_inputs, Vec::new())?;
    ProverStatement::new(statement, traces)
}

fn trace_of_height(height: usize) -> RowMajorMatrix<Felt> {
    generate_pow4_trace(Felt::from_u64(START), height)
}

#[test]
fn statement_inputs_are_indexed_and_required() {
    let cases = [
        (
            vec![0, 1, 0, 2, 0],
            vec![(3, vec![7, 11]), (1, vec![3])],
            vec![vec![], vec![3], vec![], vec![7, 11], vec![]],
        ),
        (
            vec![1, 2, 1],
            vec![(2, vec![7]), (0, vec![3]), (1, vec![0, 0])],
            vec![vec![3], vec![0, 0], vec![7]],
        ),
        (vec![0, 0], vec![], vec![vec![], vec![]]),
        (vec![2], vec![(0, vec![0, 0])], vec![vec![0, 0]]),
        (vec![0, 0], vec![(1, vec![])], vec![vec![], vec![]]),
    ];
    for (counts, entries, expected) in cases {
        let airs = counts
            .into_iter()
            .map(|num_public_values| TinyAir { num_public_values, ..TinyAir::new([]) })
            .collect();
        let entries = entries
            .into_iter()
            .map(|(i, values)| (i, values.into_iter().map(Felt::from_u64).collect()))
            .collect();
        let statement =
            Statement::<Felt, QuadFelt, _>::new(TestMultiAir::new(airs), entries, Vec::new())
                .unwrap();
        crate::air::debug::assert_multi_air_valid(statement.multi_air());
        let expected: Vec<Vec<_>> = expected
            .into_iter()
            .map(|values| values.into_iter().map(Felt::from_u64).collect())
            .collect();
        assert_eq!(statement.air_inputs(), expected);
    }

    let statement = |entries| {
        Statement::<Felt, QuadFelt, _>::new(
            TestMultiAir::new(vec![
                TinyAir { num_public_values: 2, ..TinyAir::new([]) },
                TinyAir { num_public_values: 0, ..TinyAir::new([]) },
            ]),
            entries,
            Vec::new(),
        )
    };
    for (entries, expected, actual) in [
        (vec![], 2, 0),
        (vec![(1, vec![])], 2, 0),
        (vec![(0, vec![])], 2, 0),
        (vec![(0, vec![Felt::ZERO])], 2, 1),
        (vec![(0, vec![Felt::ZERO; 3])], 2, 3),
        (vec![(0, vec![Felt::ZERO; 2]), (1, vec![Felt::ZERO])], 0, 1),
    ] {
        assert!(matches!(
            statement(entries),
            Err(InstanceError::PublicValuesLengthMismatch { expected: e, actual: a })
                if e == expected && a == actual
        ));
    }
    for entries in [
        vec![(2, vec![])],
        vec![(usize::MAX, vec![])],
        vec![(1, vec![]), (1, vec![])],
        vec![(0, vec![Felt::ZERO; 2]), (0, vec![Felt::ZERO; 2])],
    ] {
        assert!(matches!(statement(entries), Err(InstanceError::InvalidPublicInputs)));
    }
}

// ---------------------------------------------------------------------------
// Single-trace tests
// ---------------------------------------------------------------------------

#[test]
fn prover_statement_rejects_one_row_trace() {
    assert!(matches!(
        tiny_prover_statement(
            vec![TinyAir::new(vec![])],
            vec![trace_of_height(1)],
            vec![(0, vec![Felt::from_u64(START)])],
        ),
        Err(InstanceError::TraceHeightTooSmall { air: 0, height: 1 })
    ));
}

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
        vec![(0, vec![Felt::from_u64(START)])],
    )
    .expect("valid");

    let prover_instance =
        ProverInstance::new(&config, prover_statement, None).expect("no preprocessed columns");
    let (output, statement) =
        prover_instance.prove(test_challenger()).expect("proving should succeed");

    // Baseline should verify
    let baseline_statement =
        VerifierInstance::new(&config, &statement, None).expect("no preprocessed columns");
    let _digest = baseline_statement
        .verify(&output.proof, test_challenger())
        .expect("baseline proof should verify");

    // Extra field element should cause rejection
    let mut bad_proof = output.proof;
    let (mut fields, commitments) = bad_proof.transcript.into_parts();
    fields.push(Felt::ONE);
    bad_proof.transcript = TranscriptData::new(fields, commitments);

    let err = baseline_statement
        .verify(&bad_proof, test_challenger())
        .expect_err("extra transcript data should fail verification");
    assert!(matches!(err, VerifierError::Transcript(TranscriptError::TrailingData)));
}

#[test]
fn malformed_log_trace_heights_is_rejected() {
    let config = test_config();
    let prover_statement = tiny_prover_statement(
        vec![TinyAir::new(vec![])],
        vec![trace_of_height(4)],
        vec![(0, vec![Felt::from_u64(START)])],
    )
    .expect("valid");
    let prover_instance =
        ProverInstance::new(&config, prover_statement, None).expect("no preprocessed columns");
    let (output, statement) =
        prover_instance.prove(test_challenger()).expect("proving should succeed");
    let stark_statement =
        VerifierInstance::new(&config, &statement, None).expect("no preprocessed columns");

    // Poke the `pub(crate)` `log_trace_heights` directly to feed the verifier
    // malformed shapes that bypass `ProverStatement` construction — the cases
    // that would otherwise panic or overflow rather than return a clean error.

    // log_h = 200 trips the `usize` overflow guard in `TraceOrder::from_log_heights`,
    // before `1usize << log_h` could overflow.
    let mut bad_proof = output.proof.clone();
    bad_proof.log_trace_heights = vec![200];
    let err = stark_statement
        .verify(&bad_proof, test_challenger())
        .expect_err("oversized log trace height should fail verification");
    assert!(matches!(
        err,
        VerifierError::Shape(ShapeError::LogTraceHeightTooLarge { log_h: 200, .. })
    ));

    // log_h = 30 with log_blowup = 3 and Felt::TWO_ADICITY = 32 overflows the LDE
    // domain (33 > 32), rejected by `try_canonical` before any generator lookup.
    let mut bad_proof = output.proof;
    bad_proof.log_trace_heights = vec![30];
    let err = stark_statement
        .verify(&bad_proof, test_challenger())
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
#[should_panic(expected = "ext constraint not satisfied")]
fn constraint_checker_rejects_invalid_aux_trace() {
    let air = TinyAir {
        aux_offset: Felt::ONE,
        ..TinyAir::new([])
    };
    let prover_statement = tiny_prover_statement(
        vec![air],
        vec![trace_of_height(4)],
        vec![(0, vec![Felt::from_u64(START)])],
    )
    .unwrap();
    crate::debug::check_constraints(&prover_statement, test_challenger());
}

#[test]
fn air_order_reflects_caller_order() {
    let config = test_config();
    let airs = vec![
        TinyAir { num_public_values: 2, ..TinyAir::new([]) },
        TinyAir::new([]),
        TinyAir::new([]),
    ];
    let inputs = vec![
        (2, vec![Felt::from_u64(11)]),
        (0, vec![Felt::from_u64(3), Felt::from_u64(4)]),
        (1, vec![Felt::ZERO]),
    ];
    let traces = [(7, 16), (0, 8), (11, 4)]
        .map(|(start, height)| generate_pow4_trace(Felt::from_u64(start), height));
    let prover_statement = tiny_prover_statement(airs.clone(), traces.to_vec(), inputs).unwrap();
    crate::debug::check_constraints(&prover_statement, test_challenger());
    let (output, statement) = ProverInstance::new(&config, prover_statement, None)
        .unwrap()
        .prove(test_challenger())
        .unwrap();
    let digest = VerifierInstance::new(&config, &statement, None)
        .unwrap()
        .verify(&output.proof, test_challenger())
        .unwrap();
    assert_eq!(digest, output.digest);
    let explicit_inputs = statement.air_inputs().iter().cloned().enumerate().collect();
    let explicit_statement =
        Statement::new(TestMultiAir::new(airs.clone()), explicit_inputs, Vec::new()).unwrap();
    assert_eq!(
        VerifierInstance::new(&config, &explicit_statement, None)
            .unwrap()
            .verify(&output.proof, test_challenger())
            .unwrap(),
        digest
    );
    assert_eq!(output.proof.log_trace_heights.as_slice(), &[4, 3, 2]);
    let trace_order = TraceOrder::from_log_heights::<Felt, QuadFelt, _>(
        statement.airs(),
        output.proof.log_trace_heights.clone(),
    )
    .unwrap();
    assert_eq!(trace_order.instance_indices(), &[2, 1, 0]);
    for bad_inputs in [
        vec![
            (0, vec![Felt::from_u64(3), Felt::from_u64(5)]),
            (2, vec![Felt::from_u64(11)]),
            (1, vec![Felt::ZERO]),
        ],
        vec![
            (0, vec![Felt::from_u64(11), Felt::from_u64(3)]),
            (2, vec![Felt::from_u64(4)]),
            (1, vec![Felt::ZERO]),
        ],
    ] {
        let statement =
            Statement::new(TestMultiAir::new(airs.clone()), bad_inputs, Vec::new()).unwrap();
        assert!(
            VerifierInstance::new(&config, &statement, None)
                .unwrap()
                .verify(&output.proof, test_challenger())
                .is_err()
        );
    }
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

#[test]
fn block_hashing_preserves_proof_transcript() {
    let mut config = test_config();
    let prover_statement = || {
        tiny_prover_statement(
            vec![TinyAir::new([4]), TinyAir::new([2])],
            vec![trace_of_height(64), trace_of_height(8)],
            vec![(0, vec![Felt::from_u64(START)]), (1, vec![Felt::from_u64(START)])],
        )
        .unwrap()
    };
    let prove = |config: &_| {
        ProverInstance::new(config, prover_statement(), None)
            .unwrap()
            .prove(test_challenger())
            .unwrap()
    };
    let (eager, _) = prove(&config);
    config.hash_lde_blocks = true;
    let (blocks, statement) = prove(&config);
    assert_eq!(blocks.proof.transcript.as_slices(), eager.proof.transcript.as_slices());
    assert_eq!(blocks.digest, eager.digest);
    config.hash_lde_blocks = false;
    let digest = VerifierInstance::new(&config, &statement, None)
        .unwrap()
        .verify(&blocks.proof, test_challenger())
        .unwrap();
    assert_eq!(digest, blocks.digest);
}
