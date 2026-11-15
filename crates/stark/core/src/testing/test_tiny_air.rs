//! Integration tests for the lifted STARK prove/verify cycle using a minimal
//! single-column AIR with periodic columns and auxiliary traces.

use alloc::{borrow::Cow, vec, vec::Vec};
use core::convert::Infallible;

use p3_field::{Algebra, Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::air::native::LiftedAirBuilder as _;
use crate::{
    ProverInstance, VerifierError, VerifierInstance,
    air::{
        BaseAir, InstanceError, LiftedAir, LiftedAirBuilder, ProverStatement, Statement, native,
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
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let result = native::ProverAir::build_aux_trace(
            self,
            native::AuxTraceInputs {
                main,
                preprocessed: None,
                public_values: air_inputs,
                statement: aux_inputs,
                challenges,
            },
        );
        let aux = match result {
            Ok(aux) => aux,
            Err(never) => match never {},
        };
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for TinyAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: self.num_public_values,
            num_challenges: 1,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&self.periodic_cols),
        }
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;
        let public_sum =
            inputs.public_values.iter().fold(B::Expr::ZERO, |sum, value| sum + value.dup());

        // Preserve both expression construction and global assertion order.
        sink.when(frame.first_row()).assert_eq(local[0].dup(), public_sum.dup());
        sink.when(frame.transition())
            .assert_eq(next[0].dup(), local[0].dup().exp_power_of_2(2));
        for periodic in frame.periodic {
            sink.when(frame.first_row()).assert_one(periodic.dup());
            sink.when(frame.last_row()).assert_one(periodic.dup());
        }

        let aux = frame.aux.current[0].dup();
        sink.when(frame.first_row())
            .assert_eq_ext(aux.dup(), inputs.challenges[0].dup() + B::ExtExpr::from(public_sum));
        sink.when(frame.transition())
            .assert_eq_ext(frame.aux.next[0].dup(), aux.exp_power_of_2(2));
    }
}

impl native::ProverAir<QuadFelt> for TinyAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        let (mut trace, values) = tiny_aux(
            inputs.main,
            inputs.challenges[0]
                + QuadFelt::from(inputs.public_values.iter().copied().sum::<Felt>()),
        );
        trace.values[0] += QuadFelt::from(self.aux_offset);
        Ok(native::AuxTrace { columns: trace, exports: values })
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

// Direct execution uses the same private source as the legacy proof fixtures above. These pilots
// instantiate native scalar, packed and non-Copy symbolic inputs without another equation body.
mod native_kernel_pilot {
    use alloc::{format, vec, vec::Vec};

    use p3_field::{Algebra, BasedVectorSpace, PackedValue, PrimeCharacteristicRing};
    use p3_matrix::{Matrix, dense::RowMajorMatrix};

    use super::{Felt, QuadFelt, START, TinyAir, trace_of_height};
    use crate::{
        air::native::{self, AirKernel, LiftedAirBuilder},
        testing::configs::{PackedFelt, PackedQuadFelt},
    };

    enum Emission<B, E> {
        Base(B),
        Extension(E),
    }

    struct Sink<B, E> {
        emissions: Vec<Emission<B, E>>,
    }

    impl<B, E> Default for Sink<B, E> {
        fn default() -> Self {
            Self { emissions: Vec::new() }
        }
    }

    impl<B: Algebra<Felt>, E: Algebra<B>> LiftedAirBuilder for Sink<B, E> {
        type F = Felt;
        type Expr = B;
        type ExtExpr = E;

        fn emit_base(&mut self, value: B, _meta: native::ConstraintMeta<'_>) {
            self.emissions.push(Emission::Base(value));
        }

        fn emit_ext(&mut self, value: E, _meta: native::ConstraintMeta<'_>) {
            self.emissions.push(Emission::Extension(value));
        }
    }

    impl<B, E> Sink<B, E> {
        fn classes(&self) -> Vec<bool> {
            self.emissions
                .iter()
                .map(|value| matches!(value, Emission::Extension(_)))
                .collect()
        }
    }

    struct ConcretePilot {
        kernel: native::DirectKernel<TinyAir>,
        main: RowMajorMatrix<Felt>,
        public: [Felt; 2],
        challenges: [QuadFelt; 1],
        auxiliary: native::AuxTrace<QuadFelt>,
    }

    impl ConcretePilot {
        fn new(height: usize) -> Self {
            let source = TinyAir {
                num_public_values: 2,
                ..TinyAir::new([2, 4])
            };
            let kernel = native::DirectKernel::new(source).unwrap();
            let main = trace_of_height(height);
            let public = [Felt::ONE, Felt::from_u64(START - 1)];
            let challenges =
                [QuadFelt::from_basis_coefficients_slice(&[Felt::from_u64(3), Felt::from_u64(5)])
                    .unwrap()];
            let auxiliary = native::ProverAir::build_aux_trace(
                &kernel,
                native::AuxTraceInputs {
                    main: &main,
                    preprocessed: None,
                    public_values: &public,
                    statement: &[],
                    challenges: &challenges,
                },
            )
            .unwrap();
            assert_eq!(
                auxiliary.columns.values[0],
                challenges[0] + QuadFelt::from(Felt::from_u64(START))
            );
            assert_eq!(auxiliary.exports, vec![auxiliary.columns.values[height - 1]]);
            let layout = kernel.descriptor().analysis().layout();
            assert_eq!(layout.base_indices(), &[0, 1, 2, 3, 4, 5]);
            assert_eq!(layout.ext_indices(), &[6, 7]);
            Self {
                kernel,
                main,
                public,
                challenges,
                auxiliary,
            }
        }
    }

    fn indicator(value: bool) -> Felt {
        if value { Felt::ONE } else { Felt::ZERO }
    }

    #[test]
    fn direct_tiny_scalar_session_accepts_known_pow4_rows_and_cyclic_next() {
        let pilot = ConcretePilot::new(8);
        let session = pilot
            .kernel
            .bind(native::UniformInputs {
                public_values: &pilot.public,
                challenges: &pilot.challenges,
                exports: &pilot.auxiliary.exports,
            })
            .unwrap();
        for row in 0..pilot.main.height() {
            let next = (row + 1) % pilot.main.height();
            let periodic: Vec<_> = session
                .descriptor()
                .spec()
                .periodic_columns
                .iter()
                .map(|column| column[row % column.len()])
                .collect();
            let frame = native::AirFrame {
                main: native::Rows {
                    current: &pilot.main.values[row..row + 1],
                    next: &pilot.main.values[next..next + 1],
                },
                preprocessed: native::Rows { current: &[], next: &[] },
                aux: native::Rows {
                    current: &pilot.auxiliary.columns.values[row..row + 1],
                    next: &pilot.auxiliary.columns.values[next..next + 1],
                },
                periodic: &periodic,
                selectors: native::Selectors {
                    first: indicator(row == 0),
                    last: indicator(row + 1 == pilot.main.height()),
                    transition: indicator(row + 1 != pilot.main.height()),
                },
            };
            let mut sink = Sink::<Felt, QuadFelt>::default();
            session.eval(&frame, &mut sink);
            assert_eq!(sink.classes(), vec![false, false, false, false, false, false, true, true]);
            for value in sink.emissions {
                match value {
                    Emission::Base(value) => assert_eq!(value, Felt::ZERO),
                    Emission::Extension(value) => assert_eq!(value, QuadFelt::ZERO),
                }
            }
        }
    }

    #[test]
    fn direct_tiny_packed_session_uses_real_goldilocks_packing_and_shared_uniforms() {
        let height = PackedFelt::WIDTH.max(8).next_power_of_two();
        let pilot = ConcretePilot::new(height);
        let public = pilot.public.map(PackedFelt::from);
        let challenges = pilot.challenges.map(PackedQuadFelt::from);
        let exports: Vec<_> =
            pilot.auxiliary.exports.iter().copied().map(PackedQuadFelt::from).collect();
        let session = pilot
            .kernel
            .bind(native::UniformInputs {
                public_values: &public,
                challenges: &challenges,
                exports: &exports,
            })
            .unwrap();
        assert!(height.is_multiple_of(PackedFelt::WIDTH));
        for start in (0..height).step_by(PackedFelt::WIDTH) {
            let main = [PackedFelt::from_fn(|lane| pilot.main.values[start + lane])];
            let next = [PackedFelt::from_fn(|lane| pilot.main.values[(start + lane + 1) % height])];
            let pack_aux = |offset: usize| {
                <PackedQuadFelt as BasedVectorSpace<PackedFelt>>::from_basis_coefficients_fn(
                    |coefficient| {
                        PackedFelt::from_fn(|lane| {
                            pilot.auxiliary.columns.values[(start + lane + offset) % height]
                                .as_basis_coefficients_slice()[coefficient]
                        })
                    },
                )
            };
            let auxiliary = [pack_aux(0)];
            let next_auxiliary = [pack_aux(1)];
            let periodic: Vec<_> = session
                .descriptor()
                .spec()
                .periodic_columns
                .iter()
                .map(|column| PackedFelt::from_fn(|lane| column[(start + lane) % column.len()]))
                .collect();
            let frame = native::AirFrame {
                main: native::Rows { current: &main, next: &next },
                preprocessed: native::Rows { current: &[], next: &[] },
                aux: native::Rows {
                    current: &auxiliary,
                    next: &next_auxiliary,
                },
                periodic: &periodic,
                selectors: native::Selectors {
                    first: PackedFelt::from_fn(|lane| indicator(start + lane == 0)),
                    last: PackedFelt::from_fn(|lane| indicator(start + lane + 1 == height)),
                    transition: PackedFelt::from_fn(|lane| indicator(start + lane + 1 != height)),
                },
            };
            let mut sink = Sink::<PackedFelt, PackedQuadFelt>::default();
            session.eval(&frame, &mut sink);
            assert_eq!(sink.classes(), vec![false, false, false, false, false, false, true, true]);
            for value in sink.emissions {
                match value {
                    Emission::Base(value) => {
                        assert!(value.as_slice().iter().all(|value| *value == Felt::ZERO));
                    },
                    Emission::Extension(value) => {
                        let coefficients: &[PackedFelt] = value.as_basis_coefficients_slice();
                        for coefficient in coefficients {
                            assert!(
                                coefficient.as_slice().iter().all(|value| *value == Felt::ZERO)
                            );
                        }
                    },
                }
            }
        }
    }

    #[test]
    fn direct_tiny_symbolic_session_preserves_non_copy_inputs_and_capture_order() {
        use native::symbolic::{
            AuxInput, BaseInput, BaseLeaf, RowOffset, SymbolicExpression, SymbolicExpressionExt,
        };
        type B = SymbolicExpression<Felt>;
        type E = SymbolicExpressionExt<Felt, Felt>;

        let source = TinyAir {
            num_public_values: 2,
            ..TinyAir::new([2, 4])
        };
        let capture = native::capture(&source).unwrap();
        let kernel = native::DirectKernel::new(source).unwrap();
        assert_eq!(kernel.descriptor().fingerprint(), capture.descriptor.fingerprint());
        let main = [B::input(BaseInput::Main { offset: RowOffset::Current, index: 0 })];
        let next = [B::input(BaseInput::Main { offset: RowOffset::Next, index: 0 })];
        let auxiliary = [E::input(AuxInput::Trace { offset: RowOffset::Current, index: 0 })];
        let next_auxiliary = [E::input(AuxInput::Trace { offset: RowOffset::Next, index: 0 })];
        let periodic = [B::input(BaseInput::Periodic(0)), B::input(BaseInput::Periodic(1))];
        let public = [B::input(BaseInput::Public(0)), B::input(BaseInput::Public(1))];
        let challenges = [E::input(AuxInput::Challenge(0))];
        let exports = [E::input(AuxInput::Export(0))];
        let session = kernel
            .bind(native::UniformInputs {
                public_values: &public,
                challenges: &challenges,
                exports: &exports,
            })
            .unwrap();
        let frame = native::AirFrame {
            main: native::Rows { current: &main, next: &next },
            preprocessed: native::Rows { current: &[], next: &[] },
            aux: native::Rows {
                current: &auxiliary,
                next: &next_auxiliary,
            },
            periodic: &periodic,
            selectors: native::Selectors {
                first: B::Leaf(BaseLeaf::IsFirstRow),
                last: B::Leaf(BaseLeaf::IsLastRow),
                transition: B::Leaf(BaseLeaf::IsTransition),
            },
        };
        let mut sink = Sink::<B, E>::default();
        session.eval(&frame, &mut sink);
        assert_eq!(sink.classes(), vec![false, false, false, false, false, false, true, true]);
        assert_eq!(sink.emissions.len(), capture.assertions.len());
        for (actual, expected) in sink.emissions.into_iter().zip(capture.assertions) {
            match (actual, expected) {
                (Emission::Base(actual), native::Assertion::Base(expected)) => {
                    assert_eq!(actual.degree_multiple(), expected.degree_multiple());
                    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                },
                (Emission::Extension(actual), native::Assertion::Extension(expected)) => {
                    assert_eq!(actual.degree_multiple(), expected.degree_multiple());
                    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                },
                _ => panic!("direct session changed assertion class/global order"),
            }
        }
    }
}
