//! End-to-end tests for preprocessed traces on the stark-instance API.
//!
//! These exercise the real preprocessed path: the commitment is observed
//! first, the tree is opened via the PCS, and the per-AIR window is fed to the
//! constraint folders. Preprocessed content is served through
//! native source factories; the prover bundles it via
//! [`Preprocessed::build`] + [`ProverInstance::new`], and the verifier receives
//! a trusted setup identity via [`VerifierInstance::new`] and native table heights from descriptors.

use alloc::{borrow::Cow, sync::Arc, vec, vec::Vec};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
};

use p3_field::{Algebra, Dup, Field, PackedValue, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::air::native::LiftedAirBuilder as _;
use crate::{
    Preprocessed, PreprocessedValidationError, ProverInstance, ShapeError, VerifierError,
    VerifierInstance,
    air::{MultiAir, ProverStatement, Statement, log2_strict_u8, native},
    check_constraints,
    pcs::params::PcsParams,
    proof::{StarkOutput, StarkProof},
    testing::configs::goldilocks_poseidon2::{
        Felt, Lmcs, PackedFelt, PackedQuadFelt, QuadFelt, TestConfig, test_challenger, test_config,
    },
};

// ---------------------------------------------------------------------------
// AIR fixtures
// ---------------------------------------------------------------------------

/// AIR with a preprocessed column carrying the row index `0, 1, 2, …`, served
/// by value through its native fixed-matrix factory.
///
/// Constraints (gated so symbolic degree ≥ 2): first row `main[0] ==
/// preprocessed[0]`; transition `Δmain == Δpreprocessed` (uses the
/// preprocessed window non-trivially); first row `aux[0] == challenge`.
#[derive(Clone, Debug)]
struct RowCounterAir {
    preprocessed: RowMajorMatrix<Felt>,
    declared_width: usize,
    declared_log_height: Option<u8>,
}

impl RowCounterAir {
    fn new(preprocessed: RowMajorMatrix<Felt>) -> Self {
        Self {
            declared_width: preprocessed.width(),
            declared_log_height: Some(log2_strict_u8(preprocessed.height())),
            preprocessed,
        }
    }
}

impl native::LiftedAir for RowCounterAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: Some(native::PreprocessedSpec {
                width: self.declared_width,
                log_height: self
                    .declared_log_height
                    .expect("row-counter fixture has a fixed height"),
            }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local_main = frame.main.current[0].dup();
        let next_main = frame.main.next[0].dup();
        let local_preproc = frame.preprocessed.current[0].dup();
        let next_preproc = frame.preprocessed.next[0].dup();

        builder.when(frame.first_row()).assert_eq(local_main.dup(), local_preproc.dup());
        builder
            .when(frame.transition())
            .assert_eq(next_main - local_main, next_preproc - local_preproc);
        builder
            .when(frame.first_row())
            .assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl native::ProverAir<QuadFelt> for RowCounterAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        let (columns, exports) = build_aux(inputs.main.height(), inputs.challenges);
        Ok(native::AuxTrace { columns, exports })
    }
}

/// AIR with no preprocessed columns. Transition `next == local²`.
#[derive(Clone, Copy, Debug)]
struct ConstantAir;

impl native::LiftedAir for ConstantAir {
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
        let local = frame.main.current[0].dup();
        builder
            .when(frame.transition())
            .assert_eq(frame.main.next[0].dup(), local.dup() * local);
        builder
            .when(frame.first_row())
            .assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl native::ProverAir<QuadFelt> for ConstantAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        let (columns, exports) = build_aux(inputs.main.height(), inputs.challenges);
        Ok(native::AuxTrace { columns, exports })
    }
}

/// Heterogeneous AIR for mixed-instance tests.
#[derive(Clone, Debug)]
enum MixedAir {
    Constant(ConstantAir),
    RowCounter(RowCounterAir),
}

impl native::LiftedAir for MixedAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        match self {
            Self::Constant(air) => native::LiftedAir::spec(air),
            Self::RowCounter(air) => native::LiftedAir::spec(air),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::Constant(air) => native::LiftedAir::build_preprocessed_trace(air),
            Self::RowCounter(air) => native::LiftedAir::build_preprocessed_trace(air),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        match self {
            Self::Constant(air) => native::LiftedAir::eval(air, frame, inputs, builder),
            Self::RowCounter(air) => native::LiftedAir::eval(air, frame, inputs, builder),
        }
    }
}

impl native::ProverAir<QuadFelt> for MixedAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        match self {
            Self::Constant(air) => native::ProverAir::build_aux_trace(air, inputs),
            Self::RowCounter(air) => native::ProverAir::build_aux_trace(air, inputs),
        }
    }
}

// ---------------------------------------------------------------------------
// MultiAir + helpers
// ---------------------------------------------------------------------------

/// Minimal [`MultiAir`] over a homogeneous AIR list.
#[derive(Clone, Debug)]
struct PreprocMultiAir<A> {
    airs: Vec<A>,
}

impl<A: native::AirKernel<F = Felt>> MultiAir<Felt, QuadFelt> for PreprocMultiAir<A> {
    type Air = A;

    fn airs(&self) -> &[A] {
        &self.airs
    }
}

fn row_index_trace(height: usize) -> RowMajorMatrix<Felt> {
    RowMajorMatrix::new((0..height).map(|r| Felt::from_u64(r as u64)).collect(), 1)
}

fn shifted_row_index_trace(height: usize) -> RowMajorMatrix<Felt> {
    RowMajorMatrix::new((0..height).map(|r| Felt::from_u64((r + 1) as u64)).collect(), 1)
}

/// Trace satisfying [`ConstantAir`]'s `next == local²` transition.
fn squaring_trace(height: usize) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(height);
    let mut current = Felt::from_u64(2);
    for _ in 0..height {
        values.push(current);
        current = current * current;
    }
    RowMajorMatrix::new(values, 1)
}

/// Constant aux trace `[challenge; height]`, matching every fixture AIR.
fn build_aux(height: usize, challenges: &[QuadFelt]) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    (RowMajorMatrix::new(vec![challenges[0]; height], 1), Vec::new())
}

/// Build a prover statement with fixed public inputs for the fixture AIRs.
fn prover_statement<A: native::AirKernel<F = Felt>>(
    airs: Vec<A>,
    traces: Vec<RowMajorMatrix<Felt>>,
) -> ProverStatement<Felt, QuadFelt, PreprocMultiAir<A>> {
    let inputs = airs
        .iter()
        .enumerate()
        .filter(|(_, air)| air.descriptor().spec().num_public_values != 0)
        .map(|(i, air)| {
            (i, vec![Felt::from_usize(i + 3); air.descriptor().spec().num_public_values])
        })
        .collect();
    let statement = Statement::new(PreprocMultiAir { airs }, inputs, vec![]).expect("statement");
    ProverStatement::new(statement, traces).expect("prover statement")
}

fn row_counter_statement(
    traces: Vec<RowMajorMatrix<Felt>>,
) -> ProverStatement<Felt, QuadFelt, PreprocMultiAir<native::DirectKernel<RowCounterAir>>> {
    let airs = traces
        .iter()
        .cloned()
        .map(|trace| native::DirectKernel::new(RowCounterAir::new(trace)).unwrap())
        .collect();
    prover_statement(airs, traces)
}

type TestOutput = StarkOutput<Felt, QuadFelt, TestConfig>;
type TestPreprocessed = Preprocessed<Felt, Lmcs>;

fn prove_with_preprocessed<MA>(
    config: &TestConfig,
    ps: ProverStatement<Felt, QuadFelt, MA>,
) -> (TestOutput, TestPreprocessed, Statement<Felt, QuadFelt, MA>)
where
    MA: MultiAir<Felt, QuadFelt>,
    MA::Air: native::ProverAir<QuadFelt> + native::LiftedAir<F = Felt>,
    <MA::Air as native::AirKernel>::Prepared<PackedFelt, PackedQuadFelt>: Sync,
{
    let preprocessed = Preprocessed::build(ps.statement(), config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let prover_instance =
        ProverInstance::new(config, ps, Some(&preprocessed)).expect("valid preprocessed setup");
    let (output, statement) = prover_instance.prove(test_challenger()).expect("prove succeeds");
    (output, preprocessed, statement)
}

fn verify_and_reparse<MA>(
    config: &TestConfig,
    statement: &Statement<Felt, QuadFelt, MA>,
    output: &TestOutput,
    preprocessed: &TestPreprocessed,
) where
    MA: MultiAir<Felt, QuadFelt>,
{
    let verifier_instance =
        VerifierInstance::new(config, statement, Some(preprocessed.identity().clone()))
            .expect("valid preprocessed setup");
    let digest = verifier_instance
        .verify(&output.proof, test_challenger())
        .expect("verify succeeds");
    assert_eq!(output.digest, digest);

    let (_, reparse_digest) =
        StarkProof::from_data(&verifier_instance, &output.proof, test_challenger())
            .expect("preprocessed transcript re-parse should succeed");
    assert_eq!(output.digest, reparse_digest);
}

fn prove_verify_reparse<MA>(ps: ProverStatement<Felt, QuadFelt, MA>)
where
    MA: MultiAir<Felt, QuadFelt>,
    MA::Air: native::ProverAir<QuadFelt> + native::LiftedAir<F = Felt>,
    <MA::Air as native::AirKernel>::Prepared<PackedFelt, PackedQuadFelt>: Sync,
{
    let config = test_config();
    let (output, preprocessed, statement) = prove_with_preprocessed(&config, ps);
    verify_and_reparse(&config, &statement, &output, &preprocessed);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn single_air_with_preprocessed() {
    let height = 8;
    let ps = row_counter_statement(vec![row_index_trace(height)]);
    let config = test_config();
    let (output, preprocessed, statement) = prove_with_preprocessed(&config, ps);
    verify_and_reparse(&config, &statement, &output, &preprocessed);

    let missing_commitment = VerifierInstance::new(&config, &statement, None);
    assert!(
        matches!(
            missing_commitment,
            Err(PreprocessedValidationError::PresenceMismatch { expected: true, actual: false })
        ),
        "preprocessed statements require the setup commitment",
    );
}

#[test]
fn mixed_airs_preprocessed_at_index_1() {
    let height = 8;
    let ps = prover_statement(
        vec![
            native::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(
                height,
            ))))
            .unwrap(),
        ],
        vec![squaring_trace(height), row_index_trace(height)],
    );

    prove_verify_reparse(ps);
}

#[test]
fn rejects_width_mismatch() {
    let height = 8;
    let mut air = RowCounterAir::new(row_index_trace(height));
    air.declared_width = 2;
    let ps = prover_statement(
        vec![native::DirectKernel::new(air).unwrap()],
        vec![row_index_trace(height)],
    );
    let config = test_config();

    // Factory output is rejected before LDE/tree construction or instance creation.
    let result = Preprocessed::build(ps.statement(), &config);
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::WidthMismatch { expected: 2, actual: 1, .. })
        ),
        "expected WidthMismatch {{ expected: 2, actual: 1 }}",
    );
}

#[test]
fn rejects_height_mismatch() {
    // Preprocessed matrix height (4) differs from the main trace height (8).
    let ps = prover_statement(
        vec![native::DirectKernel::new(RowCounterAir::new(row_index_trace(4))).unwrap()],
        vec![row_index_trace(8)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let result = ProverInstance::new(&config, ps, Some(&preprocessed));
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::Shape(ShapeError::PreprocessedHeightMismatch {
                air: 0,
                log_trace_height: 3,
                log_preprocessed_height: 2,
            }))
        ),
        "main trace height must match the AIR's fixed preprocessing height",
    );
}

#[test]
fn rejects_setup_with_different_preprocessed_height() {
    let config = test_config();
    let setup_statement = row_counter_statement(vec![row_index_trace(4)]);
    let setup = Preprocessed::build(setup_statement.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let ps = row_counter_statement(vec![row_index_trace(8)]);
    assert!(matches!(
        ProverInstance::new(&config, ps, Some(&setup)),
        Err(PreprocessedValidationError::FingerprintMismatch { air: 0, .. })
    ));
}

#[test]
fn rejects_log_blowup_mismatch() {
    let height = 8;
    let ps = row_counter_statement(vec![row_index_trace(height)]);
    let build_config = test_config();
    let preprocessed = Preprocessed::build(ps.statement(), &build_config)
        .expect("valid fixed setup")
        .expect("has preprocessed");

    let mut proving_config = test_config();
    proving_config.pcs = PcsParams::new(2, 2, 2, 0, 0, 2, 0).expect("valid PCS params");
    let result = ProverInstance::new(&proving_config, ps, Some(&preprocessed));
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::BlowupMismatch { expected: 2, actual: 3 })
        ),
        "expected BlowupMismatch before inspecting cached LDE dimensions",
    );
}

#[test]
fn rejects_reassigned_preprocessed_tables() {
    let config = test_config();
    let intended = row_counter_statement(vec![row_index_trace(4), row_index_trace(8)]);
    let intended_setup = Preprocessed::build(intended.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let reassigned = row_counter_statement(vec![row_index_trace(8), row_index_trace(4)]);
    let (output, reassigned_setup, statement) = prove_with_preprocessed(&config, reassigned);

    // Sorting by height gives the same committed tree, although the AIR owners differ.
    assert_eq!(intended_setup.commitment(), reassigned_setup.commitment());
    verify_and_reparse(&config, &statement, &output, &reassigned_setup);
    // Identical sorted roots do not authorize reassigning fixed tables to different relations.
    assert!(matches!(
        VerifierInstance::new(&config, &statement, Some(intended_setup.identity().clone())),
        Err(PreprocessedValidationError::FingerprintMismatch { air: 0, .. }),
    ));

    let verifier = VerifierInstance::new(
        &config,
        intended.statement(),
        Some(intended_setup.identity().clone()),
    )
    .expect("valid intended setup");
    for result in [
        verifier.verify(&output.proof, test_challenger()).map(|_| ()),
        StarkProof::from_data(&verifier, &output.proof, test_challenger()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(VerifierError::Plan(crate::PlanError::Shape(
                ShapeError::PreprocessedHeightMismatch {
                    air: 0,
                    log_trace_height: 3,
                    log_preprocessed_height: 2,
                }
            )))
        ));
    }
}

#[test]
fn rejects_reassigned_equal_height_preprocessed_tables() {
    let config = test_config();
    let tables = [row_index_trace(4), shifted_row_index_trace(4)];
    let intended = row_counter_statement(tables.to_vec());
    let intended_setup = Preprocessed::build(intended.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let reassigned = row_counter_statement(tables.into_iter().rev().collect());
    let (output, reassigned_setup, statement) = prove_with_preprocessed(&config, reassigned);

    // Equal heights preserve AIR-index order, so exchanging table contents changes the root.
    assert_ne!(intended_setup.commitment(), reassigned_setup.commitment());
    verify_and_reparse(&config, &statement, &output, &reassigned_setup);

    let verifier = VerifierInstance::new(
        &config,
        intended.statement(),
        Some(intended_setup.identity().clone()),
    )
    .expect("valid intended setup");
    assert!(matches!(
        verifier.verify(&output.proof, test_challenger()),
        Err(VerifierError::Pcs(_))
    ));
}

#[test]
fn setup_rejects_incorrect_declared_height() {
    let mut air = RowCounterAir::new(row_index_trace(4));
    air.declared_log_height = Some(3);
    let statement = Statement::new(
        PreprocMultiAir {
            airs: vec![native::DirectKernel::new(air).unwrap()],
        },
        vec![],
        vec![],
    )
    .expect("statement");
    assert!(matches!(
        Preprocessed::build(&statement, &test_config()),
        Err(PreprocessedValidationError::HeightMismatch { air: 0, main: 8, preprocessed: 4 }),
    ));
}

#[test]
fn reuses_setup_with_equal_table_heights_and_variable_main_height() {
    let config = test_config();
    let airs = [
        MixedAir::Constant(ConstantAir),
        MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))),
        MixedAir::RowCounter(RowCounterAir::new(shifted_row_index_trace(4))),
    ];
    let statement = Statement::new(
        PreprocMultiAir {
            airs: airs
                .iter()
                .cloned()
                .map(|source| native::DirectKernel::new(source).unwrap())
                .collect(),
        },
        vec![],
        vec![],
    )
    .expect("statement");
    let setup = Preprocessed::build(&statement, &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    for height in [2, 4, 8] {
        let ps = prover_statement(
            airs.iter()
                .cloned()
                .map(|source| native::DirectKernel::new(source).unwrap())
                .collect(),
            vec![squaring_trace(height), row_index_trace(4), shifted_row_index_trace(4)],
        );
        let (output, statement) = ProverInstance::new(&config, ps, Some(&setup))
            .expect("valid setup")
            .prove(test_challenger())
            .expect("prove succeeds");
        verify_and_reparse(&config, &statement, &output, &setup);
    }
}

#[test]
fn rejects_wrong_trusted_preprocessed_commitment() {
    let height = 8;
    let ps = row_counter_statement(vec![row_index_trace(height)]);
    let config = test_config();
    let (output, _preprocessed, statement) = prove_with_preprocessed(&config, ps);

    let wrong_ps = row_counter_statement(vec![shifted_row_index_trace(height)]);
    let wrong_preprocessed = Preprocessed::build(wrong_ps.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let verifier_instance =
        VerifierInstance::new(&config, &statement, Some(wrong_preprocessed.identity().clone()))
            .expect("presence is valid");

    assert!(
        verifier_instance.verify(&output.proof, test_challenger()).is_err(),
        "verification must reject a proof checked against the wrong trusted setup commitment",
    );
}

#[test]
fn preprocessed_with_short_nonlinear_air() {
    // The two-row squaring trace has a nonzero quotient. On wide SIMD targets this
    // checks that a partial pack writes its output, including without preprocessed columns.
    let ps = prover_statement(
        vec![
            native::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(8))))
                .unwrap(),
        ],
        vec![squaring_trace(2), row_index_trace(8)],
    );

    prove_verify_reparse(ps);
}

#[test]
fn preprocessed_shorter_than_max_trace() {
    // The tallest AIR (ConstantAir, height 8) has no preprocessed columns, so the
    // tallest preprocessed trace (RowCounter, height 4) sits below the max trace
    // height. The PCS virtually lifts the shorter preprocessed tree.
    let ps = prover_statement(
        vec![
            native::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))))
                .unwrap(),
        ],
        vec![squaring_trace(8), row_index_trace(4)],
    );

    prove_verify_reparse(ps);
}

#[test]
fn preprocessed_much_shorter_than_max_trace() {
    // Larger lift ratio: the preprocessed tree (height 2) is folded by 4 at query
    // time against a max trace height of 8.
    let ps = prover_statement(
        vec![
            native::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(2))))
                .unwrap(),
        ],
        vec![squaring_trace(8), row_index_trace(2)],
    );

    prove_verify_reparse(ps);
}

#[test]
fn preprocessed_multiple_heights_below_max() {
    // Two preprocessed AIRs at heights 2 and 4 (so the preprocessed tree lifts
    // internally to 4), under a taller non-preprocessed AIR at height 8. Exercises
    // both within-tree lifting and the global query fold.
    let ps = prover_statement(
        vec![
            native::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))))
                .unwrap(),
            native::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(2))))
                .unwrap(),
        ],
        vec![squaring_trace(8), row_index_trace(4), row_index_trace(2)],
    );

    prove_verify_reparse(ps);
}

/// Record auxiliary-builder and evaluator calls during proving and constraint checks.
#[derive(Clone, Debug)]
struct CountedAir {
    inner: MixedAir,
    materializations: Arc<AtomicUsize>,
    aux_calls: Arc<AtomicUsize>,
    borrowed_address: Arc<AtomicUsize>,
    preparations: Arc<AtomicUsize>,
    prepared_evaluations: Arc<AtomicUsize>,
    max_batch_evaluations: Arc<AtomicUsize>,
}

impl CountedAir {
    fn new(inner: MixedAir) -> Self {
        Self {
            inner,
            materializations: Arc::new(AtomicUsize::new(0)),
            aux_calls: Arc::new(AtomicUsize::new(0)),
            borrowed_address: Arc::new(AtomicUsize::new(0)),
            preparations: Arc::new(AtomicUsize::new(0)),
            prepared_evaluations: Arc::new(AtomicUsize::new(0)),
            max_batch_evaluations: Arc::new(AtomicUsize::new(0)),
        }
    }
}

fn counted_value<B: Algebra<Felt>, E: Algebra<B>>(inputs: native::UniformInputs<'_, B, E>) -> E {
    inputs.challenges[0].square() + inputs.exports[0].dup() * inputs.public_values[0].dup()
}

impl CountedAir {
    fn record_evaluation(&self, evaluations: &AtomicUsize) {
        self.prepared_evaluations.fetch_add(1, Ordering::Relaxed);
        let count = evaluations.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_batch_evaluations.fetch_max(count, Ordering::Relaxed);
    }

    fn eval_cached<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        cached: &AB::ExtExpr,
        builder: &mut AB,
    ) {
        // Compare with independently read uniform inputs before the inner assertion stream.
        builder.assert_eq_ext(cached.dup(), counted_value(inputs));
        native::LiftedAir::eval(&self.inner, frame, inputs, builder);
    }
}

impl native::LiftedAir for CountedAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        let mut spec = native::LiftedAir::spec(&self.inner);
        spec.num_public_values = 1;
        spec.num_exports = 1;
        spec
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.materializations.fetch_add(1, Ordering::Relaxed);
        native::LiftedAir::build_preprocessed_trace(&self.inner)
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // Source capture describes the relation without exercising kernel lifecycle counters.
        self.eval_cached(frame, inputs, &counted_value(inputs), builder);
    }
}

#[derive(Debug, thiserror::Error)]
enum CountedWitnessError {
    #[error("counted fixture setup presence differs from its fixed-column declaration")]
    Presence,
    #[error("counted fixture setup width {actual} differs from declared width {expected}")]
    Width { expected: usize, actual: usize },
    #[error("counted fixture setup height {preprocessed} differs from main height {main}")]
    Height { main: usize, preprocessed: usize },
}

impl native::ProverAir<QuadFelt> for CountedAir {
    type Error = CountedWitnessError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        let width = native::LiftedAir::spec(self).preprocessed_width();
        if inputs.preprocessed.is_some() != (width > 0) {
            return Err(CountedWitnessError::Presence);
        }
        if let Some(trace) = inputs.preprocessed {
            if trace.height() != inputs.main.height() {
                return Err(CountedWitnessError::Height {
                    main: inputs.main.height(),
                    preprocessed: trace.height(),
                });
            }
            if trace.width() != width {
                return Err(CountedWitnessError::Width { expected: width, actual: trace.width() });
            }
        }
        self.borrowed_address.store(
            inputs.preprocessed.map_or(0, |trace| trace.values.as_ptr() as usize),
            Ordering::Relaxed,
        );
        self.aux_calls.fetch_add(1, Ordering::Relaxed);
        let auxiliary = native::ProverAir::build_aux_trace(&self.inner, inputs)
            .unwrap_or_else(|never| match never {});
        Ok(native::AuxTrace {
            columns: auxiliary.columns,
            exports: vec![
                inputs.challenges[0].double() + QuadFelt::from_usize(inputs.main.height()),
            ],
        })
    }
}

// Owns expressions and per-binding state; no Default or Clone implementation is required.
struct CountedPrepared<E> {
    value: E,
    evaluations: AtomicUsize,
}

struct CountingKernel {
    source: CountedAir,
    descriptor: native::AirDescriptor<Felt>,
}

impl CountingKernel {
    fn new(source: CountedAir) -> Result<Self, native::DescriptorError> {
        let descriptor = native::capture(&source)?.descriptor;
        Ok(Self { source, descriptor })
    }
}

impl native::AirKernel for CountingKernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = CountedPrepared<E>;

    fn descriptor(&self) -> &native::AirDescriptor<Felt> {
        &self.descriptor
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: native::UniformInputs<'_, B, E>,
    ) -> CountedPrepared<E> {
        self.source.preparations.fetch_add(1, Ordering::Relaxed);
        CountedPrepared {
            value: counted_value(inputs),
            evaluations: AtomicUsize::new(0),
        }
    }

    fn eval_row<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        prepared: &CountedPrepared<AB::ExtExpr>,
        builder: &mut AB,
    ) {
        self.source.record_evaluation(&prepared.evaluations);
        self.source.eval_cached(frame, inputs, &prepared.value, builder);
    }
}

impl native::LiftedAir for CountingKernel {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        self.descriptor.spec().as_borrowed()
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        native::LiftedAir::build_preprocessed_trace(&self.source)
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        native::LiftedAir::eval(&self.source, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for CountingKernel {
    type Error = CountedWitnessError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native::ProverAir::build_aux_trace(&self.source, inputs)
    }
}

#[test]
fn prover_reuses_setup_and_evaluation_data() {
    // Include a missing table and different heights in an instance order unlike proof order.
    // The largest trace spans multiple parallel row batches.
    let airs: Vec<_> = [
        MixedAir::Constant(ConstantAir),
        MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))),
        MixedAir::RowCounter(RowCounterAir::new(row_index_trace(2))),
    ]
    .into_iter()
    .map(CountedAir::new)
    .collect();
    let make_statement = || {
        prover_statement(
            airs.iter()
                .cloned()
                .map(|source| CountingKernel::new(source).unwrap())
                .collect(),
            vec![squaring_trace(1024), row_index_trace(4), row_index_trace(2)],
        )
    };
    let config = test_config();
    let first = make_statement();
    let preprocessed = Preprocessed::build(first.statement(), &config)
        .expect("valid fixed setup")
        .expect("has preprocessed");
    let original_addresses: Vec<_> = preprocessed
        .raw_traces()
        .iter()
        .map(|trace| trace.as_ref().map_or(0, |trace| trace.values.as_ptr() as usize))
        .collect();
    for ps in [first, make_statement()] {
        let prover = ProverInstance::new(&config, ps, Some(&preprocessed)).expect("valid setup");
        let (output, statement) = prover.prove(test_challenger()).expect("prove");
        verify_and_reparse(&config, &statement, &output, &preprocessed);
        for (air, &address) in airs.iter().zip(&original_addresses) {
            assert_eq!(
                air.borrowed_address.load(Ordering::Relaxed),
                address,
                "reuse the original allocation in instance order, including absent slots"
            );
        }
    }
    for (air, height) in airs.iter().zip([1024usize, 4, 2]) {
        assert_eq!(air.materializations.load(Ordering::Relaxed), 1, "generate only during setup");
        assert_eq!(air.aux_calls.load(Ordering::Relaxed), 2, "both proofs build auxiliary traces");
        let kernel = CountingKernel::new(air.clone()).unwrap();
        let quotient_rows = height << crate::log_quotient_degree(&kernel).unwrap();
        let packed_rows = quotient_rows.div_ceil(<Felt as Field>::Packing::WIDTH);
        assert_eq!(
            air.max_batch_evaluations.load(Ordering::Relaxed),
            packed_rows,
            "all packed rows must share one prepared value",
        );
    }
}

#[test]
fn constraint_checker_uses_prover_hooks() {
    for (inner, main) in [
        (MixedAir::Constant(ConstantAir), squaring_trace(4)),
        (MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))), row_index_trace(4)),
    ] {
        let height = main.height();
        let air = CountedAir::new(inner);
        let statement =
            prover_statement(vec![CountingKernel::new(air.clone()).unwrap()], vec![main]);
        let preprocessed =
            Preprocessed::build(statement.statement(), &test_config()).expect("valid fixed setup");
        check_constraints(
            &statement,
            preprocessed.as_ref().map(Preprocessed::raw_traces),
            test_challenger(),
        );

        assert_eq!(air.materializations.load(Ordering::Relaxed), 1, "reuse one setup trace");
        assert_eq!(air.aux_calls.load(Ordering::Relaxed), 1, "use the cached setup hook");
        assert_eq!(air.preparations.load(Ordering::Relaxed), 2, "prepare once per checking pass");
        assert_eq!(
            air.prepared_evaluations.load(Ordering::Relaxed),
            2 * height,
            "both the base and full passes must use the prepared evaluator",
        );
    }
}

fn capture_counting_kernel(
    kernel: &CountingKernel,
    rows_per_binding: usize,
) -> native::Capture<Felt, QuadFelt> {
    use native::AirKernel;

    native::capture_from_spec::<Felt, QuadFelt>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| {
            let session = kernel.bind(inputs).unwrap();
            for _ in 0..rows_per_binding {
                session.eval(frame, sink);
            }
        },
    )
    .unwrap()
}

#[test]
fn native_counted_kernel_preserves_source_setup_borrows_and_binding_lifecycle() {
    use native::AirKernel;

    fn assert_sync<T: Sync>() {}
    assert_sync::<CountedPrepared<PackedQuadFelt>>();

    for (inner, main, base_indices, ext_indices) in [
        (MixedAir::Constant(ConstantAir), squaring_trace(4), vec![1], vec![0, 2]),
        (
            MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))),
            row_index_trace(4),
            vec![1, 2],
            vec![0, 3],
        ),
    ] {
        let source = CountedAir::new(inner);
        let expected = native::capture_with::<_, QuadFelt>(&source).unwrap();
        let kernel = CountingKernel::new(source.clone()).unwrap();
        assert_eq!(expected.descriptor.analysis().layout().base_indices(), base_indices.as_slice());
        assert_eq!(expected.descriptor.analysis().layout().ext_indices(), ext_indices.as_slice());
        assert_eq!(source.materializations.load(Ordering::Relaxed), 0);
        assert_eq!(source.aux_calls.load(Ordering::Relaxed), 0);
        assert_eq!(source.preparations.load(Ordering::Relaxed), 0);
        assert_eq!(source.prepared_evaluations.load(Ordering::Relaxed), 0);

        // Explicit setup materializes at most one table. Both witness calls borrow that allocation.
        let fixed = native::LiftedAir::build_preprocessed_trace(&kernel);
        let address = fixed.as_ref().map_or(0, |trace| trace.values.as_ptr() as usize);
        let public = [Felt::from_u64(3)];
        let challenges = [QuadFelt::from_u64(7)];
        for _ in 0..2 {
            let auxiliary = native::ProverAir::build_aux_trace(
                &kernel,
                native::AuxTraceInputs {
                    main: &main,
                    preprocessed: fixed.as_ref(),
                    public_values: &public,
                    statement: &[],
                    challenges: &challenges,
                },
            )
            .unwrap();
            assert_eq!(auxiliary.columns.values, vec![QuadFelt::from_u64(7); 4]);
            assert_eq!(auxiliary.exports, vec![QuadFelt::from_u64(18)]);
            assert_eq!(source.borrowed_address.load(Ordering::Relaxed), address);
        }
        assert_eq!(source.materializations.load(Ordering::Relaxed), 1);
        assert_eq!(source.aux_calls.load(Ordering::Relaxed), 2);

        let exports = [QuadFelt::from_u64(18)];
        assert!(matches!(
            kernel.bind::<Felt, QuadFelt>(native::UniformInputs {
                public_values: &[],
                challenges: &challenges,
                exports: &exports,
            }),
            Err(native::BindError::PublicValues { expected: 1, actual: 0 }),
        ));
        assert_eq!(source.preparations.load(Ordering::Relaxed), 0);

        // A real non-Copy symbolic session shares its owned prepared value across row evaluations.
        let once = capture_counting_kernel(&kernel, 1);
        assert_eq!(once.descriptor.fingerprint(), expected.descriptor.fingerprint());
        assert_eq!(once.descriptor.analysis(), expected.descriptor.analysis());
        assert_eq!(source.preparations.load(Ordering::Relaxed), 1);
        assert_eq!(source.prepared_evaluations.load(Ordering::Relaxed), 1);
        assert_eq!(source.max_batch_evaluations.load(Ordering::Relaxed), 1);
        let repeated = capture_counting_kernel(&kernel, 3);
        assert_eq!(
            repeated.descriptor.analysis().layout().total_constraints(),
            3 * expected.descriptor.analysis().layout().total_constraints(),
        );
        assert_eq!(source.preparations.load(Ordering::Relaxed), 2);
        assert_eq!(source.prepared_evaluations.load(Ordering::Relaxed), 4);
        assert_eq!(source.max_batch_evaluations.load(Ordering::Relaxed), 3);
        assert_eq!(source.materializations.load(Ordering::Relaxed), 1);
        assert_eq!(source.aux_calls.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn native_counted_witness_checks_setup_before_recording_a_borrow() {
    let source = CountedAir::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(4))));
    let main = row_index_trace(4);
    let wrong_width = RowMajorMatrix::new(vec![Felt::ZERO; 8], 2);
    let wrong_height = row_index_trace(2);
    let public = [Felt::from_u64(3)];
    let challenges = [QuadFelt::from_u64(7)];
    let build = |preprocessed| {
        native::ProverAir::build_aux_trace(
            &source,
            native::AuxTraceInputs {
                main: &main,
                preprocessed,
                public_values: &public,
                statement: &[],
                challenges: &challenges,
            },
        )
    };
    assert!(matches!(build(None), Err(CountedWitnessError::Presence)));
    assert!(matches!(
        build(Some(&wrong_width)),
        Err(CountedWitnessError::Width { expected: 1, actual: 2 }),
    ));
    assert!(matches!(
        build(Some(&wrong_height)),
        Err(CountedWitnessError::Height { main: 4, preprocessed: 2 }),
    ));
    assert_eq!(source.aux_calls.load(Ordering::Relaxed), 0);
    assert_eq!(source.borrowed_address.load(Ordering::Relaxed), 0);
    assert_eq!(source.materializations.load(Ordering::Relaxed), 0);
}
