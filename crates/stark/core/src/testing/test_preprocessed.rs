//! End-to-end tests for preprocessed traces on the stark-instance API.
//!
//! These exercise the real preprocessed path: the commitment is observed
//! first, the tree is opened via the PCS, and the per-AIR window is fed to the
//! constraint folders. Preprocessed content is served through
//! native source factories; the prover bundles it via
//! [`Preprocessed::build`] + [`ProverInstance::new`], and the verifier receives
//! a trusted setup identity via [`VerifierInstance::new`] and native table heights from
//! descriptors.

use alloc::{borrow::Cow, sync::Arc, vec, vec::Vec};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
};

use p3_field::{Algebra, Dup, Field, PackedValue, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    PlanError, Preprocessed, PreprocessedValidationError, ProverError, ProverInstance, ShapeError,
    VerifierError, VerifierInstance, air,
    air::{LiftedAirBuilder as _, MultiAir, ProverStatement, Statement, log2_strict_u8},
    check_constraints,
    pcs::params::PcsParams,
    proof::{StarkOutput, StarkProof},
    prover::PackedPreparation,
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
}

impl RowCounterAir {
    fn new(preprocessed: RowMajorMatrix<Felt>) -> Self {
        Self { preprocessed }
    }
}

impl air::LiftedAir for RowCounterAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: Some(air::PreprocessedSpec {
                width: self.preprocessed.width(),
                log_height: log2_strict_u8(self.preprocessed.height()),
            }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
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

impl air::ProverAir<QuadFelt> for RowCounterAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        let (columns, exports) = build_aux(inputs.main.height(), inputs.challenges);
        Ok(air::AuxTrace { columns, exports })
    }
}

/// AIR with no preprocessed columns. Transition `next == local²`.
#[derive(Clone, Copy, Debug)]
struct ConstantAir;

impl air::LiftedAir for ConstantAir {
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
        let local = frame.main.current[0].dup();
        builder
            .when(frame.transition())
            .assert_eq(frame.main.next[0].dup(), local.dup() * local);
        builder
            .when(frame.first_row())
            .assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl air::ProverAir<QuadFelt> for ConstantAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        let (columns, exports) = build_aux(inputs.main.height(), inputs.challenges);
        Ok(air::AuxTrace { columns, exports })
    }
}

/// Heterogeneous AIR for mixed-instance tests.
#[derive(Clone, Debug)]
enum MixedAir {
    Constant(ConstantAir),
    RowCounter(RowCounterAir),
}

impl air::LiftedAir for MixedAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        match self {
            Self::Constant(air) => air::LiftedAir::spec(air),
            Self::RowCounter(air) => air::LiftedAir::spec(air),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::Constant(air) => air::LiftedAir::build_preprocessed_trace(air),
            Self::RowCounter(air) => air::LiftedAir::build_preprocessed_trace(air),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        match self {
            Self::Constant(air) => air::LiftedAir::eval(air, frame, inputs, builder),
            Self::RowCounter(air) => air::LiftedAir::eval(air, frame, inputs, builder),
        }
    }
}

impl air::ProverAir<QuadFelt> for MixedAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        match self {
            Self::Constant(air) => air::ProverAir::build_aux_trace(air, inputs),
            Self::RowCounter(air) => air::ProverAir::build_aux_trace(air, inputs),
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

impl<A: air::AirKernel<F = Felt>> MultiAir<Felt, QuadFelt> for PreprocMultiAir<A> {
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
fn prover_statement<A: air::AirKernel<F = Felt>>(
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
) -> ProverStatement<Felt, QuadFelt, PreprocMultiAir<air::DirectKernel<RowCounterAir>>> {
    let airs = traces
        .iter()
        .cloned()
        .map(|trace| air::DirectKernel::new(RowCounterAir::new(trace)).unwrap())
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
    MA::Air: air::ProverAir<QuadFelt> + air::LiftedAir<F = Felt>,
    <MA::Air as air::AirKernel>::Prepared<PackedFelt, PackedQuadFelt>: PackedPreparation,
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
    MA::Air: air::ProverAir<QuadFelt> + air::LiftedAir<F = Felt>,
    <MA::Air as air::AirKernel>::Prepared<PackedFelt, PackedQuadFelt>: PackedPreparation,
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
            air::DirectKernel::new(MixedAir::Constant(ConstantAir)).unwrap(),
            air::DirectKernel::new(MixedAir::RowCounter(RowCounterAir::new(row_index_trace(
                height,
            ))))
            .unwrap(),
        ],
        vec![squaring_trace(height), row_index_trace(height)],
    );

    prove_verify_reparse(ps);
}

#[test]
fn rejects_height_mismatch() {
    // Preprocessed matrix height (4) differs from the main trace height (8).
    let ps = prover_statement(
        vec![air::DirectKernel::new(RowCounterAir::new(row_index_trace(4))).unwrap()],
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
            Err(ProverError::Plan(PlanError::Shape(ShapeError::PreprocessedHeightMismatch {
                air: 0,
                log_trace_height: 3,
                log_preprocessed_height: 2,
            })))
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
        Err(ProverError::Preprocessed(PreprocessedValidationError::FingerprintMismatch {
            air: 0,
            ..
        }))
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
            Err(ProverError::Preprocessed(PreprocessedValidationError::BlowupMismatch {
                expected: 2,
                actual: 3
            }))
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
                .map(|source| air::DirectKernel::new(source).unwrap())
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
                .map(|source| air::DirectKernel::new(source).unwrap())
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
fn mixed_proofs_open_fixed_tables_across_trace_heights() {
    let cases: &[(usize, &[usize])] = &[
        (2, &[8]),    // A short nonlinear trace exercises partial packed output.
        (8, &[4]),    // The shorter fixed tree is virtually lifted.
        (8, &[2]),    // The larger lift ratio requires more global query folding.
        (8, &[4, 2]), // Internal fixed-tree lifting and global folding both occur.
    ];
    for &(nonfixed_height, fixed_heights) in cases {
        let mut airs = vec![MixedAir::Constant(ConstantAir)];
        let mut traces = vec![squaring_trace(nonfixed_height)];
        for &height in fixed_heights {
            let trace = row_index_trace(height);
            airs.push(MixedAir::RowCounter(RowCounterAir::new(trace.clone())));
            traces.push(trace);
        }
        let kernels = airs.into_iter().map(|air| air::DirectKernel::new(air).unwrap()).collect();
        prove_verify_reparse(prover_statement(kernels, traces));
    }
}

/// Record auxiliary-builder and evaluator calls during proving and constraint checks.
#[derive(Clone, Debug)]
struct CountedAir {
    inner: MixedAir,
    counters: Arc<LifecycleCounters>,
}

#[derive(Debug, Default)]
struct LifecycleCounters {
    materializations: AtomicUsize,
    aux_calls: AtomicUsize,
    borrowed_address: AtomicUsize,
    preparations: AtomicUsize,
    prepared_evaluations: AtomicUsize,
    max_batch_evaluations: AtomicUsize,
}

impl CountedAir {
    fn new(inner: MixedAir) -> Self {
        Self { inner, counters: Arc::default() }
    }
}

fn counted_value<B: Algebra<Felt>, E: Algebra<B>>(inputs: air::UniformInputs<'_, B, E>) -> E {
    inputs.challenges[0].square() + inputs.exports[0].dup() * inputs.public_values[0].dup()
}

impl CountedAir {
    fn record_evaluation(&self, evaluations: &AtomicUsize) {
        self.counters.prepared_evaluations.fetch_add(1, Ordering::Relaxed);
        let count = evaluations.fetch_add(1, Ordering::Relaxed) + 1;
        self.counters.max_batch_evaluations.fetch_max(count, Ordering::Relaxed);
    }

    fn eval_cached<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        cached: &AB::ExtExpr,
        builder: &mut AB,
    ) {
        // Compare with independently read uniform inputs before the inner assertion stream.
        builder.assert_eq_ext(cached.dup(), counted_value(inputs));
        air::LiftedAir::eval(&self.inner, frame, inputs, builder);
    }
}

impl air::LiftedAir for CountedAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        let mut spec = air::LiftedAir::spec(&self.inner);
        spec.num_public_values = 1;
        spec.num_exports = 1;
        spec
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.counters.materializations.fetch_add(1, Ordering::Relaxed);
        air::LiftedAir::build_preprocessed_trace(&self.inner)
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // Source capture describes the relation without exercising kernel lifecycle counters.
        self.eval_cached(frame, inputs, &counted_value(inputs), builder);
    }
}

impl air::ProverAir<QuadFelt> for CountedAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        self.counters.borrowed_address.store(
            inputs.preprocessed.map_or(0, |trace| trace.values.as_ptr() as usize),
            Ordering::Relaxed,
        );
        self.counters.aux_calls.fetch_add(1, Ordering::Relaxed);
        let auxiliary = air::ProverAir::build_aux_trace(&self.inner, inputs)
            .unwrap_or_else(|never| match never {});
        Ok(air::AuxTrace {
            columns: auxiliary.columns,
            exports: vec![
                inputs.challenges[0].double() + QuadFelt::from_usize(inputs.main.height()),
            ],
        })
    }
}

// Owns expressions and per-binding state; no Default or Clone implementation is required.
// Serial builds deliberately make this state non-Sync, exercising the actual prover call below.
struct CountedPrepared<E> {
    value: E,
    evaluations: AtomicUsize,
    #[cfg(not(feature = "concurrent"))]
    _single_threaded: core::marker::PhantomData<core::cell::Cell<()>>,
}

struct CountingKernel {
    source: CountedAir,
    descriptor: air::AirDescriptor<Felt>,
}

impl CountingKernel {
    fn new(source: CountedAir) -> Result<Self, air::DescriptorError> {
        let descriptor = air::capture(&source)?.descriptor;
        Ok(Self { source, descriptor })
    }
}

impl air::AirKernel for CountingKernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = CountedPrepared<E>;

    fn descriptor(&self) -> &air::AirDescriptor<Felt> {
        &self.descriptor
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: air::UniformInputs<'_, B, E>,
    ) -> CountedPrepared<E> {
        self.source.counters.preparations.fetch_add(1, Ordering::Relaxed);
        CountedPrepared {
            value: counted_value(inputs),
            evaluations: AtomicUsize::new(0),
            #[cfg(not(feature = "concurrent"))]
            _single_threaded: core::marker::PhantomData,
        }
    }

    fn eval_row<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        prepared: &CountedPrepared<AB::ExtExpr>,
        builder: &mut AB,
    ) {
        self.source.record_evaluation(&prepared.evaluations);
        self.source.eval_cached(frame, inputs, &prepared.value, builder);
    }
}

impl air::LiftedAir for CountingKernel {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        self.descriptor.spec().as_borrowed()
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        air::LiftedAir::build_preprocessed_trace(&self.source)
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        air::LiftedAir::eval(&self.source, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for CountingKernel {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        air::ProverAir::build_aux_trace(&self.source, inputs)
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
                air.counters.borrowed_address.load(Ordering::Relaxed),
                address,
                "reuse the original allocation in instance order, including absent slots"
            );
        }
    }
    for (air, height) in airs.iter().zip([1024usize, 4, 2]) {
        assert_eq!(
            air.counters.materializations.load(Ordering::Relaxed),
            1,
            "generate only during setup"
        );
        assert_eq!(
            air.counters.aux_calls.load(Ordering::Relaxed),
            2,
            "both proofs build auxiliary traces"
        );
        let kernel = CountingKernel::new(air.clone()).unwrap();
        let quotient_rows = height << crate::log_quotient_degree(&kernel).unwrap();
        let packed_rows = quotient_rows.div_ceil(<Felt as Field>::Packing::WIDTH);
        assert_eq!(
            air.counters.max_batch_evaluations.load(Ordering::Relaxed),
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

        assert_eq!(
            air.counters.materializations.load(Ordering::Relaxed),
            1,
            "reuse one setup trace"
        );
        assert_eq!(air.counters.aux_calls.load(Ordering::Relaxed), 1, "use the cached setup hook");
        assert_eq!(
            air.counters.preparations.load(Ordering::Relaxed),
            2,
            "prepare once per checking pass"
        );
        assert_eq!(
            air.counters.prepared_evaluations.load(Ordering::Relaxed),
            2 * height,
            "both the base and full passes must use the prepared evaluator",
        );
    }
}
