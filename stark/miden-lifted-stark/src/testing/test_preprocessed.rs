//! End-to-end tests for preprocessed traces on the stark-instance API.
//!
//! These exercise the real preprocessed path: the commitment is observed
//! first, the tree is opened via the PCS, and the per-AIR window is fed to the
//! constraint folders. Preprocessed content is served through
//! [`BaseAir::preprocessed_trace`]; the prover bundles it via
//! [`Preprocessed::build`] + [`ProverInstance::new`], and the verifier receives
//! only the commitment via [`VerifierInstance::new`].

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Preprocessed, PreprocessedValidationError, ProverInstance, VerifierInstance,
    air::{
        AirBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder, MultiAir,
        ProverStatement, Statement, WindowAccess,
    },
    pcs::params::PcsParams,
    proof::{StarkOutput, StarkProof},
    testing::configs::goldilocks_poseidon2::{
        Felt, Lmcs, QuadFelt, TestConfig, test_challenger, test_config,
    },
};

// ---------------------------------------------------------------------------
// AIR fixtures
// ---------------------------------------------------------------------------

/// AIR with a preprocessed column carrying the row index `0, 1, 2, …`, served
/// by value through [`BaseAir::preprocessed_trace`].
///
/// Constraints (gated so symbolic degree ≥ 2): first row `main[0] ==
/// preprocessed[0]`; transition `Δmain == Δpreprocessed` (uses the
/// preprocessed window non-trivially); first row `aux[0] == challenge`.
#[derive(Clone, Debug)]
struct RowCounterAir {
    preprocessed: RowMajorMatrix<Felt>,
}

impl BaseAir<Felt> for RowCounterAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }
}

impl LiftedAir<Felt, QuadFelt> for RowCounterAir {
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let local_main: AB::Expr = main.current_slice()[0].into();
        let next_main: AB::Expr = main.next_slice()[0].into();

        let preproc = builder.preprocessed();
        let local_preproc: AB::Expr = preproc.current_slice()[0].into();
        let next_preproc: AB::Expr = preproc.next_slice()[0].into();

        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();

        builder.when_first_row().assert_eq(local_main.clone(), local_preproc.clone());
        builder
            .when_transition()
            .assert_eq(next_main - local_main, next_preproc - local_preproc);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
    }
}

/// AIR with no preprocessed columns. Transition `next == local²`.
#[derive(Clone, Copy, Debug)]
struct ConstantAir;

impl BaseAir<Felt> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
}

impl LiftedAir<Felt, QuadFelt> for ConstantAir {
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let local: AB::Expr = main.current_slice()[0].into();
        let next: AB::Expr = main.next_slice()[0].into();

        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();

        builder.when_transition().assert_eq(next, local.clone() * local);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
    }
}

/// Heterogeneous AIR for mixed-instance tests.
#[derive(Clone, Debug)]
enum MixedAir {
    Constant(ConstantAir),
    RowCounter(RowCounterAir),
}

impl BaseAir<Felt> for MixedAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::Constant(_) => None,
            Self::RowCounter(a) => a.preprocessed_trace(),
        }
    }
}

impl LiftedAir<Felt, QuadFelt> for MixedAir {
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Constant(_) => 0,
            Self::RowCounter(a) => a.preprocessed_width(),
        }
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        match self {
            Self::Constant(a) => a.build_aux_trace(main, air_inputs, aux_inputs, challenges),
            Self::RowCounter(a) => a.build_aux_trace(main, air_inputs, aux_inputs, challenges),
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Constant(a) => a.eval(builder),
            Self::RowCounter(a) => a.eval(builder),
        }
    }
}

/// AIR that declares a wider preprocessed trace (`preprocessed_width() == 2`)
/// than the matrix it serves (width 1), to drive the width-mismatch check.
#[derive(Clone, Debug)]
struct WrongWidthAir {
    preprocessed: RowMajorMatrix<Felt>,
}

impl BaseAir<Felt> for WrongWidthAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed.clone())
    }
}

impl LiftedAir<Felt, QuadFelt> for WrongWidthAir {
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main.height(), challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Well-formed degree-2 constraint; never reached because validation
        // rejects the bundle before proving.
        let main = builder.main();
        let local: AB::Expr = main.current_slice()[0].into();
        let next: AB::Expr = main.next_slice()[0].into();
        let aux = builder.permutation();
        let aux_local: AB::ExprEF = aux.current_slice()[0].into();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();
        builder.when_transition().assert_eq(next, local.clone() * local);
        builder.when_first_row().assert_eq_ext(aux_local, challenge);
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

impl<A: LiftedAir<Felt, QuadFelt>> MultiAir<Felt, QuadFelt> for PreprocMultiAir<A> {
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

/// Build a no-public-input prover statement for `airs` + `traces`.
fn prover_statement<A: LiftedAir<Felt, QuadFelt>>(
    airs: Vec<A>,
    traces: Vec<RowMajorMatrix<Felt>>,
) -> ProverStatement<Felt, QuadFelt, PreprocMultiAir<A>> {
    let statement = Statement::new(PreprocMultiAir { airs }, vec![], vec![]).expect("statement");
    ProverStatement::new(statement, traces).expect("prover statement")
}

type TestOutput = StarkOutput<Felt, QuadFelt, TestConfig>;
type TestPreprocessed = Preprocessed<Felt, Lmcs>;

fn prove_with_preprocessed<MA>(
    config: &TestConfig,
    ps: &ProverStatement<Felt, QuadFelt, MA>,
) -> (TestOutput, TestPreprocessed)
where
    MA: MultiAir<Felt, QuadFelt>,
{
    let preprocessed = Preprocessed::build(ps.statement(), config).expect("has preprocessed");
    let output = ProverInstance::new(config, ps, Some(&preprocessed))
        .expect("valid preprocessed setup")
        .prove(test_challenger())
        .expect("prove succeeds");
    (output, preprocessed)
}

fn verify_and_reparse<MA>(
    config: &TestConfig,
    ps: &ProverStatement<Felt, QuadFelt, MA>,
    output: &TestOutput,
    preprocessed: &TestPreprocessed,
) where
    MA: MultiAir<Felt, QuadFelt>,
{
    let verifier_instance =
        VerifierInstance::new(config, ps.statement(), Some(preprocessed.commitment()))
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

fn prove_verify_reparse<MA>(ps: &ProverStatement<Felt, QuadFelt, MA>)
where
    MA: MultiAir<Felt, QuadFelt>,
{
    let config = test_config();
    let (output, preprocessed) = prove_with_preprocessed(&config, ps);
    verify_and_reparse(&config, ps, &output, &preprocessed);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn single_air_with_preprocessed() {
    let height = 8;
    let ps = prover_statement(
        vec![RowCounterAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let config = test_config();
    let (output, preprocessed) = prove_with_preprocessed(&config, &ps);
    verify_and_reparse(&config, &ps, &output, &preprocessed);

    let missing_commitment = VerifierInstance::new(&config, ps.statement(), None);
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
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(height) }),
        ],
        vec![squaring_trace(height), row_index_trace(height)],
    );

    prove_verify_reparse(&ps);
}

#[test]
fn rejects_width_mismatch() {
    let height = 8;
    let ps = prover_statement(
        vec![WrongWidthAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let result = ProverInstance::new(&config, &ps, Some(&preprocessed));
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
        vec![RowCounterAir { preprocessed: row_index_trace(4) }],
        vec![row_index_trace(8)],
    );
    let config = test_config();

    let preprocessed = Preprocessed::build(ps.statement(), &config).expect("has preprocessed");
    let result = ProverInstance::new(&config, &ps, Some(&preprocessed));
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::HeightMismatch { main: 8, preprocessed: 4, .. })
        ),
        "expected HeightMismatch {{ main: 8, preprocessed: 4 }}",
    );
}

#[test]
fn rejects_log_blowup_mismatch() {
    let height = 8;
    let ps = prover_statement(
        vec![RowCounterAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let build_config = test_config();
    let preprocessed =
        Preprocessed::build(ps.statement(), &build_config).expect("has preprocessed");

    let mut proving_config = test_config();
    proving_config.pcs = PcsParams::new(2, 2, 2, 0, 0, 2, 0).expect("valid PCS params");
    let result = ProverInstance::new(&proving_config, &ps, Some(&preprocessed));
    assert!(
        matches!(
            result,
            Err(PreprocessedValidationError::LdeHeightMismatch {
                log_blowup: 2,
                expected: 32,
                actual: 64,
                ..
            })
        ),
        "expected LdeHeightMismatch for setup built with a different log_blowup",
    );
}

#[test]
fn rejects_wrong_trusted_preprocessed_commitment() {
    let height = 8;
    let ps = prover_statement(
        vec![RowCounterAir { preprocessed: row_index_trace(height) }],
        vec![row_index_trace(height)],
    );
    let config = test_config();
    let (output, _preprocessed) = prove_with_preprocessed(&config, &ps);

    let wrong_ps = prover_statement(
        vec![RowCounterAir {
            preprocessed: shifted_row_index_trace(height),
        }],
        vec![row_index_trace(height)],
    );
    let wrong_preprocessed =
        Preprocessed::build(wrong_ps.statement(), &config).expect("has preprocessed");
    let verifier_instance =
        VerifierInstance::new(&config, ps.statement(), Some(wrong_preprocessed.commitment()))
            .expect("presence is valid");

    assert!(
        verifier_instance.verify(&output.proof, test_challenger()).is_err(),
        "verification must reject a proof checked against the wrong trusted setup commitment",
    );
}

#[test]
fn preprocessed_shorter_than_max_trace() {
    // The tallest AIR (ConstantAir, height 8) has no preprocessed columns, so the
    // tallest preprocessed trace (RowCounter, height 4) sits below the max trace
    // height. The PCS virtually lifts the shorter preprocessed tree.
    let ps = prover_statement(
        vec![
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(4) }),
        ],
        vec![squaring_trace(8), row_index_trace(4)],
    );

    prove_verify_reparse(&ps);
}

#[test]
fn preprocessed_much_shorter_than_max_trace() {
    // Larger lift ratio: the preprocessed tree (height 2) is folded by 4 at query
    // time against a max trace height of 8.
    let ps = prover_statement(
        vec![
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(2) }),
        ],
        vec![squaring_trace(8), row_index_trace(2)],
    );

    prove_verify_reparse(&ps);
}

#[test]
fn preprocessed_multiple_heights_below_max() {
    // Two preprocessed AIRs at heights 2 and 4 (so the preprocessed tree lifts
    // internally to 4), under a taller non-preprocessed AIR at height 8. Exercises
    // both within-tree lifting and the global query fold.
    let ps = prover_statement(
        vec![
            MixedAir::Constant(ConstantAir),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(4) }),
            MixedAir::RowCounter(RowCounterAir { preprocessed: row_index_trace(2) }),
        ],
        vec![squaring_trace(8), row_index_trace(4), row_index_trace(2)],
    );

    prove_verify_reparse(&ps);
}
