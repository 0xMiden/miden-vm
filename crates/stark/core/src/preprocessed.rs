//! Preprocessed data: the fixed per-AIR matrices and their committed LDE tree.
//!
//! Preprocessed columns are setup-owned fixed circuit data declared by the native descriptor.
//! Setup calls each source factory once and retains its matrix beside the committed LDE tree.
//! Provers borrow this cache; verifiers receive a trusted [`SetupIdentity`] associating the root
//! with ordered descriptor fingerprints and the PCS/alignment parameters. Neither capture nor
//! verifier construction invokes a factory. Fingerprints are local association metadata and are
//! never added to the protocol transcript.

use alloc::{vec, vec::Vec};

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;
use tracing::trace_span;

use crate::{
    StarkConfig,
    air::{AirKernel, LiftedAir, MultiAir, PreprocessedSpec, Statement, log2_strict_u8},
    domain::{DomainError, LiftedDomain},
    lmcs::{Lmcs, LmcsError, LmcsTree, tree_indices::TreeIndices},
    plan::ExecutionPlan,
    prover::commit::Committed,
};

/// Association of a trusted fixed-setup root with immutable AIR and PCS metadata.
///
/// This does not authenticate an arbitrary root, evaluator or fixed-matrix contents. The caller
/// supplies a trusted root; ordered fingerprints, blowup and alignment prevent accidentally
/// reusing it with different relation/configuration metadata. Execution allocation is deliberately
/// excluded, so a kernel may raise its quotient capacity while reusing the same fixed setup.
/// Only the commitment, never these fingerprints, is observed by the protocol transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupIdentity<C> {
    commitment: C,
    fingerprints: Vec<[u8; 32]>,
    log_blowup: u8,
    alignment: usize,
}

impl<C> SetupIdentity<C> {
    /// Associate an existing trusted root without evaluating a source or constructing any table.
    ///
    /// Optional setup presence is checked by the instance constructor. This constructor does not
    /// prove that `commitment` is the root of the declared matrices.
    pub fn new<EF, K, SC>(commitment: C, kernels: &[K], config: &SC) -> Self
    where
        K: AirKernel,
        K::F: TwoAdicField,
        EF: ExtensionField<K::F>,
        SC: StarkConfig<K::F, EF>,
        SC::Lmcs: Lmcs<Commitment = C>,
    {
        Self {
            commitment,
            fingerprints: kernels.iter().map(|kernel| kernel.descriptor().fingerprint()).collect(),
            log_blowup: config.pcs().log_blowup(),
            alignment: config.lmcs().alignment(),
        }
    }

    pub fn commitment(&self) -> &C {
        &self.commitment
    }

    /// Descriptor fingerprints in AIR instance order, including AIRs without fixed data.
    pub fn fingerprints(&self) -> &[[u8; 32]] {
        &self.fingerprints
    }

    pub fn log_blowup(&self) -> u8 {
        self.log_blowup
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }
}

// ============================================================================
// Preprocessed
// ============================================================================

/// Fixed per-AIR preprocessed data: the cached raw matrices plus their
/// committed LDE tree.
///
/// `traces[i]` is `Some` exactly when AIR `i` declares preprocessed columns;
/// the LDE tree commits one LDE trace per such AIR, in proof order. Built at
/// setup via [`Preprocessed::build`] and borrowed by prover instances.
///
/// Parameterized over the LMCS `L` rather than a full [`StarkConfig`] so the
/// value can be borrowed by prover instances with the same commitment type. The
/// bundle is still tied to the PCS blowup and LMCS alignment used at build time;
/// `validate_preprocessed` checks those config-dependent dimensions.
pub struct Preprocessed<F, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Per-AIR raw preprocessed matrices in instance order; `None` where the
    /// AIR declares none. Native source factories may allocate on every call, so they are computed
    /// once here and retained for validation, auxiliary-trace construction,
    /// and `check_constraints`.
    traces: Vec<Option<RowMajorMatrix<F>>>,
    /// Committed LDE tree, one committed LDE trace per preprocessed AIR.
    committed: Committed<F, RowMajorMatrix<F>, L>,
    identity: SetupIdentity<L::Commitment>,
}

impl<F, L> Preprocessed<F, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Build and validate the fixed setup, returning `Ok(None)` when no AIR has fixed data.
    ///
    /// Calls each source's factory exactly once, including factories that return `None`, then
    /// validates presence, raw storage, width, native height and LDE domain before committing.
    /// Raw matrices remain in instance order; fixed LDE leaves are sorted by native height and
    /// instance index. Source construction is required only here, not by kernels or verification.
    pub fn build<EF, MA, SC>(
        statement: &Statement<F, EF, MA>,
        config: &SC,
    ) -> Result<Option<Self>, PreprocessedValidationError>
    where
        EF: ExtensionField<F>,
        MA: MultiAir<F, EF>,
        MA::Air: LiftedAir<F = F>,
        SC: StarkConfig<F, EF, Lmcs = L>,
    {
        let airs = statement.airs();
        // Materialize every factory once before inspecting any result, including no-table AIRs.
        let traces: Vec<Option<RowMajorMatrix<F>>> =
            airs.iter().map(LiftedAir::build_preprocessed_trace).collect();

        // Sort by declared height before reading matrix heights: malformed raw storage must not
        // reach Matrix::height. Once validated, these are exactly the native-height sorted leaves.
        let mut pairs: Vec<(usize, &RowMajorMatrix<F>)> = traces
            .iter()
            .enumerate()
            .filter_map(|(i, trace)| trace.as_ref().map(|matrix| (i, matrix)))
            .collect();
        pairs.sort_by_key(|(air, _)| {
            (airs[*air].descriptor().spec().preprocessed.map(|fixed| fixed.log_height), *air)
        });
        let mut trace_for_air = vec![None; airs.len()];
        for (trace, &(air, _)) in pairs.iter().enumerate() {
            trace_for_air[air] = Some(trace);
        }

        let log_blowup = config.pcs().log_blowup();
        for (air, (kernel, matrix)) in airs.iter().zip(&traces).enumerate() {
            let height = validate_raw_trace(
                air,
                trace_for_air[air].unwrap_or(0),
                kernel.descriptor().spec().preprocessed,
                matrix.as_ref(),
            )?;
            if let Some(height) = height {
                LiftedDomain::<F>::try_canonical(log2_strict_u8(height), log_blowup)
                    .map_err(|source| PreprocessedValidationError::Domain { air, source })?;
            }
        }
        if pairs.is_empty() {
            return Ok(None);
        }

        let ldes: Vec<_> = pairs
            .into_iter()
            .map(|(air_idx, trace)| {
                let log_h = log2_strict_u8(trace.height());
                let coset_shift = LiftedDomain::<F>::try_canonical(log_h, log_blowup)
                    .expect("preprocessed domains were validated before LDE construction")
                    .lde_shift();
                let width = trace.width();
                trace_span!(target: "miden::vm::prove", "preprocessed LDE", air = air_idx, log_height = log_h, width).in_scope(
                    || config.dft().coset_lde_batch(trace.clone(), log_blowup.into(), coset_shift),
                )
            })
            .collect();
        let committed: Committed<F, RowMajorMatrix<F>, L> =
            Committed::new(config.lmcs().build_aligned_tree(ldes));
        let identity = SetupIdentity::new::<EF, _, _>(committed.root(), airs, config);
        Ok(Some(Self { traces, committed, identity }))
    }

    /// Commitment (Merkle root) of the preprocessed LDE tree — handed to the
    /// verifier via [`VerifierInstance::new`](crate::VerifierInstance::new).
    pub fn commitment(&self) -> L::Commitment {
        self.committed.root()
    }

    /// Trusted association of this bundle's root, AIRs and fixed-setup parameters.
    pub fn identity(&self) -> &SetupIdentity<L::Commitment> {
        &self.identity
    }

    /// Read-only raw setup matrices in AIR instance order, including `None` for no-table AIRs.
    ///
    /// Borrow these matrices for witness construction and debugging; do not rebuild factories.
    pub fn raw_traces(&self) -> &[Option<RowMajorMatrix<F>>] {
        &self.traces
    }

    /// Build an LMCS batch opening for setup-fixed preprocessed rows.
    ///
    /// The returned proof opens the queried rows against [`Self::commitment`].
    /// Callers that need standalone row authentication can pair this proof with
    /// the preprocessed commitment supplied to their verifier instance.
    pub fn batch_proof<EF, C>(
        &self,
        config: &C,
        query_indices: impl IntoIterator<Item = usize>,
        query_log_height: u8,
    ) -> Result<L::BatchProof, LmcsError>
    where
        EF: ExtensionField<F>,
        C: StarkConfig<F, EF, Lmcs = L>,
    {
        let tree = self.committed.tree();
        let indices = TreeIndices::new(query_indices, query_log_height)?;
        config.lmcs().lifted_batch_proof(tree, &indices)
    }

    /// The committed LDE tree, for opening and per-AIR quotient-domain views.
    pub(crate) fn committed(&self) -> &Committed<F, RowMajorMatrix<F>, L> {
        &self.committed
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Inspect raw storage before any matrix height accessor can divide by its width.
fn raw_matrix_height<F: TwoAdicField>(
    air: usize,
    matrix: &RowMajorMatrix<F>,
) -> Result<usize, PreprocessedValidationError> {
    let width = matrix.width();
    let elements = matrix.values.len();
    if width == 0 || !elements.is_multiple_of(width) {
        return Err(PreprocessedValidationError::RawMatrixShape { air, width, elements });
    }
    let height = elements / width;
    if height < 2 || !height.is_power_of_two() {
        return Err(PreprocessedValidationError::RawMatrixShape { air, width, elements });
    }
    Ok(height)
}

/// Check an identity against kernel metadata and the selected fixed-setup configuration.
/// No source evaluation, factory or witness capability is required.
pub(crate) fn validate_setup_identity<EF, K, SC>(
    config: &SC,
    kernels: &[K],
    identity: &SetupIdentity<<SC::Lmcs as Lmcs>::Commitment>,
) -> Result<(), PreprocessedValidationError>
where
    K: AirKernel,
    K::F: TwoAdicField,
    EF: ExtensionField<K::F>,
    SC: StarkConfig<K::F, EF>,
{
    if identity.fingerprints.len() != kernels.len() {
        return Err(PreprocessedValidationError::FingerprintCountMismatch {
            expected: kernels.len(),
            actual: identity.fingerprints.len(),
        });
    }
    for (air, (kernel, &actual)) in kernels.iter().zip(&identity.fingerprints).enumerate() {
        let expected = kernel.descriptor().fingerprint();
        if actual != expected {
            return Err(PreprocessedValidationError::FingerprintMismatch { air, expected, actual });
        }
    }
    let expected_blowup = config.pcs().log_blowup();
    if identity.log_blowup != expected_blowup {
        return Err(PreprocessedValidationError::BlowupMismatch {
            expected: expected_blowup,
            actual: identity.log_blowup,
        });
    }
    let expected_alignment = config.lmcs().alignment();
    if identity.alignment != expected_alignment {
        return Err(PreprocessedValidationError::AlignmentMismatch {
            expected: expected_alignment,
            actual: identity.alignment,
        });
    }
    Ok(())
}

/// Validate one supplied raw matrix against a descriptor's fixed-data declaration.
/// Returns its native height after checking storage before any height accessor is used.
fn validate_raw_trace<F: TwoAdicField>(
    air: usize,
    trace: usize,
    expected: Option<PreprocessedSpec>,
    matrix: Option<&RowMajorMatrix<F>>,
) -> Result<Option<usize>, PreprocessedValidationError> {
    if expected.is_some() != matrix.is_some() {
        return Err(PreprocessedValidationError::TracePresenceMismatch {
            air,
            expected: expected.is_some(),
            actual: matrix.is_some(),
        });
    }
    let (Some(expected), Some(matrix)) = (expected, matrix) else {
        return Ok(None);
    };
    let height = raw_matrix_height(air, matrix)?;
    let width = matrix.width();
    if width != expected.width {
        return Err(PreprocessedValidationError::WidthMismatch {
            trace,
            air,
            expected: expected.width,
            actual: width,
        });
    }
    let native_height = 1usize << expected.log_height;
    if height != native_height {
        return Err(PreprocessedValidationError::HeightMismatch {
            air,
            main: native_height,
            preprocessed: height,
        });
    }
    Ok(Some(height))
}

/// Validate cached fixed data and its identity against the retained execution plan and kernels.
/// Aggregate optional setup presence is checked by the outer instance constructor.
pub(crate) fn validate_preprocessed<F, EF, K, SC>(
    config: &SC,
    airs: &[K],
    plan: &ExecutionPlan<F>,
    preprocessed: &Preprocessed<F, SC::Lmcs>,
) -> Result<(), PreprocessedValidationError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    K: AirKernel<F = F>,
    SC: StarkConfig<F, EF>,
{
    let log_blowup = config.pcs().log_blowup();
    validate_setup_identity::<EF, _, _>(config, airs, &preprocessed.identity)?;

    if preprocessed.traces.len() != airs.len() {
        return Err(PreprocessedValidationError::RawTraceCountMismatch {
            expected: airs.len(),
            actual: preprocessed.traces.len(),
        });
    }
    let expected_alignment = config.lmcs().alignment();
    let actual_alignment = preprocessed.committed.tree().alignment();
    if actual_alignment != expected_alignment {
        return Err(PreprocessedValidationError::AlignmentMismatch {
            expected: expected_alignment,
            actual: actual_alignment,
        });
    }

    let preprocessed_trace_to_air = &plan.preprocessed_trace_to_air;
    let air_to_preprocessed_trace = &plan.air_to_preprocessed_trace;
    for (air, (kernel, matrix)) in airs.iter().zip(&preprocessed.traces).enumerate() {
        validate_raw_trace(
            air,
            air_to_preprocessed_trace[air].unwrap_or(0),
            kernel.descriptor().spec().preprocessed,
            matrix.as_ref(),
        )?;
    }

    let committed_traces = preprocessed.committed.tree().leaves();
    if committed_traces.len() != preprocessed_trace_to_air.len() {
        return Err(PreprocessedValidationError::TreeLengthMismatch {
            expected: preprocessed_trace_to_air.len(),
            actual: committed_traces.len(),
        });
    }
    for (trace, &air_u8) in preprocessed_trace_to_air.iter().enumerate() {
        let air = air_u8 as usize;
        let expected_width = airs[air].descriptor().spec().preprocessed_width();
        let committed_trace = &committed_traces[trace];
        let actual_width = committed_trace.width();
        if actual_width != expected_width {
            return Err(PreprocessedValidationError::WidthMismatch {
                trace,
                air,
                expected: expected_width,
                actual: actual_width,
            });
        }
        let main_height = 1usize << plan.order.log_heights()[air];
        let expected_lde_height = main_height.checked_shl(u32::from(log_blowup)).ok_or(
            PreprocessedValidationError::LdeHeightOverflow { air, main: main_height, log_blowup },
        )?;
        let actual_lde_height = committed_trace.height();
        if actual_lde_height != expected_lde_height {
            return Err(PreprocessedValidationError::LdeHeightMismatch {
                trace,
                air,
                log_blowup,
                expected: expected_lde_height,
                actual: actual_lde_height,
            });
        }
    }
    Ok(())
}

/// Errors from fixed-setup construction, trusted association validation and cached matrix shape.
#[derive(Debug, Error)]
pub enum PreprocessedValidationError {
    #[error("fixed setup has {actual} descriptor fingerprints, expected {expected}")]
    FingerprintCountMismatch { expected: usize, actual: usize },
    #[error("AIR {air}: fixed setup descriptor fingerprint differs from the selected kernel")]
    FingerprintMismatch {
        air: usize,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("fixed setup uses PCS log blowup {actual}, expected {expected}")]
    BlowupMismatch { expected: u8, actual: u8 },
    #[error("AIR {air}: invalid fixed-data LDE domain: {source}")]
    Domain {
        air: usize,
        #[source]
        source: DomainError,
    },
    #[error(
        "preprocessed setup presence mismatch: AIRs declare preprocessed columns = {expected}, setup supplied = {actual}"
    )]
    PresenceMismatch { expected: bool, actual: bool },
    #[error("raw preprocessed trace count {actual} does not match AIR count {expected}")]
    RawTraceCountMismatch { expected: usize, actual: usize },
    #[error(
        "AIR {air}: raw preprocessed storage ({elements} elements, width {width}) must contain complete power-of-two rows, at least two"
    )]
    RawMatrixShape {
        air: usize,
        width: usize,
        elements: usize,
    },
    #[error(
        "AIR {air}: preprocessed trace presence mismatch: AIR declares preprocessed columns = {expected}, raw trace supplied = {actual}"
    )]
    TracePresenceMismatch { air: usize, expected: bool, actual: bool },
    #[error(
        "preprocessed setup alignment mismatch: config expects {expected}, setup uses {actual}"
    )]
    AlignmentMismatch { expected: usize, actual: usize },
    #[error(
        "preprocessed trace {trace} (AIR {air}) width mismatch: AIR declares {expected}, setup has {actual}"
    )]
    WidthMismatch {
        trace: usize,
        air: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "preprocessed trace count {actual} does not match the preprocessed-AIR count {expected}"
    )]
    TreeLengthMismatch { expected: usize, actual: usize },
    #[error(
        "AIR {air}: preprocessed matrix height ({preprocessed}) does not match declared native/main height ({main})"
    )]
    HeightMismatch {
        air: usize,
        main: usize,
        preprocessed: usize,
    },
    #[error(
        "AIR {air}: main trace height {main} overflows usize when shifted by log_blowup {log_blowup}"
    )]
    LdeHeightOverflow { air: usize, main: usize, log_blowup: u8 },
    #[error(
        "preprocessed trace {trace} (AIR {air}) LDE height mismatch for log_blowup {log_blowup}: expected {expected}, setup has {actual}"
    )]
    LdeHeightMismatch {
        trace: usize,
        air: usize,
        log_blowup: u8,
        expected: usize,
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    use super::*;
    use crate::{
        air,
        air::{DirectKernel, ProverStatement},
        pcs::PcsParams,
        testing::{
            airs::miden::DummyMidenAir,
            configs::goldilocks_poseidon2::{Felt, QuadFelt, test_config},
        },
    };

    #[test]
    fn raw_storage_is_checked_before_matrix_height_division() {
        for (width, elements) in [(0, 0), (2, 3), (2, 0), (2, 2), (2, 6)] {
            // Deliberately malformed storage at the validation boundary, not an invalid kernel.
            let mut matrix = RowMajorMatrix::new(vec![Goldilocks::ZERO; 4], 2);
            matrix.width = width;
            matrix.values.resize(elements, Goldilocks::ZERO);
            assert!(
                matches!(raw_matrix_height(3, &matrix), Err(PreprocessedValidationError::RawMatrixShape { air: 3, width: actual_width, elements: actual_elements }) if actual_width == width && actual_elements == elements)
            );
        }
        let matrix = RowMajorMatrix::new(vec![Goldilocks::ZERO; 8], 2);
        assert_eq!(raw_matrix_height(3, &matrix).unwrap(), 4);
    }

    /// Reuse the existing degree-nine source; only its setup-owned fixed matrix is configured.
    struct FixedDummy {
        relation: DummyMidenAir<Felt>,
        declared: Option<PreprocessedSpec>,
        matrix: Option<RowMajorMatrix<Felt>>,
        materializations: Arc<AtomicUsize>,
    }

    impl LiftedAir for FixedDummy {
        type F = Felt;

        fn spec(&self) -> air::AirSpec<'_, Felt> {
            let mut spec = LiftedAir::spec(&self.relation);
            spec.preprocessed = self.declared;
            spec
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            self.materializations.fetch_add(1, Ordering::Relaxed);
            self.matrix.clone()
        }

        fn eval<S: air::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &air::Frame<'_, S>,
            inputs: air::Inputs<'_, S>,
            sink: &mut S,
        ) {
            LiftedAir::eval(&self.relation, frame, inputs, sink);
        }
    }

    struct SetupMultiAir {
        airs: Vec<DirectKernel<FixedDummy>>,
    }

    impl MultiAir<Felt, QuadFelt> for SetupMultiAir {
        type Air = DirectKernel<FixedDummy>;

        fn airs(&self) -> &[Self::Air] {
            &self.airs
        }
    }

    fn setup_statement(
        cases: Vec<(Option<PreprocessedSpec>, Option<RowMajorMatrix<Felt>>)>,
    ) -> (Statement<Felt, QuadFelt, SetupMultiAir>, Vec<Arc<AtomicUsize>>) {
        let counters: Vec<_> = cases.iter().map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let airs = cases
            .into_iter()
            .zip(&counters)
            .map(|((declared, matrix), counter)| {
                DirectKernel::new(FixedDummy {
                    relation: DummyMidenAir::new(9, 1),
                    declared,
                    matrix,
                    materializations: counter.clone(),
                })
                .unwrap()
            })
            .collect();
        let statement = Statement::new(SetupMultiAir { airs }, vec![], vec![]).unwrap();
        (statement, counters)
    }

    #[test]
    fn factories_run_once_including_none_and_fixed_leaves_keep_their_order() {
        let (statement, counters) = setup_statement(vec![
            (
                Some(PreprocessedSpec { width: 1, log_height: 3 }),
                Some(RowMajorMatrix::new(vec![Felt::ZERO; 8], 1)),
            ),
            (None, None),
            (
                Some(PreprocessedSpec { width: 2, log_height: 2 }),
                Some(RowMajorMatrix::new(vec![Felt::ONE; 8], 2)),
            ),
            (
                Some(PreprocessedSpec { width: 3, log_height: 2 }),
                Some(RowMajorMatrix::new(vec![Felt::TWO; 12], 3)),
            ),
        ]);
        assert!(counters.iter().all(|counter| counter.load(Ordering::Relaxed) == 0));
        let config = test_config();
        let setup = Preprocessed::build(&statement, &config).unwrap().unwrap();
        assert!(counters.iter().all(|counter| counter.load(Ordering::Relaxed) == 1));
        let plan =
            ExecutionPlan::new(statement.airs(), vec![3, 4, 2, 2], config.pcs().log_blowup())
                .unwrap();
        assert_eq!(plan.preprocessed_trace_to_air, vec![2, 3, 0]);
        assert_eq!(plan.air_to_preprocessed_trace, vec![Some(2), None, Some(0), Some(1)]);
        assert_eq!(setup.raw_traces().len(), 4);
        assert!(setup.raw_traces()[1].is_none());
        assert_eq!(setup.raw_traces()[2].as_ref().unwrap().values, vec![Felt::ONE; 8]);
        let leaves = setup.committed().tree().leaves();
        assert_eq!(leaves.iter().map(Matrix::width).collect::<Vec<_>>(), vec![2, 3, 1]);
        assert_eq!(setup.identity().commitment(), &setup.commitment());
        assert_eq!(setup.identity().alignment(), config.lmcs().alignment());
        assert_eq!(setup.identity().log_blowup(), config.pcs().log_blowup());

        // Both trusted-root association and metadata validation are factory-free.
        let identity =
            SetupIdentity::new::<QuadFelt, _, _>(setup.commitment(), statement.airs(), &config);
        validate_setup_identity::<QuadFelt, _, _>(&config, statement.airs(), &identity).unwrap();
        assert_eq!(&identity, setup.identity());
        assert!(counters.iter().all(|counter| counter.load(Ordering::Relaxed) == 1));

        let mut missing = identity.clone();
        missing.fingerprints.pop();
        assert!(matches!(
            validate_setup_identity::<QuadFelt, _, _>(&config, statement.airs(), &missing),
            Err(PreprocessedValidationError::FingerprintCountMismatch { expected: 4, actual: 3 })
        ));
        let mut reordered = identity.clone();
        reordered.fingerprints.swap(0, 2);
        assert!(matches!(
            validate_setup_identity::<QuadFelt, _, _>(&config, statement.airs(), &reordered),
            Err(PreprocessedValidationError::FingerprintMismatch { air: 0, .. })
        ));
        let mut different_blowup = identity.clone();
        different_blowup.log_blowup += 1;
        assert!(matches!(
            validate_setup_identity::<QuadFelt, _, _>(&config, statement.airs(), &different_blowup),
            Err(PreprocessedValidationError::BlowupMismatch { .. })
        ));
        let mut different_alignment = identity;
        different_alignment.alignment += 1;
        assert!(matches!(
            validate_setup_identity::<QuadFelt, _, _>(
                &config,
                statement.airs(),
                &different_alignment
            ),
            Err(PreprocessedValidationError::AlignmentMismatch { .. })
        ));
    }

    #[test]
    fn factory_shape_failures_are_typed_before_lde_and_still_visit_none_factories() {
        let config = test_config();
        let build = |declared, matrix| {
            let (statement, counters) = setup_statement(vec![(declared, matrix), (None, None)]);
            let result = Preprocessed::build(&statement, &config);
            assert!(counters.iter().all(|counter| counter.load(Ordering::Relaxed) == 1));
            result
        };
        let fixed = Some(PreprocessedSpec { width: 1, log_height: 2 });
        assert!(matches!(
            build(fixed, None),
            Err(PreprocessedValidationError::TracePresenceMismatch {
                air: 0,
                expected: true,
                actual: false
            })
        ));
        assert!(matches!(
            build(None, Some(RowMajorMatrix::new(vec![Felt::ZERO; 4], 1))),
            Err(PreprocessedValidationError::TracePresenceMismatch {
                air: 0,
                expected: false,
                actual: true
            })
        ));
        let mut malformed = RowMajorMatrix::new(vec![Felt::ZERO; 4], 1);
        malformed.width = 0;
        assert!(matches!(
            build(fixed, Some(malformed)),
            Err(PreprocessedValidationError::RawMatrixShape { air: 0, width: 0, .. })
        ));
        assert!(matches!(
            build(
                Some(PreprocessedSpec { width: 2, log_height: 2 }),
                Some(RowMajorMatrix::new(vec![Felt::ZERO; 4], 1))
            ),
            Err(PreprocessedValidationError::WidthMismatch { air: 0, expected: 2, actual: 1, .. })
        ));
        assert!(matches!(
            build(fixed, Some(RowMajorMatrix::new(vec![Felt::ZERO; 8], 1))),
            Err(PreprocessedValidationError::HeightMismatch { air: 0, main: 4, preprocessed: 8 })
        ));
        assert!(build(None, None).unwrap().is_none());

        let (statement, _) =
            setup_statement(vec![(fixed, Some(RowMajorMatrix::new(vec![Felt::ZERO; 4], 1)))]);
        let mut oversized = config;
        oversized.pcs = PcsParams::new(32, 1, 3, 0, 0, 1, 0).unwrap();
        assert!(matches!(
            Preprocessed::build(&statement, &oversized),
            Err(PreprocessedValidationError::Domain {
                air: 0,
                source: DomainError::LdeOrderTooLarge { .. }
            })
        ));
    }

    #[test]
    fn cached_raw_storage_is_validated_without_rebuilding_the_factory() {
        let (statement, counters) = setup_statement(vec![(
            Some(PreprocessedSpec { width: 1, log_height: 2 }),
            Some(RowMajorMatrix::new(vec![Felt::ZERO; 4], 1)),
        )]);
        let config = test_config();
        let mut setup = Preprocessed::build(&statement, &config).unwrap().unwrap();
        let prover =
            ProverStatement::new(statement, vec![RowMajorMatrix::new(vec![Felt::ZERO; 36], 9)])
                .unwrap();
        let plan =
            ExecutionPlan::new(prover.statement().airs(), vec![2], config.pcs().log_blowup())
                .unwrap();
        validate_preprocessed::<Felt, QuadFelt, _, _>(
            &config,
            prover.statement().airs(),
            &plan,
            &setup,
        )
        .unwrap();
        setup.traces[0].as_mut().unwrap().width = 0;
        assert!(matches!(
            validate_preprocessed::<Felt, QuadFelt, _, _>(
                &config,
                prover.statement().airs(),
                &plan,
                &setup,
            ),
            Err(PreprocessedValidationError::RawMatrixShape { air: 0, width: 0, .. })
        ));
        assert_eq!(counters[0].load(Ordering::Relaxed), 1);
    }
}
