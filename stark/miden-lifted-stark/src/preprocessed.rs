//! Preprocessed data: the fixed per-AIR matrices and their committed LDE tree.
//!
//! Preprocessed columns are *fixed circuit data* (lookup tables, selectors)
//! declared by the AIR via [`BaseAir::preprocessed_trace`] and committed once
//! at setup. The prover holds the cached raw matrices plus their LDE tree (the
//! [`Preprocessed`] bundle, built once and borrowed across proofs); the
//! verifier holds only the commitment (a root hash, trusted like the AIR list
//! itself).
//!
//! [`Preprocessed::build`] caches the by-value [`BaseAir::preprocessed_trace`]
//! evals and builds the aligned LDE tree using the supplied STARK config. The
//! resulting bundle is tied to that config's PCS blowup and LMCS alignment.
//! `validate_preprocessed` checks a bundle against a prover statement and
//! config; it runs at [`ProverInstance::new`](crate::ProverInstance::new)
//! construction time, so the prover never re-checks the shape.

use alloc::vec::Vec;

use miden_lifted_air::{BaseAir, LiftedAir, MultiAir, ProverStatement, Statement, log2_strict_u8};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;
use tracing::info_span;

use crate::{
    StarkConfig,
    domain::LiftedDomain,
    lmcs::{Lmcs, LmcsTree},
    order::TraceOrder,
    prover::commit::Committed,
    util::bitrev::materialize_bitrev,
};

// ============================================================================
// Preprocessed
// ============================================================================

/// Fixed per-AIR preprocessed data: the cached raw matrices plus their
/// committed LDE tree.
///
/// `traces[i]` is `Some` exactly when AIR `i` declares preprocessed columns;
/// the LDE tree commits one LDE trace per such AIR, in proof order. Built once
/// at setup via [`Preprocessed::build`] and borrowed across proofs.
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
    /// AIR declares none. The cached [`BaseAir::preprocessed_trace`] evals —
    /// `preprocessed_trace` re-allocates on every call, so they are computed
    /// once here and retained for validation and `check_constraints`.
    traces: Vec<Option<RowMajorMatrix<F>>>,
    /// Committed LDE tree, one committed LDE trace per preprocessed AIR.
    committed: Committed<F, RowMajorMatrix<F>, L>,
}

impl<F, L> Preprocessed<F, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Build the preprocessed bundle from a statement's AIRs, or `None` when no
    /// AIR declares preprocessed columns.
    ///
    /// Calls [`BaseAir::preprocessed_trace`] once per AIR (caching the by-value
    /// result), then LDEs the declared matrices — sorted height-ascending,
    /// tiebroken by AIR index, the committed trace order both sides reproduce —
    /// and builds the aligned tree.
    ///
    /// # Panics
    ///
    /// Panics if a declared preprocessed matrix has non-power-of-two height or
    /// its LDE order exceeds the field's two-adicity — programmer errors at
    /// setup, not untrusted input.
    pub fn build<EF, MA, C>(statement: &Statement<F, EF, MA>, config: &C) -> Option<Self>
    where
        EF: ExtensionField<F>,
        MA: MultiAir<F, EF>,
        C: StarkConfig<F, EF, Lmcs = L>,
    {
        let traces: Vec<Option<RowMajorMatrix<F>>> =
            statement.airs().iter().map(BaseAir::preprocessed_trace).collect();
        if traces.iter().all(Option::is_none) {
            return None;
        }

        // Committed trace order: preprocessed AIRs sorted by `(height, air_idx)`. This must
        // match the trace↔AIR mapping the prover/verifier reconstruct via
        // `TraceOrder::preprocessed_air_for_trace_index` (preprocessed AIRs in proof
        // order, i.e. sorted by `(main_trace_height, air_idx)`). The two
        // coincide because `validate_preprocessed` rejects any bundle whose
        // preprocessed height differs from the main trace height — so sorting by
        // the preprocessed matrix height here yields the same order. `build`
        // sees only the AIR list (fixed circuit data), not the witness traces,
        // so it cannot call `TraceOrder` directly.
        let mut pairs: Vec<(usize, &RowMajorMatrix<F>)> = traces
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.as_ref().map(|m| (i, m)))
            .collect();
        pairs.sort_by_key(|(air_idx, m)| (m.height(), *air_idx));

        let log_blowup = config.pcs().log_blowup();
        let ldes: Vec<_> = pairs
            .into_iter()
            .map(|(air_idx, trace)| {
                let height = trace.height();
                assert!(
                    height.is_power_of_two(),
                    "preprocessed matrix for AIR {air_idx} has non-power-of-two height {height}",
                );
                let log_h = log2_strict_u8(height);
                let coset_shift = LiftedDomain::<F>::canonical_lde_shift(log_h + log_blowup)
                    .expect("preprocessed LDE order exceeds field two-adicity");
                let width = trace.width();
                info_span!("preprocessed LDE", air = air_idx, log_height = log_h, width).in_scope(
                    || {
                        let lde = config.dft().coset_lde_batch(
                            trace.clone(),
                            log_blowup.into(),
                            coset_shift,
                        );
                        materialize_bitrev(lde)
                    },
                )
            })
            .collect();

        Some(Self {
            traces,
            committed: Committed::new(config.lmcs().build_aligned_tree(ldes)),
        })
    }

    /// Commitment (Merkle root) of the preprocessed LDE tree — handed to the
    /// verifier via [`VerifierInstance::new`](crate::VerifierInstance::new).
    pub fn commitment(&self) -> L::Commitment {
        self.committed.root()
    }

    /// The committed LDE tree, for opening and per-AIR quotient-domain views.
    pub(crate) fn committed(&self) -> &Committed<F, RowMajorMatrix<F>, L> {
        &self.committed
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate a [`Preprocessed`] bundle against a prover statement and STARK config:
/// per-AIR presence, raw matrix shape, committed LDE shape, and LMCS alignment.
///
/// Called by [`ProverInstance::new`](crate::ProverInstance::new) only when both
/// the AIRs declare preprocessed columns and a bundle is supplied; aggregate
/// presence parity is checked separately by the constructor.
pub(crate) fn validate_preprocessed<F, EF, MA, SC>(
    config: &SC,
    prover_statement: &ProverStatement<F, EF, MA>,
    preprocessed: &Preprocessed<F, SC::Lmcs>,
) -> Result<(), PreprocessedValidationError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    let airs = prover_statement.statement().airs();
    let main_traces = prover_statement.traces();
    let log_blowup = config.pcs().log_blowup();

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

    // Reconstruct the trace↔AIR mapping the prover/verifier use.
    // Heights are already validated by `ProverStatement::new`, so this cannot fail.
    let heights: Vec<usize> = main_traces.iter().map(Matrix::height).collect();
    let trace_order = TraceOrder::from_trace_heights::<F, EF, _>(airs, &heights)
        .expect("ProverStatement guarantees valid trace shapes");
    let preprocessed_trace_to_air = trace_order.preprocessed_air_for_trace_index::<F, EF, _>(airs);
    let air_to_preprocessed_trace = trace_order.preprocessed_trace_index_for_air::<F, EF, _>(airs);

    // Raw cached matrices must line up with AIR declarations in instance order.
    for (air_idx, (air, raw_preprocessed)) in airs.iter().zip(&preprocessed.traces).enumerate() {
        let expected_presence = air.preprocessed_width() > 0;
        let actual_presence = raw_preprocessed.is_some();
        if actual_presence != expected_presence {
            return Err(PreprocessedValidationError::TracePresenceMismatch {
                air: air_idx,
                expected: expected_presence,
                actual: actual_presence,
            });
        }

        let Some(raw_preprocessed) = raw_preprocessed else {
            continue;
        };

        let trace = air_to_preprocessed_trace[air_idx]
            .expect("presence validation guarantees a declared preprocessed AIR");
        let expected_width = air.preprocessed_width();
        let actual_width = raw_preprocessed.width();
        if actual_width != expected_width {
            return Err(PreprocessedValidationError::WidthMismatch {
                trace,
                air: air_idx,
                expected: expected_width,
                actual: actual_width,
            });
        }

        let main = main_traces[air_idx].height();
        if raw_preprocessed.height() != main {
            return Err(PreprocessedValidationError::HeightMismatch {
                air: air_idx,
                main,
                preprocessed: raw_preprocessed.height(),
            });
        }
    }

    let committed_traces = preprocessed.committed.tree().leaves();
    if committed_traces.len() != preprocessed_trace_to_air.len() {
        return Err(PreprocessedValidationError::TreeLengthMismatch {
            expected: preprocessed_trace_to_air.len(),
            actual: committed_traces.len(),
        });
    }

    // Validate the committed leaves directly against the AIRs and config, not by
    // trusting them to be the LDE of `traces`. A `Preprocessed` need not have come
    // from `build` (e.g. a deserialized bundle), so its raw and committed halves are
    // checked independently: width against the declared AIR, and LDE height against
    // this proving config's blowup applied to the main trace height (catching a
    // bundle built under a different blowup).
    for (preprocessed_trace_idx, &air_idx_u8) in preprocessed_trace_to_air.iter().enumerate() {
        let air_idx = air_idx_u8 as usize;
        let expected_width = airs[air_idx].preprocessed_width();
        let committed_trace = &committed_traces[preprocessed_trace_idx];
        let actual_width = committed_trace.width();
        if actual_width != expected_width {
            return Err(PreprocessedValidationError::WidthMismatch {
                trace: preprocessed_trace_idx,
                air: air_idx,
                expected: expected_width,
                actual: actual_width,
            });
        }

        let main_height = main_traces[air_idx].height();
        let expected_lde_height = main_height.checked_shl(u32::from(log_blowup)).ok_or(
            PreprocessedValidationError::LdeHeightOverflow {
                air: air_idx,
                main: main_height,
                log_blowup,
            },
        )?;
        let actual_lde_height = committed_trace.height();
        if actual_lde_height != expected_lde_height {
            return Err(PreprocessedValidationError::LdeHeightMismatch {
                trace: preprocessed_trace_idx,
                air: air_idx,
                log_blowup,
                expected: expected_lde_height,
                actual: actual_lde_height,
            });
        }
    }

    Ok(())
}

/// Errors from constructing a stark-layer instance: preprocessed presence
/// parity and (prover side) the bundle's shape against the AIR declarations.
#[derive(Debug, Error)]
pub enum PreprocessedValidationError {
    #[error(
        "preprocessed setup presence mismatch: AIRs declare preprocessed columns = {expected}, setup supplied = {actual}"
    )]
    PresenceMismatch { expected: bool, actual: bool },
    #[error("raw preprocessed trace count {actual} does not match AIR count {expected}")]
    RawTraceCountMismatch { expected: usize, actual: usize },
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
        "AIR {air}: preprocessed matrix height ({preprocessed}) does not match main trace height ({main})"
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
