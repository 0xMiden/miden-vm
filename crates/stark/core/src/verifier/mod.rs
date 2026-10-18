//! Lifted STARK verifier.
//!
//! This module provides:
//! - [`VerifierInstance::verify`](crate::VerifierInstance::verify): Verify a [`Statement`].
//!
//! Takes a challenger (consumed by value) and proof data, constructs the
//! verifier transcript internally, and returns a [`StarkDigest`] on success.
//! The caller must check that the digest matches the prover's digest.
//!
//! # Fiat-Shamir / transcript binding
//!
//! The caller must produce the same challenger state as the prover — see the
//! prover module-level docs for the full binding contract and recommended
//! pattern.
//!
//! The proof's per-AIR log trace heights are carried on [`StarkProofData`] (in
//! instance order); [`VerifierInstance::verify`](crate::VerifierInstance::verify)
//! observes the derived instance count and those heights at the protocol layer.
//! Callers must not pre-observe them.
//!
//! # Statement-bound trace heights
//!
//! The verifier accepts whatever trace heights the proof carries; it never
//! compares them against a caller-supplied expectation. If your statement
//! fixes the trace size (e.g. a proof for a 2^16-row execution), parse it
//! with [`StarkProof::from_data`](crate::proof::StarkProof::from_data) using the same
//! [`VerifierInstance`], and check `proof.log_trace_heights()` yourself.
//!
//! # Transcript boundaries (strict consumption)
//!
//! [`VerifierInstance::verify`](crate::VerifierInstance::verify) finalizes the
//! transcript internally: it rejects proofs with trailing data (via
//! [`TranscriptError::TrailingData`]) and returns a binding digest that must
//! match the prover's digest.
//!
//! If you want to bundle extra data alongside the proof, you must manage
//! boundaries yourself (e.g. parse and validate that data first, then pass the
//! remaining transcript to
//! [`VerifierInstance::verify`](crate::VerifierInstance::verify)).

extern crate alloc;

pub(crate) mod constraints;
pub(crate) mod periodic;

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use constraints::ConstraintFolder;
use miden_lifted_air::{
    BaseAir, InstanceError, LiftedAir, MultiAir, ReductionError, RowWindow, Statement,
};
use miden_stark_transcript::{Channel, TranscriptError, VerifierChannel, VerifierTranscript};
use p3_challenger::CanObserve;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use periodic::PeriodicPolys;
use thiserror::Error;

use crate::{
    StarkConfig,
    domain::{Coset, DomainError, LiftedDomain, log_quotient_degree},
    lmcs::Lmcs,
    order::{ShapeError, TraceOrder},
    pcs::verifier::{CommitmentGroup, PcsError, verify_aligned},
    preprocessed::PreprocessedValidationError,
    proof::{StarkDigest, StarkProofData},
    util::packing::row_to_packed_ext,
};

// ============================================================================
// VerifierInstance
// ============================================================================

/// Verifier-side bundle: a [`StarkConfig`], a borrowed [`Statement`], and the
/// optional preprocessed commitment (a trusted setup input, not read from the
/// proof).
///
/// Construction validates preprocessed presence parity, so holding a
/// `VerifierInstance` guarantees the commitment is present exactly when the
/// AIRs declare preprocessed columns.
pub struct VerifierInstance<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    config: &'a SC,
    statement: &'a Statement<F, EF, MA>,
    preprocessed_commitment: Option<<SC::Lmcs as Lmcs>::Commitment>,
}

impl<'a, F, EF, MA, SC> VerifierInstance<'a, F, EF, MA, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    SC: StarkConfig<F, EF>,
{
    /// Bundle a config + statement with an optional preprocessed commitment.
    ///
    /// The commitment must be `Some` exactly when some AIR declares preprocessed
    /// columns; otherwise this errors with
    /// [`PreprocessedValidationError::PresenceMismatch`].
    pub fn new(
        config: &'a SC,
        statement: &'a Statement<F, EF, MA>,
        preprocessed_commitment: Option<<SC::Lmcs as Lmcs>::Commitment>,
    ) -> Result<Self, PreprocessedValidationError> {
        let expected = statement.airs().iter().any(|a| a.preprocessed_width() > 0);
        let actual = preprocessed_commitment.is_some();
        if expected != actual {
            return Err(PreprocessedValidationError::PresenceMismatch { expected, actual });
        }
        Ok(Self {
            config,
            statement,
            preprocessed_commitment,
        })
    }

    /// Verify a proof against this instance.
    pub fn verify(
        &self,
        proof: &StarkProofData<F, EF, SC>,
        challenger: SC::Challenger,
    ) -> Result<StarkDigest<F, EF, SC>, VerifierError> {
        verify(self, proof, challenger)
    }

    /// Borrow the STARK configuration.
    pub fn config(&self) -> &SC {
        self.config
    }

    /// Borrow the wrapped air-crate statement.
    pub fn statement(&self) -> &Statement<F, EF, MA> {
        self.statement
    }

    /// Borrow the preprocessed commitment, if any.
    pub fn preprocessed_commitment(&self) -> Option<&<SC::Lmcs as Lmcs>::Commitment> {
        self.preprocessed_commitment.as_ref()
    }
}

/// Errors that can occur during verification.
///
/// Returned exclusively for runtime instance / proof-shape failures or
/// cryptographic verification failures. AIR structural correctness is
/// trusted — call [`crate::debug::assert_prover_setup`] (or
/// [`miden_lifted_air::debug::assert_multi_air_valid`]) from tests.
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Shape(#[from] ShapeError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Pcs(#[from] PcsError),
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    #[error("external assertion evaluation failed: {0}")]
    Reduction(ReductionError),
    #[error("constraint mismatch: quotient * vanishing != folded constraints")]
    ConstraintMismatch,
    #[error("external assertion {assertion} is non-zero")]
    ExternalAssertionFailed {
        /// Index into the assertions vector returned by
        /// [`Statement::eval_external`].
        assertion: usize,
    },
}

/// Verify a [`Statement`].
///
/// The verifier reads per-AIR log trace heights from the proof (in caller
/// order, matching [`Statement::airs`]) and reconstructs the proof's AIR
/// ordering deterministically from those heights. The caller's challenger
/// must already be bound to protocol parameters and AIR configurations —
/// see the prover module-level docs. The statement's inputs are absorbed via
/// [`Statement::observe`], then the instance count and proof's log trace heights
/// are observed in instance order.
///
/// The verifier mirrors the prover's protocol:
///
/// 1. Validate runtime statement/proof shape data, absorb statement-owned inputs, and observe the
///    instance count plus log trace heights in instance order
/// 2. Receive commitments and sample challenges in the same order as the prover
/// 3. For each AIR (in proof order), evaluate constraints at the lifted OOD point yⱼ = z^{rⱼ}
/// 4. Accumulate folded constraints with β: acc = acc·β + foldedⱼ
/// 5. Check quotient identity: `acc == Q(z) * Z_{H_max}(z)`
/// 6. Evaluate [`Statement::eval_external`] with aux values reordered back to instance order
///
/// Lifting: for a trace of height nⱼ lifted by factor rⱼ, the committed
/// codeword encodes `p_lift(X) = p(X^{rⱼ})`; opening at `[z, z · h_max]`
/// yields the local/next row pair for the original trace domain.
///
/// **Statement-bound heights:** this function does not compare the proof's
/// declared heights against any caller expectation. If your statement fixes
/// trace dimensions, parse via
/// [`StarkProof::from_data`](crate::proof::StarkProof::from_data) using this instance and check
/// `proof.log_trace_heights()` before calling this. See the module-level docs for the full
/// contract.
///
/// # Trust contract
///
/// `verify` validates the runtime statement plus everything carried on the
/// proof; the AIR list is **trusted** (run
/// [`miden_lifted_air::debug::assert_multi_air_valid`] from tests).
///
/// ## Validated
/// - Same statement checks as [`prove`](crate::ProverInstance::prove) minus trace shape (no traces
///   here)
/// - Same `log_quotient_degree <= log_blowup` compat check
/// - Proof shape via the internal trace-order reconstruction from log heights
/// - Proof byte parsing (transcript channel)
/// - PCS / FRI / DEEP / LMCS / transcript / constraint identity
/// - External assertions from [`Statement::eval_external`]
/// - Preprocessed openings against the trusted commitment (via the PCS)
///
/// ## Trusted (NOT validated)
/// - AIR structural shape (same list as in [`prove`](crate::ProverInstance::prove))
pub(crate) fn verify<F, EF, MA, SC>(
    instance: &VerifierInstance<'_, F, EF, MA, SC>,
    proof: &StarkProofData<F, EF, SC>,
    mut challenger: SC::Challenger,
) -> Result<StarkDigest<F, EF, SC>, VerifierError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    MA: MultiAir<F, EF>,
{
    // --- Trust boundary (see doc-block above). -------------------------------
    let config = instance.config();
    let statement: &Statement<F, EF, MA> = instance.statement();
    let preprocessed_commitment = instance.preprocessed_commitment();
    //
    // `TraceOrder::from_log_heights` validates the (untrusted) proof heights
    // against the AIRs: it bounds `log_h` within the host's `usize` width
    // (later code dereferences `1usize << log_h` and would otherwise overflow on
    // a malicious proof) and checks per-AIR periodic-height feasibility.
    // Statement::new already enforced the input-side contracts before construction.
    let trace_order = TraceOrder::from_log_heights::<F, EF, _>(
        statement.airs(),
        proof.log_trace_heights.clone(),
    )?;

    // Preprocessed trace↔AIR mappings (instance order), reconstructed from the
    // heights — the same ones the prover used.
    let preprocessed_trace_to_air =
        trace_order.preprocessed_air_for_trace_index::<F, EF, _>(statement.airs());
    let air_to_preprocessed_trace =
        trace_order.preprocessed_trace_index_for_air::<F, EF, _>(statement.airs());

    let air_refs: Vec<&MA::Air> = statement.airs().iter().collect();
    let proof_ordered_airs = trace_order.to_proof_order(&air_refs);
    let air_inputs = statement.air_inputs();

    let log_blowup = config.pcs().log_blowup();
    let log_max_trace_height = trace_order.max_log_height();
    let max_lde_domain = LiftedDomain::<F>::try_canonical(log_max_trace_height, log_blowup)?;
    let instance_domains: Vec<_> = trace_order
        .log_heights_proof()
        .iter()
        .map(|&log_h| max_lde_domain.try_sub_domain(log_h))
        .collect::<Result<_, _>>()?;

    // Observe the preprocessed commitment first (when present); mirrors the
    // prover. It is a trusted statement input, not read from the proof.
    if let Some(commitment) = preprocessed_commitment {
        challenger.observe(commitment.clone());
    }

    // `Statement::observe` absorbs statement-owned inputs. The protocol then
    // binds the instance count and each log trace height in instance order.
    statement.observe(&mut challenger, trace_order.log_heights());
    trace_order.observe_shape::<F, _>(&mut challenger);

    let mut channel = VerifierTranscript::from_data(challenger, &proof.transcript);

    // Infer constraint degree from symbolic AIR analysis (max across all AIRs).
    // NOTE: `log_quotient_degree` runs symbolic eval and may panic if the AIR is
    // invalid. The AIR is trusted (see `miden_lifted_air::debug::assert_multi_air_valid`
    // for the debug-only structural check).
    let max_log_quotient_degree = proof_ordered_airs
        .iter()
        .map(|&air| log_quotient_degree::<F, EF, _>(air))
        .max()
        .expect("TraceOrder construction rejects empty AIR sets");
    if max_log_quotient_degree > log_blowup {
        return Err(DomainError::ConstraintDegreeTooHigh {
            log_quotient: max_log_quotient_degree,
            log_blowup,
        }
        .into());
    }

    // Pair the max LDE domain with the constraint degree for the constraint layer.
    let max_eval_domain = max_lde_domain.evaluation_domain(max_log_quotient_degree);

    let quotient_degree = 1 << max_log_quotient_degree as usize;

    let max_trace_height = max_lde_domain.trace_height();

    // 1. Receive main trace commitment
    let main_commit = channel.receive_commitment()?.clone();

    // 2. Sample randomness for aux traces
    let max_num_randomness =
        proof_ordered_airs.iter().map(|air| air.num_randomness()).max().unwrap_or(0);

    let randomness: Vec<EF> = (0..max_num_randomness)
        .map(|_| channel.sample_algebra_element::<EF>())
        .collect();

    // 3. Receive aux trace commitment
    let aux_commit = channel.receive_commitment()?.clone();

    // Receive aux values from the transcript (one EF element per aux value, per instance).
    // When no AIR has aux columns, each entry is empty so nothing is received.
    let all_aux_values: Vec<Vec<EF>> = proof_ordered_airs
        .iter()
        .map(|air| {
            let count = air.num_aux_values();
            (0..count)
                .map(|_| channel.receive_algebra_element::<EF>())
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 4. Sample constraint folding alpha and accumulation beta
    let alpha: EF = channel.sample_algebra_element::<EF>();
    let beta: EF = channel.sample_algebra_element::<EF>();

    // 5. Receive quotient commitment
    let quotient_commit = channel.receive_commitment()?.clone();

    // 6. Sample OOD point (outside max trace domain H and max LDE coset gK)
    let z: EF = max_lde_domain.sample_ood_point(&mut channel);
    let h = max_lde_domain.trace_subgroup().generator();
    let z_next = z * h;

    // 7. Widths per commitment group (unpadded data widths).
    let main_widths: Vec<usize> = proof_ordered_airs.iter().map(|air| air.width()).collect();
    let aux_widths: Vec<usize> =
        proof_ordered_airs.iter().map(|air| air.aux_width() * EF::DIMENSION).collect();
    let quotient_widths: Vec<usize> = vec![quotient_degree * EF::DIMENSION];

    // Build commitments with original (unpadded) widths.
    // The PCS aligned wrapper handles alignment and truncation internally.
    // The preprocessed group (when present) is first, mirroring the prover; its
    // widths are in committed preprocessed trace order, while main/aux are in proof order.
    //
    // Group indices, in batch order `[preprocessed?, main, aux, quotient]`: the
    // preprocessed group occupies index 0 only when present, shifting the rest
    // up by one. The prover builds its `trees` vector in this same order.
    let s = preprocessed_commitment.is_some() as usize;
    let (preproc_g, main_g, aux_g, quot_g) =
        (preprocessed_commitment.is_some().then_some(0), s, s + 1, s + 2);
    let full_log_height = log_max_trace_height + log_blowup;
    let mut commitments = Vec::with_capacity(4);
    if let Some(commitment) = preprocessed_commitment {
        let preprocessed_widths: Vec<usize> = preprocessed_trace_to_air
            .iter()
            .map(|&air_idx| statement.airs()[air_idx as usize].preprocessed_width())
            .collect();
        // The preprocessed tree is committed at its own setup-fixed depth, determined by the
        // tallest preprocessed trace. The PCS virtually lifts it to the max when shorter.
        let preprocessed_log_height = preprocessed_trace_to_air
            .iter()
            .map(|&air_idx| trace_order.log_heights()[air_idx as usize])
            .max()
            .expect("preprocessed group is non-empty when a commitment is present")
            + log_blowup;
        commitments.push(CommitmentGroup {
            root: commitment.clone(),
            widths: preprocessed_widths,
            log_height: preprocessed_log_height,
        });
    }
    commitments.push(CommitmentGroup {
        root: main_commit,
        widths: main_widths,
        log_height: full_log_height,
    });
    commitments.push(CommitmentGroup {
        root: aux_commit,
        widths: aux_widths,
        log_height: full_log_height,
    });
    commitments.push(CommitmentGroup {
        root: quotient_commit,
        widths: quotient_widths,
        log_height: full_log_height,
    });

    // 8. Verify PCS openings (returns per-matrix RowMajorMatrix<EF>, truncated to original widths)
    let opened = verify_aligned::<F, EF, SC::Lmcs, _, 2>(
        config.pcs(),
        config.lmcs(),
        &commitments,
        &max_lde_domain,
        [z, z_next],
        &mut channel,
    )?;

    // 9. Per-AIR constraint evaluation and beta accumulation.
    //
    // opened[g] has one matrix per AIR (for main/aux) or one matrix total (quotient).
    // Each matrix has N=2 rows: row 0 = local (z), row 1 = next (z·h).
    //
    // AIRs are in the proof's ordering (ascending height), so j indexes both
    // AIR and trace position directly.
    debug_assert_eq!(opened[main_g].len(), proof_ordered_airs.len());
    debug_assert_eq!(opened[aux_g].len(), proof_ordered_airs.len());
    let mut accumulated = EF::ZERO;

    for (j, air) in proof_ordered_airs.iter().enumerate() {
        let domain_j = instance_domains[j];

        // opened[main_g][j] is a 2-row RowMajorMatrix (local, next) already truncated.
        let main_window = RowWindow::from_view(&opened[main_g][j].as_view());

        // Extract aux trace opened values (reconstitute EF from base field components).
        // Row widths were validated against `air.aux_width() * EF::DIMENSION`
        // by `verify_aligned` upstream; reaching here with a mismatch would
        // indicate a framework bug.
        let aux_mat = &opened[aux_g][j];
        let aux_local = row_to_packed_ext::<F, EF>(&aux_mat.row_slice(0).expect("aux row 0"))
            .expect("aux row width should match: PCS verify_aligned validates this upstream");
        let aux_next = row_to_packed_ext::<F, EF>(&aux_mat.row_slice(1).expect("aux row 1"))
            .expect("aux row width should match: PCS verify_aligned validates this upstream");
        let aux_window = RowWindow::from_two_rows(&aux_local, &aux_next);

        // Selectors at the lifted OOD point yⱼ = z^{rⱼ} (encapsulated in LiftedDomain).
        let selectors = domain_j.selectors_at(z);

        // Periodic values: for a column with period p, eval_at computes z^{n/p}.
        // Using (max_trace_height, z) gives z^{max_n / p}, which equals
        // y_j^{n_j / p} = (z^{max_n/n_j})^{n_j/p} = z^{max_n/p}. This avoids
        // computing y_j = z^{r_j} explicitly.
        let periodic_polys = PeriodicPolys::new(&air.periodic_columns());
        let periodic_values = periodic_polys.eval_at::<EF>(max_trace_height, z);

        let aux_values_j = &all_aux_values[j];
        let num_rand = air.num_randomness();

        // Extract the opened preprocessed window when this AIR declares
        // preprocessed columns. The preprocessed trace index comes from the inverse
        // `air_to_preprocessed_trace` mapping; the opened matrix is a 2-row
        // `RowMajorMatrix` already truncated to the declared width by `verify_aligned`, so this
        // is a zero-copy view (mirrors the main window above).
        let instance_idx = trace_order.instance_indices()[j] as usize;
        let preprocessed_window = match air_to_preprocessed_trace[instance_idx] {
            Some(preprocessed_trace_idx) => RowWindow::from_view(
                &opened[preproc_g.expect("preproc group present")][preprocessed_trace_idx]
                    .as_view(),
            ),
            None => RowWindow::from_two_rows(&[], &[]),
        };

        let mut folder = ConstraintFolder {
            main: main_window,
            preprocessed: preprocessed_window,
            aux: aux_window,
            randomness: &randomness[..num_rand],
            public_values: air_inputs,
            periodic_values: &periodic_values,
            permutation_values: aux_values_j,
            selectors,
            alpha,
            accumulator: EF::ZERO,
            _phantom: PhantomData,
        };

        #[cfg(debug_assertions)]
        miden_lifted_air::debug::check_builder_shape(*air, &folder);
        air.eval(&mut folder);

        // Accumulate: acc = acc * beta + folded_j
        accumulated = accumulated * beta + folder.accumulator;
    }

    // 11. Evaluate the proof's external assertions. Aux values came off the
    // wire in proof order; reorder them back to instance order before handing
    // them to `eval_external`, which is defined in instance-order terms.
    let aux_instance = trace_order.to_instance_order(&all_aux_values);
    let aux_views: Vec<&[EF]> = aux_instance.iter().map(Vec::as_slice).collect();
    let assertions = statement
        .eval_external(&randomness, &aux_views, trace_order.log_heights())
        .map_err(VerifierError::Reduction)?;
    for (k, assertion) in assertions.iter().enumerate() {
        if *assertion != EF::ZERO {
            return Err(VerifierError::ExternalAssertionFailed { assertion: k });
        }
    }

    // 12. Reconstruct Q(z) and check quotient identity Q(z) * Z_{H_max}(z)
    // Quotient group has a single matrix; row 0 is the evaluation at z.
    let quot_row = opened[quot_g][0].row_slice(0).expect("quotient row 0");
    let quotient_chunks = row_to_packed_ext::<F, EF>(&quot_row)
        .expect("quotient row width should match: PCS verify_aligned validates this upstream");
    let quotient_z = max_eval_domain.reconstruct_quotient::<EF>(z, &quotient_chunks);

    // `max_lde_domain` is the tallest (lift_ratio = 0), so lifted == unlifted here.
    let vanishing = max_lde_domain.trace_subgroup().vanishing_at(z);
    if accumulated != quotient_z * vanishing {
        return Err(VerifierError::ConstraintMismatch);
    }

    // 13. Finalize transcript: check emptiness and return digest
    Ok(channel.finalize()?)
}
