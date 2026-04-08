//! Lifted STARK verifier.
//!
//! This module provides:
//! - [`verify_single`]: Verify a single AIR instance.
//! - [`verify_multi`]: Verify multiple AIR instances with traces of different heights.
//!
//! These functions take a challenger (consumed by value) and proof data, construct
//! the verifier transcript internally, and return a [`StarkDigest`] on success.
//! The caller must check that the digest matches the prover's digest.
//!
//! # Fiat-Shamir / transcript binding (initial challenger state)
//!
//! This crate intentionally does **not** prescribe the *initial* transcript state.
//! In particular, the verifier APIs here take the statement out-of-band (AIR(s),
//! instance metadata like trace heights, and `public_values`).
//!
//! The protocol implementation assumes that all inputs that may vary (including
//! `public_values`) have already been observed by the challenger passed in.
//! This is required so callers can avoid including large public inputs in the proof
//! when they are available out-of-band.
//!
//! If your application treats any of these inputs as untrusted, you must
//! authenticate them by binding them into the Fiat-Shamir challenger state
//! (domain separation + an AIR/version tag + public inputs), in the same way on
//! both prover and verifier.
//!
//! The module-level docs in the prover module show the recommended ergonomic
//! pattern: pre-seed the challenger before passing it to `prove_multi`/`verify_multi`.
//!
//! # Transcript boundaries (strict consumption)
//!
//! [`verify_multi`] finalizes the transcript internally: it rejects proofs with
//! trailing data (via [`TranscriptError::TrailingData`]) and returns a binding
//! digest that must match the prover's digest. This makes it harder to
//! accidentally accept a proof embedded inside a larger transcript with
//! confusing boundaries.
//!
//! If you want to bundle extra data alongside the proof, you must manage
//! boundaries yourself (e.g. parse and validate that data first, then pass the
//! remaining transcript to [`verify_multi`]).
//!
//! # Multi-trace ordering
//!
//! For [`verify_multi`], `instances` must be provided in ascending trace height order
//! (smallest first). This is a protocol-level requirement.

extern crate alloc;

pub mod constraints;
pub mod periodic;

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use constraints::{ConstraintFolder, reconstruct_quotient, row_to_packed_ext};
use miden_lifted_air::{
    AirInstance, AirValidationError, LiftedAir, ReducedAuxValues, ReductionError, RowWindow,
    VarLenPublicInputs, validate_instances,
};
use miden_stark_transcript::{Channel, TranscriptError, VerifierChannel, VerifierTranscript};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::Matrix;
use periodic::PeriodicPolys;
use thiserror::Error;

use crate::{
    StarkConfig,
    coset::LiftedCoset,
    pcs::verifier::{PcsError, verify_aligned},
    proof::{StarkDigest, StarkProof},
};

/// Errors that can occur during verification.
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("AIR validation failed: {0}")]
    Air(#[from] AirValidationError),
    #[error("PCS verification failed: {0}")]
    Pcs(#[from] PcsError),
    #[error("transcript error: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("invalid aux shape")]
    InvalidAuxShape,
    #[error("constraint mismatch: quotient * vanishing != folded constraints")]
    ConstraintMismatch,
    #[error(
        "constraint degree exceeds blowup: \
         log_quotient_degree {log_quotient_degree} > log_blowup {log_blowup}"
    )]
    ConstraintDegreeTooHigh { log_quotient_degree: u8, log_blowup: u8 },
    #[error("global reduced aux identity check failed")]
    InvalidReducedAux,
    #[error("aux value reduction failed: {0}")]
    Reduction(ReductionError),
}

/// Verify a single AIR.
///
/// Transcript warning: the protocol assumes the challenger inside `channel` has
/// already observed all variable statement inputs (in particular `public_values`).
/// This lets callers keep public inputs out of the proof when they are available
/// out-of-band. See the module-level docs for guidance.
/// This is a convenience wrapper around [`verify_multi`] for the single-AIR case.
///
/// # Arguments
/// - `config`: STARK configuration (PCS params, LMCS, DFT)
/// - `air`: The AIR definition
/// - `log_trace_height`: Log₂ of the trace height
/// - `public_values`: Public values for this AIR
/// - `var_len_public_inputs`: Variable-length public inputs for bus identity checks
/// - `channel`: Verifier channel for transcript
///
/// # Returns
/// `Ok(())` on success, or a `VerifierError` if verification fails.
pub fn verify_single<F, EF, A, SC>(
    config: &SC,
    air: &A,
    log_trace_height: u8,
    public_values: &[F],
    var_len_public_inputs: VarLenPublicInputs<'_, F>,
    proof: &StarkProof<F, EF, SC>,
    challenger: SC::Challenger,
) -> Result<StarkDigest<F, EF, SC>, VerifierError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    A: LiftedAir<F, EF>,
{
    let instance = AirInstance {
        log_trace_height,
        public_values,
        var_len_public_inputs,
    };
    verify_multi(config, &[(air, instance)], proof, challenger)
}

/// Verify multiple AIRs with traces of different heights.
///
/// Transcript warning: the protocol assumes the challenger inside `channel` has
/// already observed all variable statement inputs (in particular each instance's
/// `public_values`). This lets callers keep public inputs out of the proof when they
/// are available out-of-band.
///
/// Instances must be provided in ascending height order (smallest first). Each trace
/// may have a different height that is a power of 2. The verifier mirrors the prover's
/// protocol:
///
/// 1. Receive commitments and sample challenges in the same order as the prover
/// 2. For each AIR, evaluate constraints at the lifted OOD point yⱼ = z^{rⱼ}
/// 3. Accumulate folded constraints with β: acc = acc·β + foldedⱼ
/// 4. Check quotient identity: `acc == Q(z) * Z_{H_max}(z)`
///
/// Lifting ensures correctness: for a trace of height nⱼ lifted by factor rⱼ,
/// the committed codeword corresponds to the lifted polynomial `p_lift(X) = p(X^{rⱼ})`.
/// Opening at `[z, z * h_max]` therefore yields
/// `[p(z^{r_j}), p(h_{n_j} * z^{r_j})]`, i.e. the local/next row pair for the original
/// (unlifted) trace domain.
///
/// # Arguments
/// - `config`: STARK configuration (PCS params, LMCS, DFT)
/// - `instances`: Pairs of (AIR, instance) sorted by trace height (ascending)
/// - `channel`: Verifier channel for transcript/proof I/O
///
/// # Returns
/// `Ok(())` on success, or a `VerifierError` if verification fails.
pub fn verify_multi<F, EF, A, SC>(
    config: &SC,
    instances: &[(&A, AirInstance<'_, F>)],
    proof: &StarkProof<F, EF, SC>,
    challenger: SC::Challenger,
) -> Result<StarkDigest<F, EF, SC>, VerifierError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    A: LiftedAir<F, EF>,
{
    let mut channel = VerifierTranscript::from_data(challenger, proof);
    // Validate AIR properties, instance dimensions, and ascending height.
    let log_max_trace_height = validate_instances(instances)?;

    let log_blowup = config.pcs().log_blowup();

    // Infer constraint degree from symbolic AIR analysis (max across all AIRs).
    // NOTE: `log_quotient_degree()` runs symbolic eval and may panic if the AIR is
    // invalid. Callers must ensure `validate_instances` (above) passes first.
    let log_constraint_degree =
        instances.iter().map(|(air, _)| air.log_quotient_degree()).max().unwrap_or(1) as u8;

    if log_constraint_degree > log_blowup {
        return Err(VerifierError::ConstraintDegreeTooHigh {
            log_quotient_degree: log_constraint_degree,
            log_blowup,
        });
    }

    let constraint_degree = 1 << log_constraint_degree as usize;

    let max_trace_height = 1 << log_max_trace_height as usize;
    let log_lde_height = log_max_trace_height + log_blowup;

    // Max LDE coset (for the largest trace, no lifting)
    let max_lde_coset = LiftedCoset::unlifted(log_max_trace_height, log_blowup);

    // 1. Receive main trace commitment
    let main_commit = channel.receive_commitment()?.clone();

    // 2. Sample randomness for aux traces
    let max_num_randomness =
        instances.iter().map(|(air, _)| air.num_randomness()).max().unwrap_or(0);

    let randomness: Vec<EF> = (0..max_num_randomness)
        .map(|_| channel.sample_algebra_element::<EF>())
        .collect();

    // 3. Receive aux trace commitment
    let aux_commit = channel.receive_commitment()?.clone();

    // Receive aux values from the transcript (one EF element per aux value, per instance).
    // When no AIR has aux columns, each entry is empty so nothing is received.
    let all_aux_values: Vec<Vec<EF>> = instances
        .iter()
        .map(|(air, _)| {
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
    let z: EF = max_lde_coset.sample_ood_point(&mut channel);
    let h = F::two_adic_generator(log_max_trace_height.into());
    let z_next = z * h;

    // 7. Widths per commitment group (unpadded data widths).
    let main_widths: Vec<usize> = instances.iter().map(|(air, _)| air.width()).collect();
    let aux_widths: Vec<usize> =
        instances.iter().map(|(air, _)| air.aux_width() * EF::DIMENSION).collect();
    let quotient_widths: Vec<usize> = vec![constraint_degree * EF::DIMENSION];

    // Build commitments with original (unpadded) widths.
    // The PCS aligned wrapper handles alignment and truncation internally.
    let commitments = vec![
        (main_commit, main_widths),
        (aux_commit, aux_widths),
        (quotient_commit, quotient_widths),
    ];

    // 8. Verify PCS openings (returns per-matrix RowMajorMatrix<EF>, truncated to original widths)
    let opened = verify_aligned::<F, EF, SC::Lmcs, _, 2>(
        config.pcs(),
        config.lmcs(),
        &commitments,
        log_lde_height,
        [z, z_next],
        &mut channel,
    )?;

    // 9. Group indices for accessing opened matrices: [main, aux, quotient].
    let (main_g, aux_g, quot_g) = (0, 1, 2);

    // 10. Per-AIR constraint evaluation and beta accumulation
    //
    // opened[g] has one matrix per AIR (for main/aux) or one matrix total (quotient).
    // Each matrix has N=2 rows: row 0 = local (z), row 1 = next (z·h).
    debug_assert_eq!(opened[main_g].len(), instances.len());
    debug_assert_eq!(opened[aux_g].len(), instances.len());
    let mut accumulated = EF::ZERO;
    let mut reduced_aux = ReducedAuxValues::<EF>::identity();

    for (j, (air, inst)) in instances.iter().enumerate() {
        let coset_j = LiftedCoset::new(inst.log_trace_height, log_blowup, log_max_trace_height);

        // opened[main_g][j] is a 2-row RowMajorMatrix (local, next) already truncated.
        let main_window = RowWindow::from_view(&opened[main_g][j].as_view());

        // Extract aux trace opened values (reconstitute EF from base field components).
        let aux_mat = &opened[aux_g][j];
        let aux_local = row_to_packed_ext::<F, EF>(&aux_mat.row_slice(0).expect("aux row 0"))?;
        let aux_next = row_to_packed_ext::<F, EF>(&aux_mat.row_slice(1).expect("aux row 1"))?;
        let aux_window = RowWindow::from_two_rows(&aux_local, &aux_next);

        // Selectors at the lifted OOD point yⱼ = z^{rⱼ} (encapsulated in LiftedCoset).
        let selectors = coset_j.selectors_at::<F, _>(z);

        // Periodic values: for a column with period p, eval_at computes z^{n/p}.
        // Using (max_trace_height, z) gives z^{max_n / p}, which equals
        // y_j^{n_j / p} = (z^{max_n/n_j})^{n_j/p} = z^{max_n/p}. This avoids
        // computing y_j = z^{r_j} explicitly.
        let periodic_polys = PeriodicPolys::new(&air.periodic_columns());
        let periodic_values = periodic_polys.eval_at::<EF>(max_trace_height, z);

        let aux_values_j = &all_aux_values[j];
        let num_rand = air.num_randomness();
        let mut folder = ConstraintFolder {
            main: main_window,
            aux: aux_window,
            randomness: &randomness[..num_rand],
            public_values: inst.public_values,
            periodic_values: &periodic_values,
            permutation_values: aux_values_j,
            selectors,
            alpha,
            accumulator: EF::ZERO,
            _phantom: PhantomData,
        };

        air.is_valid_builder(&folder)?;
        air.eval(&mut folder);

        // Accumulate: acc = acc * beta + folded_j
        accumulated = accumulated * beta + folder.accumulator;

        // Compute reduced aux contribution and accumulate.
        let contribution = air
            .reduced_aux_values(
                aux_values_j,
                &randomness[..num_rand],
                inst.public_values,
                inst.var_len_public_inputs,
            )
            .map_err(VerifierError::Reduction)?;
        reduced_aux.combine_in_place(&contribution);
    }

    // 11. Reconstruct Q(z) and check quotient identity Q(z) * Z_{H_max}(z)
    // Quotient group has a single matrix; row 0 is the evaluation at z.
    let quot_row = opened[quot_g][0].row_slice(0).expect("quotient row 0");
    let quotient_chunks = row_to_packed_ext::<F, EF>(&quot_row)?;
    let quotient_z = reconstruct_quotient::<F, EF>(z, &max_lde_coset, &quotient_chunks);

    let vanishing = max_lde_coset.vanishing_at::<F, _>(z);
    if accumulated != quotient_z * vanishing {
        return Err(VerifierError::ConstraintMismatch);
    }

    // 12. Check global reduced aux identity (all bus contributions combine to identity)
    if !reduced_aux.is_identity() {
        return Err(VerifierError::InvalidReducedAux);
    }

    // 13. Finalize transcript: check emptiness and return digest
    Ok(channel.finalize()?)
}
