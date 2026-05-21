//! Lifted STARK prover.
//!
//! This module provides:
//! - [`prove`]: Prove one or more AIR instances with traces of (possibly) different heights.
//!
//! [`prove`] writes the proof into a [`miden_stark_transcript::ProverChannel`]
//! (commitments, grinding witnesses, and openings).
//!
//! # Fiat-Shamir / transcript binding (initial challenger state)
//!
//! This crate does **not** prescribe the *initial* transcript state. The caller
//! must bind protocol and AIR configuration data before calling [`prove`]. Both
//! prover and verifier must produce identical challenger states. Concretely, the
//! caller **MUST** observe:
//!
//! 1. **Protocol parameters** — e.g. the STARK configuration, blowup factor, and any
//!    application-level domain separator.
//!
//! 2. **AIR configurations** — The framework does not commit to the [`MultiAir::airs`] list. The
//!    caller MUST bind every AIR configuration into the challenger before calling [`prove`] /
//!    [`verify`](crate::verify). The AIR ordering on the wire is derived deterministically from the
//!    trace heights (stable sort on `(log_trace_height, instance_index)`), so callers do not need
//!    to commit to it separately as long as they commit to the AIR list and trace heights match.
//!
//! The proof's `air_inputs` and `aux_inputs` are absorbed automatically by
//! [`Statement::observe`](crate::air::Statement::observe), followed by protocol-level
//! absorption of the instance count and each AIR's log trace height in instance
//! order. Callers do not bind these themselves.
//!
//! ## Recommended pattern
//!
//! Pre-seed the challenger so statement data stays out of the proof:
//!
//! ```ignore
//! // --- Bind protocol parameters + AIR configurations into Fiat-Shamir ---
//! let mut ch = Challenger::new(perm.clone());
//! ch.observe_slice(&b"MY_APP_V1".map(|b| F::from_u8(b)));  // domain separator
//! ch.observe(F::from_u8(config.pcs().log_blowup()));        // protocol parameters
//! // ... bind AIR configurations + air ordering (see below) ...
//!
//! // --- Prove ---
//! let output = prove(&config, &prover_statement, ch)?;
//!
//! // --- Verify (identical binding + the same statement) ---
//! let mut ch = Challenger::new(perm);
//! ch.observe_slice(&b"MY_APP_V1".map(|b| F::from_u8(b)));
//! ch.observe(F::from_u8(config.pcs().log_blowup()));
//! let verifier_digest = verify(&config, prover_statement.statement(), &output.proof, ch)?;
//! assert_eq!(output.digest, verifier_digest);
//! ```
//!
//! ## Multi-AIR binding example
//!
//! ```text
//! // Commit to AIRs in instance order — the proof's wire-format ordering is
//! // derived from the heights inside the framework, so binding the instance
//! // order is enough.
//! for air in statement.airs() {
//!     challenger.observe(air.commitment());
//! }
//! ```

extern crate alloc;

pub(crate) mod commit;
pub(crate) mod constraints;
pub(crate) mod periodic;
pub(crate) mod quotient;

use alloc::{vec, vec::Vec};

use commit::commit_traces;
use constraints::{evaluate_constraints_into, layout::get_constraint_layout};
use miden_lifted_air::{InstanceError, LiftedAir, MultiAir, ProverStatement, ReductionError};
use miden_stark_transcript::{Channel, ProverChannel, ProverTranscript};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use periodic::PeriodicLde;
use thiserror::Error;
use tracing::{info_span, instrument};

use crate::{
    StarkConfig,
    domain::{Coset, DomainError, LiftedDomain, log_quotient_degree},
    order::TraceOrder,
    pcs::prover::open_with_channel,
    proof::{StarkOutput, StarkProofData},
};

/// Prove a [`ProverStatement`].
///
/// The caller's challenger must already be bound to protocol parameters and
/// AIR configurations — see the module-level docs. The statement's `air_inputs`
/// and `aux_inputs` are absorbed internally via
/// [`Statement::observe`](crate::air::Statement::observe); both prover and verifier
/// must carry the same statement.
///
/// Validates only untrusted runtime inputs (returning [`ProverError`]); the AIR
/// structural contract is trusted — see the crate-level trust model and
/// [`crate::debug::assert_prover_setup`].
///
/// # Arguments
/// - `config`: STARK configuration (PCS params, LMCS, DFT)
/// - `prover_statement`: validated statement plus per-AIR traces (instance order)
/// - `challenger`: Fiat-Shamir challenger pre-bound to protocol parameters and AIR configurations
///
/// # Returns
/// `Ok(StarkOutput { digest, proof })`, or a [`ProverError`] if validation fails.
#[instrument(name = "prove", skip_all)]
pub fn prove<F, EF, MA, SC>(
    config: &SC,
    prover_statement: &ProverStatement<F, EF, MA>,
    mut challenger: SC::Challenger,
) -> Result<StarkOutput<F, EF, SC>, ProverError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    MA: MultiAir<F, EF>,
{
    // --- Trust boundary (see doc-block above). -------------------------------
    let statement = prover_statement.statement();
    let airs = statement.airs();

    let traces = prover_statement.traces();
    let air_inputs = statement.air_inputs();
    let trace_heights: Vec<usize> = traces.iter().map(Matrix::height).collect();
    let trace_order = TraceOrder::from_trace_heights::<F, EF, _>(airs, &trace_heights)
        .expect("ProverStatement::new should reject malformed heights");

    // Borrow each AIR and trace, then reorder both into ascending-height (proof)
    // order. AIRs are passed as `&MA::Air` (the existing constraint code expects
    // a reference); traces likewise via `&RowMajorMatrix<F>`.
    let air_refs: Vec<&MA::Air> = airs.iter().collect();
    let trace_refs: Vec<&RowMajorMatrix<F>> = traces.iter().collect();
    let proof_ordered_airs = trace_order.to_proof_order(&air_refs);
    let proof_ordered_traces = trace_order.to_proof_order(&trace_refs);
    let proof_ordered: Vec<_> = proof_ordered_airs
        .iter()
        .copied()
        .zip(proof_ordered_traces.iter().copied())
        .collect();

    let log_blowup = config.pcs().log_blowup();
    let log_max_trace_height = trace_order.max_log_height();
    let max_lde_domain = LiftedDomain::<F>::try_canonical(log_max_trace_height, log_blowup)?;
    let instance_domains: Vec<_> = trace_order
        .log_heights_proof()
        .iter()
        .map(|&log_h| max_lde_domain.try_sub_domain(log_h))
        .collect::<Result<_, _>>()?;

    // `Statement::observe` absorbs statement-owned inputs. The protocol then
    // binds the instance count and each log trace height in instance order.
    statement.observe(&mut challenger, trace_order.log_heights());
    trace_order.observe_shape::<F, _>(&mut challenger);

    let mut channel = ProverTranscript::new(challenger);

    // Infer per-AIR quotient degrees from symbolic analysis (per-AIR optimization).
    let log_quotient_degrees: Vec<u8> = proof_ordered
        .iter()
        .map(|&(air, _)| log_quotient_degree::<F, EF, _>(air))
        .collect();
    let log_quotient_degree = log_quotient_degrees.iter().copied().max().unwrap_or(1);
    if log_quotient_degree > log_blowup {
        return Err(DomainError::ConstraintDegreeTooHigh {
            log_quotient: log_quotient_degree,
            log_blowup,
        }
        .into());
    }

    // Pair the max LDE domain with the quotient degree. The `EvaluationDomain`
    // now flows through the constraint and quotient layers. Per-instance variants
    // are pre-built so the constraint loop just indexes into a `Vec`.
    let max_eval_domain = max_lde_domain.evaluation_domain(log_quotient_degree);
    let instance_eval_domains: Vec<_> = instance_domains
        .iter()
        .map(|d| d.evaluation_domain(log_quotient_degree))
        .collect();

    // Quotient evaluation coset: a sub-coset of the LDE coset where Q is evaluated
    // before being decomposed into D chunks and committed on the LDE coset itself.
    let max_quotient_height = max_eval_domain.size();

    // 1. Commit all main traces (trace order — ascending height).
    //
    // Clone with blowup × capacity so the DFT resize doesn't reallocate.
    let blowup = 1 << log_blowup as usize;
    let main_traces: Vec<_> = proof_ordered
        .iter()
        .map(|&(_, trace)| {
            let src = &trace.values;
            let mut values = Vec::with_capacity(src.len() * blowup);
            values.extend_from_slice(src);
            RowMajorMatrix::new(values, trace.width())
        })
        .collect();
    let main_committed = info_span!("commit to main traces")
        .in_scope(|| commit_traces(config, &instance_domains, main_traces));
    channel.send_commitment(main_committed.root());

    // 2. Sample randomness, build aux traces, and commit them
    let max_num_randomness =
        proof_ordered.iter().map(|&(air, _)| air.num_randomness()).max().unwrap_or(0);

    let randomness: Vec<EF> = (0..max_num_randomness)
        .map(|_| channel.sample_algebra_element::<EF>())
        .collect();

    // Build all aux traces in one call (instance-ordered), then reorder in
    // place to the proof's AIR ordering to match the rest of the prover loop.
    //
    // The output shapes are trusted (see trust contract above); a malformed
    // output is caught downstream by the LDE/commit or by verification.
    let (mut aux_traces_ef, mut all_aux_values) =
        info_span!("build aux traces").in_scope(|| prover_statement.build_aux_traces(&randomness));

    // Mirror the verifier's external assertion evaluation while aux values are
    // still in instance order. This is cheap and catches malformed statements
    // early; it could become a debug assertion if proving needs to skip this
    // verifier-side sanity check.
    let aux_views: Vec<&[EF]> = all_aux_values.iter().map(Vec::as_slice).collect();
    let assertions = statement
        .eval_external(&randomness, &aux_views, trace_order.log_heights())
        .map_err(ProverError::Reduction)?;
    for (k, assertion) in assertions.iter().enumerate() {
        if *assertion != EF::ZERO {
            return Err(ProverError::ExternalAssertionFailed { assertion: k });
        }
    }

    trace_order.reorder_to_proof_in_place(&mut aux_traces_ef);
    trace_order.reorder_to_proof_in_place(&mut all_aux_values);

    // Flatten EF -> F and commit aux traces
    let aux_traces: Vec<RowMajorMatrix<F>> = aux_traces_ef
        .into_iter()
        .map(|aux| {
            let base_width = aux.width() * EF::DIMENSION;
            let base_values = <EF as BasedVectorSpace<F>>::flatten_to_base(aux.values);
            RowMajorMatrix::new(base_values, base_width)
        })
        .collect();

    let aux_committed = info_span!("commit to aux traces")
        .in_scope(|| commit_traces(config, &instance_domains, aux_traces));
    channel.send_commitment(aux_committed.root());

    // Observe aux values into the transcript (binds to Fiat-Shamir state).
    // When no AIR has aux columns, each entry is empty so nothing is sent.
    for vals in &all_aux_values {
        for &val in vals {
            channel.send_algebra_element(val);
        }
    }

    // 3. Sample constraint folding alpha and accumulation beta
    let alpha: EF = channel.sample_algebra_element::<EF>();
    let beta: EF = channel.sample_algebra_element::<EF>();

    // 4. Evaluate constraints and accumulate quotient evaluations with beta folding.
    //
    // Per AIR (ascending height):
    //   1. Evaluate Q_j = (alpha-folded constraints) / Z_{H_j} on the native quotient domain
    //      (divide fused into the eval write).
    //   2. If D_j < D_max, upsample Q_j to the per-trace target domain.
    //   3. Cyclically extend the accumulator and Horner-fold: acc <- acc * beta + Q_j.
    //
    // Pre-allocate with LDE capacity so commit_quotient's resize doesn't reallocate.
    let mut accumulator: Vec<EF> = Vec::with_capacity(max_quotient_height * blowup);

    // Pre-compute per-AIR constraint layouts.
    let layouts: Vec<_> = proof_ordered
        .iter()
        .map(|&(air, _)| get_constraint_layout::<F, EF, _>(air))
        .collect();

    info_span!("evaluate constraints").in_scope(|| {
        for (i, &(air, _)) in proof_ordered.iter().enumerate() {
            let this_log_quotient_degree = log_quotient_degrees[i];
            let this_quotient_degree = 1usize << this_log_quotient_degree;

            // Per-AIR native quotient evaluation domain `gJ_j` (size n_j · D_j,
            // before upsampling to n_j · D_max).
            let this_quotient_eval_domain =
                instance_domains[i].evaluation_domain(this_log_quotient_degree);
            // Target after upsample to D_max (size n_j · D_max).
            let this_target_quotient_height = instance_eval_domains[i].size();

            // Truncate the committed LDE to the AIR's native quotient evaluation domain gJ_j.
            // Since B >= D_j, the committed LDE on gK (size N*B) contains gJ_j as a prefix in
            // bit-reversed storage, so this is a zero-copy view.
            let main_on_gj = main_committed.evals_on_quotient_domain(i, &this_quotient_eval_domain);
            let aux_on_gj = aux_committed.evals_on_quotient_domain(i, &this_quotient_eval_domain);

            let periodic_lde =
                PeriodicLde::build(&this_quotient_eval_domain, air.periodic_columns_matrix());

            let mut quotient_evals = EF::zero_vec(this_quotient_eval_domain.size());
            let aux_values_i = &all_aux_values[i];
            let inv_z_h = this_quotient_eval_domain.inv_vanishing_evals();

            tracing::debug_span!(
                "eval_instance",
                instance = i,
                native_height = this_quotient_eval_domain.size(),
                target_height = this_target_quotient_height,
                native_degree = this_quotient_degree,
                target_degree = 1 << log_quotient_degree as usize,
            )
            .in_scope(|| {
                evaluate_constraints_into::<F, EF, _>(
                    &mut quotient_evals,
                    air,
                    &main_on_gj,
                    &aux_on_gj,
                    &this_quotient_eval_domain,
                    alpha,
                    &randomness[..air.num_randomness()],
                    air_inputs,
                    &periodic_lde,
                    &layouts[i],
                    aux_values_i,
                    &inv_z_h,
                );
            });

            if this_log_quotient_degree < log_quotient_degree {
                let added_bits = (log_quotient_degree - this_log_quotient_degree) as usize;
                quotient_evals = tracing::debug_span!(
                    "upsample_quotient",
                    instance = i,
                    from = this_quotient_eval_domain.size(),
                    to = this_target_quotient_height,
                )
                .in_scope(|| {
                    quotient::upsample_evals::<F, EF, _>(config.dft(), quotient_evals, added_bits)
                });
            }

            debug_assert_eq!(quotient_evals.len(), this_target_quotient_height);

            // Cyclically extend the running accumulator to the per-AIR target height and
            // Horner-fold this AIR's contribution in: acc <- acc * beta + Q_j.
            tracing::debug_span!(
                "cyclic_extend_and_accumulate",
                acc_len = accumulator.len(),
                target = this_target_quotient_height
            )
            .in_scope(|| {
                quotient::cyclic_extend_and_accumulate(&mut accumulator, quotient_evals, beta);
            });
        }
    });

    debug_assert_eq!(accumulator.len(), max_quotient_height);

    // 5. Commit quotient.
    let quotient_committed = info_span!("commit to quotient poly chunks")
        .in_scope(|| quotient::commit_quotient(config, accumulator, &max_eval_domain));
    channel.send_commitment(quotient_committed.root());

    // 6. Sample OOD point (outside H and gK)
    let z: EF = max_lde_domain.sample_ood_point(&mut channel);
    let h = max_lde_domain.trace_subgroup().generator();
    let z_next = z * h;

    // 7. Open via PCS
    let trees = vec![main_committed.tree(), aux_committed.tree(), quotient_committed.tree()];

    info_span!("open").in_scope(|| {
        open_with_channel::<F, EF, SC::Lmcs, RowMajorMatrix<F>, _, 2>(
            config.pcs(),
            config.lmcs(),
            &max_lde_domain,
            [z, z_next],
            &trees,
            &mut channel,
        )
    });

    let (digest, transcript) = channel.finalize();
    let proof = StarkProofData {
        log_trace_heights: trace_order.log_heights().to_vec(),
        transcript,
    };
    Ok(StarkOutput { digest, proof })
}

/// Errors from proving — runtime validation failures of caller-supplied data.
/// The AIR's structural contract is trusted (see the crate-level trust model).
#[derive(Debug, Error)]
pub enum ProverError {
    #[error(transparent)]
    Instance(#[from] InstanceError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error("external assertion evaluation failed: {0}")]
    Reduction(ReductionError),
    #[error("external assertion {assertion} is non-zero")]
    ExternalAssertionFailed {
        /// Index into the assertions vector returned by
        /// [`Statement::eval_external`](miden_lifted_air::Statement::eval_external).
        assertion: usize,
    },
}
