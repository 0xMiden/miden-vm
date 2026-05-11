//! Lifted STARK prover.
//!
//! This module provides:
//! - [`prove_single`]: Prove a single AIR instance.
//! - [`prove_multi`]: Prove multiple AIR instances with traces of different heights.
//!
//! These functions write the proof into a [`miden_stark_transcript::ProverChannel`]
//! (commitments, grinding witnesses, and openings).
//!
//! # Fiat-Shamir / transcript binding (initial challenger state)
//!
//! This crate does **not** prescribe the *initial* transcript state. The caller
//! must bind the full statement into the Fiat-Shamir challenger before calling
//! [`prove_multi`]. Both prover and verifier must produce identical challenger
//! states. Concretely, the caller **MUST** observe:
//!
//! 1. **Protocol parameters** — e.g. the STARK configuration, blowup factor, and any
//!    application-level domain separator.
//!
//! 2. **Public values and variable-length inputs** — `public_values` and `var_len_public_inputs`
//!    for every instance. Without this, Fiat-Shamir challenges are independent of the statement.
//!
//! 3. **AIR configurations and `air_order`** — The proof defines an ordering of AIR instances
//!    (`air_order()[j]` is the caller's original index at proof position `j`), queryable via
//!    [`InstanceShapes::air_order`]. The ordering is deterministic: instances are sorted by
//!    `(log_trace_height, caller_index)`. Neither the AIR configurations nor `air_order` are
//!    absorbed into the transcript, so the caller must bind both into the challenger. How this is
//!    done is up to the caller — see the examples below. The prover can precompute `air_order` via
//!    [`InstanceShapes::from_trace_heights`]; the verifier reads it from the proof.
//!
//! ## Recommended pattern
//!
//! Pre-seed the challenger so statement data stays out of the proof:
//!
//! ```ignore
//! // --- Bind statement into Fiat-Shamir ---
//! let mut ch = Challenger::new(perm.clone());
//! ch.observe_slice(&b"MY_APP_V1".map(|b| F::from_u8(b)));  // domain separator
//! ch.observe(F::from_u8(config.pcs().log_blowup()));        // protocol parameters
//! // ... observe remaining protocol parameters ...
//! ch.observe_slice(&public_values);
//! for vl in &var_len_public_inputs {
//!     ch.observe_slice(vl);
//! }
//! // For multi-AIR: bind AIR configurations and air_order (see below).
//!
//! // --- Prove ---
//! let output = prove_multi(&config, &instances, ch)?;
//!
//! // --- Verify (identical binding) ---
//! let mut ch = Challenger::new(perm);
//! ch.observe_slice(&b"MY_APP_V1".map(|b| F::from_u8(b)));
//! ch.observe(F::from_u8(config.pcs().log_blowup()));
//! // ... observe remaining protocol parameters ...
//! ch.observe_slice(&public_values);
//! for vl in &var_len_public_inputs {
//!     ch.observe_slice(vl);
//! }
//! let verifier_digest = verify_multi(&config, &verifier_instances, &output.proof, ch)?;
//! assert_eq!(output.digest, verifier_digest);
//! ```
//!
//! ## Multi-AIR binding examples
//!
//! ```text
//! // Prover: precompute air_order before building the challenger.
//! let shapes = InstanceShapes::from_trace_heights(trace_heights)?;
//! let air_order = shapes.air_order();
//!
//! // Verifier: read air_order from the proof.
//! let air_order = proof.air_order();
//!
//! // Option A: reorder AIRs to proof order and commit — the ordering is
//! // implicit in the commitment.
//! let ordered_airs: Vec<_> = air_order.iter().map(|&idx| &airs[idx as usize]).collect();
//! let circuit = Circuit::from_airs(&ordered_airs);
//! challenger.observe(circuit.commitment());
//!
//! // Option B: commit to AIRs in their natural order, then observe
//! // air_order to bind the ordering explicitly.
//! for air in &airs {
//!     challenger.observe(air.commitment());
//! }
//! challenger.observe_slice(air_order);
//! ```

extern crate alloc;

pub mod commit;
pub mod constraints;
pub mod periodic;
pub mod quotient;

use alloc::{vec, vec::Vec};

use commit::commit_traces;
use constraints::{evaluate_constraints_into, layout::get_constraint_layout};
use miden_lifted_air::{AuxBuilder, LiftedAir, VarLenPublicInputs};
use miden_stark_transcript::{Channel, ProverChannel, ProverTranscript};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use periodic::PeriodicLde;
use thiserror::Error;
use tracing::{info_span, instrument};

use crate::{
    StarkConfig,
    domain::{Coset, LiftedDomain},
    instance::{AirWitness, InstanceShapes, InstanceValidationError},
    pcs::prover::open_with_channel,
    proof::{StarkOutput, StarkProof},
};

/// Errors that can occur during proving.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("instance validation failed: {0}")]
    Instance(#[from] InstanceValidationError),
    #[error("domain construction failed: {0}")]
    Domain(#[from] crate::domain::DomainError),
    #[error(
        "constraint degree exceeds blowup: \
         log_quotient_degree {log_quotient_degree} > log_blowup {log_blowup}"
    )]
    ConstraintDegreeTooHigh { log_quotient_degree: u8, log_blowup: u8 },
}

/// Prove a single AIR.
///
/// The caller's challenger must already be bound to the full statement
/// (protocol parameters, AIR configuration, public values, and
/// variable-length inputs) — see the module-level docs.
///
/// This is a convenience wrapper around [`prove_multi`] for the single-AIR case.
///
/// # Returns
/// `Ok(StarkOutput { digest, proof })` on success, or a `ProverError` if validation fails.
pub fn prove_single<F, EF, A, B, SC>(
    config: &SC,
    air: &A,
    trace: &RowMajorMatrix<F>,
    public_values: &[F],
    var_len_public_inputs: VarLenPublicInputs<'_, F>,
    aux_builder: &B,
    challenger: SC::Challenger,
) -> Result<StarkOutput<F, EF, SC>, ProverError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    let witness = AirWitness::new(trace, public_values, var_len_public_inputs);
    prove_multi(config, &[(air, witness, aux_builder)], challenger)
}

/// Prove multiple AIRs with traces of different heights.
///
/// The caller's challenger must already be bound to the full statement
/// (protocol parameters, AIR configurations, AIR ordering, and public
/// inputs — both fixed and variable-length) — see the module-level docs.
///
/// # Arguments
/// - `config`: STARK configuration (PCS params, LMCS, DFT)
/// - `instances`: Pairs of (AIR, witness, aux_builder)
/// - `challenger`: Fiat-Shamir challenger (heights are observed before use)
///
/// # Returns
/// `Ok(StarkOutput { digest, proof })` on success, or a `ProverError` if validation fails.
#[instrument(name = "prove", skip_all)]
pub fn prove_multi<F, EF, A, B, SC>(
    config: &SC,
    instances: &[(&A, AirWitness<'_, F>, &B)],
    mut challenger: SC::Challenger,
) -> Result<StarkOutput<F, EF, SC>, ProverError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    let trace_heights: Vec<usize> = instances.iter().map(|(_, w, _)| w.trace.height()).collect();
    let instance_shapes = InstanceShapes::from_trace_heights(trace_heights)?;

    // Reorder instances to the proof's AIR ordering.
    let instances = instance_shapes.reorder(instances.to_vec())?;

    let verifier_instances: Vec<_> =
        instances.iter().map(|(air, w, _)| (*air, w.to_instance())).collect();

    let log_blowup = config.pcs().log_blowup();

    // Validate AIR structure, instance dimensions, and trace widths.
    instance_shapes.validate_instance_data(&verifier_instances)?;
    for &(air, w, _) in &instances {
        if w.trace.width() != air.width() {
            return Err(InstanceValidationError::WidthMismatch {
                expected: air.width(),
                actual: w.trace.width(),
            }
            .into());
        }
    }

    let log_max_trace_height = *instance_shapes
        .log_trace_heights()
        .last()
        .ok_or(InstanceValidationError::Empty)?;
    let max_lde_domain = LiftedDomain::<F>::try_canonical(log_max_trace_height, log_blowup)?;
    let instance_domains = instance_shapes.ascending_subdomains(&max_lde_domain)?;

    // Observe shape metadata before creating the transcript.
    instance_shapes.observe_heights::<F, _>(&mut challenger);

    let mut channel = ProverTranscript::new(challenger);

    // Clear the challenger's absorb buffer after observing instance shapes by
    // squeezing a throwaway extension element. This guarantees later sampled
    // challenges depend on all prior inputs regardless of sponge state.
    let _instance_challenge: EF = channel.sample_algebra_element::<EF>();

    // Infer per-AIR quotient degrees from symbolic analysis (per-AIR optimization).
    let log_constraint_degrees: Vec<u8> =
        instances.iter().map(|(air, ..)| air.log_quotient_degree()).collect();
    let log_quotient_degree = log_constraint_degrees.iter().copied().max().unwrap_or(1);

    if log_quotient_degree > log_blowup {
        return Err(ProverError::ConstraintDegreeTooHigh { log_quotient_degree, log_blowup });
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
    let main_traces: Vec<_> = instances
        .iter()
        .map(|(_, w, _)| {
            let src = &w.trace.values;
            let mut values = Vec::with_capacity(src.len() * blowup);
            values.extend_from_slice(src);
            RowMajorMatrix::new(values, w.trace.width())
        })
        .collect();
    let main_committed = info_span!("commit to main traces")
        .in_scope(|| commit_traces(config, &instance_domains, main_traces));
    channel.send_commitment(main_committed.root());

    // 2. Sample randomness, build aux traces, and commit them
    let max_num_randomness =
        instances.iter().map(|(air, ..)| air.num_randomness()).max().unwrap_or(0);

    let randomness: Vec<EF> = (0..max_num_randomness)
        .map(|_| channel.sample_algebra_element::<EF>())
        .collect();

    // Build aux traces via AuxBuilder
    let (aux_traces_ef, all_aux_values): (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>) =
        info_span!("build aux traces").in_scope(|| {
            let mut traces = Vec::with_capacity(instances.len());
            let mut values = Vec::with_capacity(instances.len());
            for (air, w, aux_builder) in &instances {
                let num_rand = air.num_randomness();
                let (aux, aux_vals) = aux_builder.build_aux_trace(w.trace, &randomness[..num_rand]);

                assert_eq!(aux.width(), air.aux_width(), "aux trace width mismatch");
                assert_eq!(
                    aux_vals.len(),
                    air.num_aux_values(),
                    "aux values length mismatch: build_aux_trace returned {} values, \
                     but num_aux_values() is {}",
                    aux_vals.len(),
                    air.num_aux_values()
                );
                assert_eq!(aux.height(), w.trace.height());
                traces.push(aux);
                values.push(aux_vals);
            }
            (traces, values)
        });

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
    let layouts: Vec<_> = instances
        .iter()
        .map(|(air, ..)| get_constraint_layout::<F, EF, A>(*air))
        .collect();

    info_span!("evaluate constraints").in_scope(|| {
        for (i, (air, w, _)) in instances.iter().enumerate() {
            let this_log_constraint_degree = log_constraint_degrees[i];
            let this_constraint_degree = 1usize << this_log_constraint_degree;

            // Per-AIR native quotient evaluation domain `gJ_j` (size n_j · D_j,
            // before upsampling to n_j · D_max).
            let this_quotient_eval_domain =
                instance_domains[i].evaluation_domain(this_log_constraint_degree);
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
                native_degree = this_constraint_degree,
                target_degree = 1 << log_quotient_degree as usize,
            )
            .in_scope(|| {
                evaluate_constraints_into::<F, EF, A>(
                    &mut quotient_evals,
                    *air,
                    &main_on_gj,
                    &aux_on_gj,
                    &this_quotient_eval_domain,
                    alpha,
                    &randomness[..air.num_randomness()],
                    w.public_values,
                    &periodic_lde,
                    &layouts[i],
                    aux_values_i,
                    &inv_z_h,
                );
            });

            if this_log_constraint_degree < log_quotient_degree {
                let added_bits = (log_quotient_degree - this_log_constraint_degree) as usize;
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
    let proof = StarkProof { instance_shapes, transcript };
    Ok(StarkOutput { digest, proof })
}
