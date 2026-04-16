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
//! 3. **AIR identity and ordering** — The proof defines an ordering of AIR instances, queryable via
//!    [`InstanceShapes::air_order`]. The `air_order` values are **not** absorbed into the
//!    transcript, so the caller must bind both the AIR identity and the ordering into the
//!    challenger. How this is done is up to the caller — see the examples below. If the application
//!    has a single fixed AIR, a static domain separator suffices.
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
//! // For multi-AIR: bind AIR identity and ordering (see below).
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
//! The proof records an ordering of instances via [`InstanceShapes::air_order`]:
//! `air_order()[j]` is the caller's original index of the instance at position
//! `j`. The caller must bind the AIR identity **and** this ordering into the
//! challenger. Two approaches:
//!
//! ```text
//! let air_order = proof.instance_shapes.air_order();
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
use miden_lifted_air::{AuxBuilder, LiftedAir, VarLenPublicInputs, log2_strict_u8};
use miden_stark_transcript::{Channel, ProverChannel, ProverTranscript};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use periodic::PeriodicLde;
use thiserror::Error;
use tracing::{info_span, instrument};

use crate::{
    StarkConfig,
    coset::LiftedCoset,
    instance::{AirWitness, InstanceShapes, InstanceValidationError, validate_inputs},
    pcs::prover::open_with_channel,
    proof::{StarkOutput, StarkProof},
};

/// Errors that can occur during proving.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("instance validation failed: {0}")]
    Instance(#[from] InstanceValidationError),
    #[error(
        "constraint degree exceeds blowup: \
         log_quotient_degree {log_quotient_degree} > log_blowup {log_blowup}"
    )]
    ConstraintDegreeTooHigh { log_quotient_degree: u8, log_blowup: u8 },
}

/// Prove a single AIR.
///
/// The caller's challenger must already carry the full statement binding
/// (protocol parameters, public values, variable-length inputs, AIR identity)
/// — see the module-level docs.
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
/// The proof records the instance ordering via [`InstanceShapes::air_order`].
/// The caller's challenger must already carry the full statement binding
/// (public values, AIR configuration in proof order) — see the module-level
/// docs.
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

    // Validate AIR structure, instance dimensions, heights, and trace widths.
    let log_max_trace_height = validate_inputs(&verifier_instances, &instance_shapes, log_blowup)?;
    for &(air, w, _) in &instances {
        if w.trace.width() != air.width() {
            return Err(InstanceValidationError::WidthMismatch {
                expected: air.width(),
                actual: w.trace.width(),
            }
            .into());
        }
    }

    // Observe shape metadata before creating the transcript.
    instance_shapes.observe_heights::<F, _>(&mut challenger);

    let mut channel = ProverTranscript::new(challenger);

    // Clear the challenger's absorb buffer after observing instance shapes by
    // squeezing a throwaway extension element. This guarantees later sampled
    // challenges depend on all prior inputs regardless of sponge state.
    let _instance_challenge: EF = channel.sample_algebra_element::<EF>();

    // Infer constraint degree from symbolic AIR analysis (max across all AIRs)
    let log_constraint_degree =
        instances.iter().map(|(air, ..)| air.log_quotient_degree()).max().unwrap_or(1) as u8;

    if log_constraint_degree > log_blowup {
        return Err(ProverError::ConstraintDegreeTooHigh {
            log_quotient_degree: log_constraint_degree,
            log_blowup,
        });
    }

    let log_lde_height = log_max_trace_height + log_blowup;

    // Max LDE coset (for the largest trace, no lifting)
    let max_lde_coset = LiftedCoset::unlifted(log_max_trace_height, log_blowup);
    let max_quotient_coset = max_lde_coset.quotient_domain(log_constraint_degree);
    let max_quotient_height = max_quotient_coset.lde_height();

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
    let main_committed =
        info_span!("commit to main traces").in_scope(|| commit_traces(config, main_traces));
    channel.send_commitment(main_committed.root());

    // 2. Sample randomness and build aux traces for all AIRs
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

    let aux_committed =
        info_span!("commit to aux traces").in_scope(|| commit_traces(config, aux_traces));
    channel.send_commitment(aux_committed.root());

    // Observe aux values into the transcript (binds to Fiat-Shamir state).
    // When no AIR has aux columns, each entry is empty so nothing is sent.
    for vals in &all_aux_values {
        for &val in vals {
            channel.send_algebra_element(val);
        }
    }

    // 4. Sample constraint folding alpha and accumulation beta
    let alpha: EF = channel.sample_algebra_element::<EF>();
    let beta: EF = channel.sample_algebra_element::<EF>();

    // 5. Evaluate constraints and accumulate with beta folding.
    //
    // Single accumulator, processed in trace order (ascending height):
    //   1. Cyclically extend accumulator to the next quotient height
    //   2. Multiply every element by beta (Horner)
    //   3. Add constraint evaluations in-place: acc[i] += eval(i)
    //
    // Pre-allocate with LDE capacity so commit_quotient's resize doesn't reallocate.
    let constraint_degree = 1 << log_constraint_degree as usize;
    let mut accumulator: Vec<EF> = Vec::with_capacity(max_quotient_height * blowup);

    // Pre-compute constraint layouts for each AIR (base/ext index mapping)
    let layouts: Vec<_> = instances
        .iter()
        .map(|(air, ..)| get_constraint_layout::<F, EF, A>(*air))
        .collect();

    info_span!("evaluate constraints").in_scope(|| {
        for (i, (air, w, _)) in instances.iter().enumerate() {
            let trace_height = w.trace.height();
            let log_trace_height = log2_strict_u8(trace_height);

            // Create LiftedCoset for this trace (may be lifted relative to max)
            let this_lde_coset =
                LiftedCoset::new(log_trace_height, log_blowup, log_max_trace_height);
            let this_quotient_coset = this_lde_coset.quotient_domain(log_constraint_degree);
            let this_quotient_height = this_quotient_coset.lde_height();

            // Truncate the committed LDE to the quotient evaluation domain gJ (size N·D).
            // Since B ≥ D, the committed LDE on gK (size N·B) contains gJ as a prefix in
            // bit-reversed storage, so this is a zero-copy view.
            let main_on_gj = main_committed.evals_on_quotient_domain(i, constraint_degree);
            let aux_on_gj = aux_committed.evals_on_quotient_domain(i, constraint_degree);

            // Build periodic LDE for this trace via coset method
            let periodic_lde =
                PeriodicLde::build(&this_quotient_coset, air.periodic_columns_matrix());

            // Cyclically extend accumulator to this quotient height and scale by beta.
            // On the first iteration the accumulator is empty, so this is a no-op
            // and evaluate_constraints_into writes into a zero-filled buffer.
            tracing::debug_span!(
                "cyclic_extend",
                acc_len = accumulator.len(),
                target = this_quotient_height
            )
            .in_scope(|| {
                quotient::cyclic_extend_and_scale(&mut accumulator, this_quotient_height, beta);
            });

            let aux_values_i = &all_aux_values[i];

            // Add constraint evaluations in-place: accumulator[i] += eval(i)
            info_span!("eval_instance", instance = i, height = this_quotient_height).in_scope(
                || {
                    evaluate_constraints_into::<F, EF, A>(
                        &mut accumulator,
                        *air,
                        &main_on_gj,
                        &aux_on_gj,
                        &this_quotient_coset,
                        alpha,
                        &randomness[..air.num_randomness()],
                        w.public_values,
                        &periodic_lde,
                        &layouts[i],
                        aux_values_i,
                    );
                },
            );
        }
    });

    // Verify we have the expected size (max quotient domain)
    assert_eq!(accumulator.len(), max_quotient_height);

    // 6. Divide by vanishing polynomial once on full gJ (in-place)
    tracing::debug_span!("divide_by_vanishing", height = max_quotient_height).in_scope(|| {
        quotient::divide_by_vanishing_in_place::<F, EF>(&mut accumulator, &max_quotient_coset);
    });

    // 7. Commit quotient
    let quotient_committed = info_span!("commit to quotient poly chunks")
        .in_scope(|| quotient::commit_quotient(config, accumulator, &max_lde_coset));
    channel.send_commitment(quotient_committed.root());

    // 8. Sample OOD point (outside H and gK)
    let z: EF = max_lde_coset.sample_ood_point(&mut channel);
    let h = F::two_adic_generator(log_max_trace_height.into());
    let z_next = z * h;

    // 9. Open via PCS
    let trees = vec![main_committed.tree(), aux_committed.tree(), quotient_committed.tree()];

    info_span!("open").in_scope(|| {
        open_with_channel::<F, EF, SC::Lmcs, RowMajorMatrix<F>, _, 2>(
            config.pcs(),
            config.lmcs(),
            log_lde_height,
            [z, z_next],
            &trees,
            &mut channel,
        )
    });

    let (digest, transcript) = channel.finalize();
    let proof = StarkProof { instance_shapes, transcript };
    Ok(StarkOutput { digest, proof })
}
