//! STARK proof types and structured transcript.
//!
//! This module defines the proof artifact types shared by prover and verifier:
//! - [`StarkProof`]: raw transcript data (field elements and commitments)
//! - [`StarkDigest`]: binding digest committing to the entire interaction
//! - [`StarkOutput`]: combined prover output (proof + digest)
//! - [`StarkTranscript`]: structured parse-only view of the full protocol interaction
//!
//! [`StarkTranscript`] has a [`from_proof`](StarkTranscript::from_proof) constructor
//! that parses it from proof data and a challenger, following the same pattern as
//! [`PcsTranscript`] alongside the PCS verifier.

extern crate alloc;

use alloc::{vec, vec::Vec};

use miden_lifted_air::{AirInstance, LiftedAir, validate_instances};
use miden_stark_transcript::{Channel, TranscriptData, VerifierChannel, VerifierTranscript};
use p3_challenger::CanFinalizeDigest;
use p3_field::{ExtensionField, Field, TwoAdicField};

use crate::{
    StarkConfig,
    coset::LiftedCoset,
    lmcs::{Lmcs, utils::aligned_len},
    pcs::proof::PcsTranscript,
    verifier::VerifierError,
};

/// STARK proof: raw transcript data (field elements and commitments) produced by
/// the prover and consumed by the verifier.
pub type StarkProof<F, EF, SC> =
    TranscriptData<F, <<SC as StarkConfig<F, EF>>::Lmcs as Lmcs>::Commitment>;

/// Transcript digest: the challenger's native binding digest that commits to
/// the entire prover–verifier interaction. The prover and verifier must produce
/// the same digest for the proof to be valid.
pub type StarkDigest<F, EF, SC> =
    <<SC as StarkConfig<F, EF>>::Challenger as CanFinalizeDigest>::Digest;

/// Output of [`crate::prover::prove_single`] / [`crate::prover::prove_multi`]: the proof data and
/// its transcript digest.
pub struct StarkOutput<F: TwoAdicField, EF: ExtensionField<F>, SC: StarkConfig<F, EF>> {
    /// Transcript digest committing to the entire prover–verifier interaction.
    pub digest: StarkDigest<F, EF, SC>,
    /// Raw transcript data consumed by the verifier.
    pub proof: StarkProof<F, EF, SC>,
}

/// Structured transcript view for the full lifted STARK protocol.
///
/// Captures all commitments, sampled challenges, the OOD evaluation point, and
/// the PCS sub-transcript (DEEP evals, FRI rounds, query openings).
///
/// Constructed via [`from_proof`](Self::from_proof), which mirrors steps 1–9 of
/// [`verify_multi`](crate::verifier::verify_multi) (parse only, no constraint checks).
pub struct StarkTranscript<EF, L>
where
    L: Lmcs,
    L::F: Field,
    EF: ExtensionField<L::F>,
{
    /// Main trace commitment.
    pub main_commit: L::Commitment,
    /// Randomness sampled for auxiliary traces.
    pub randomness: Vec<EF>,
    /// Auxiliary trace commitment.
    pub aux_commit: L::Commitment,
    /// Aux values per AIR instance, observed into the transcript after the aux commitment.
    pub all_aux_values: Vec<Vec<EF>>,
    /// Constraint folding challenge alpha.
    pub alpha: EF,
    /// AIR accumulation challenge beta.
    pub beta: EF,
    /// Quotient polynomial commitment.
    pub quotient_commit: L::Commitment,
    /// Out-of-domain evaluation point z.
    pub z: EF,
    /// PCS sub-transcript (DEEP evals, FRI rounds, query openings).
    pub pcs_transcript: PcsTranscript<EF, L>,
}

impl<EF, L> StarkTranscript<EF, L>
where
    L: Lmcs,
    L::F: TwoAdicField,
    EF: ExtensionField<L::F>,
{
    /// Parse a STARK transcript from proof data and a challenger.
    ///
    /// Mirrors steps 1–9 of [`verify_multi`](crate::verifier::verify_multi):
    /// 1. Receive main trace commitment
    /// 2. Sample randomness for auxiliary traces
    /// 3. Receive auxiliary trace commitment
    /// 4. Receive aux values (per AIR instance)
    /// 5. Sample constraint folding alpha and accumulation beta
    /// 6. Receive quotient commitment
    /// 7. Sample OOD point z
    /// 8. Build commitment widths for PCS
    /// 9. Parse PCS sub-transcript via [`PcsTranscript::from_verifier_channel`]
    ///
    /// Does **not** verify constraints or check the quotient identity.
    /// Finalizes the transcript and returns the digest alongside the parsed view.
    #[allow(clippy::type_complexity)]
    pub fn from_proof<A, SC>(
        config: &SC,
        instances: &[(&A, AirInstance<'_, L::F>)],
        proof: &TranscriptData<L::F, L::Commitment>,
        challenger: SC::Challenger,
    ) -> Result<(Self, StarkDigest<L::F, EF, SC>), VerifierError>
    where
        A: LiftedAir<L::F, EF>,
        SC: StarkConfig<L::F, EF, Lmcs = L>,
    {
        let log_max_trace_height = validate_instances(instances)?;

        let mut channel = VerifierTranscript::from_data(challenger, proof);
        let log_blowup = config.pcs().log_blowup();
        let alignment = config.lmcs().alignment();

        // Infer constraint degree from symbolic AIR analysis (max across all AIRs)
        let constraint_degree =
            instances.iter().map(|(air, _)| air.constraint_degree()).max().unwrap_or(2);
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

        // 4. Receive aux values from the transcript (one EF element per aux value, per instance).
        let all_aux_values: Vec<Vec<EF>> = instances
            .iter()
            .map(|(air, _)| {
                let count = air.num_aux_values();
                (0..count)
                    .map(|_| channel.receive_algebra_element::<EF>())
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 5. Sample constraint folding alpha and accumulation beta
        let alpha: EF = channel.sample_algebra_element::<EF>();
        let beta: EF = channel.sample_algebra_element::<EF>();

        // 6. Receive quotient commitment
        let quotient_commit = channel.receive_commitment()?.clone();

        // 7. Sample OOD point (outside max trace domain H and max LDE coset gK)
        let z: EF = max_lde_coset.sample_ood_point(&mut channel);
        let h = L::F::two_adic_generator(log_max_trace_height.into());
        let z_next = z * h;

        // 8. Build commitment widths for PCS.
        //
        // The LMCS commits to rows padded to `alignment` boundary, so DEEP evals and
        // batch openings are stored at aligned widths in the transcript. We must use
        // aligned widths here to parse the transcript correctly.
        // (The verifier's `verify_aligned` does the same alignment internally, then
        // truncates the returned evals back to original widths for constraint checking.)
        let main_widths: Vec<usize> =
            instances.iter().map(|(air, _)| aligned_len(air.width(), alignment)).collect();
        let quotient_width = aligned_len(constraint_degree * EF::DIMENSION, alignment);

        let aux_widths: Vec<usize> = instances
            .iter()
            .map(|(air, _)| aligned_len(air.aux_width() * EF::DIMENSION, alignment))
            .collect();

        let commitments = vec![
            (main_commit.clone(), main_widths),
            (aux_commit.clone(), aux_widths),
            (quotient_commit.clone(), vec![quotient_width]),
        ];

        // 9. Parse PCS sub-transcript
        let pcs_transcript = PcsTranscript::from_verifier_channel::<_, 2>(
            config.pcs(),
            config.lmcs(),
            &commitments,
            log_lde_height,
            [z, z_next],
            &mut channel,
        )?;

        // 10. Finalize transcript and extract digest
        let digest = channel.finalize()?;

        Ok((
            Self {
                main_commit,
                randomness,
                aux_commit,
                all_aux_values,
                alpha,
                beta,
                quotient_commit,
                z,
                pcs_transcript,
            },
            digest,
        ))
    }
}
