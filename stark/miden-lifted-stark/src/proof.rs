//! STARK proof types and structured transcript.
//!
//! This module defines the proof artifact types shared by prover and verifier:
//! - [`StarkProofData`]: raw transcript data (field elements and commitments)
//! - [`StarkDigest`]: binding digest committing to the entire interaction
//! - [`StarkOutput`]: combined prover output (proof + digest)
//! - [`StarkProof`]: structured parse-only view of the full protocol interaction
//!
//! [`StarkProof`] has a [`from_data`](StarkProof::from_data) constructor
//! that parses it from proof data and a challenger, following the same pattern as
//! [`PcsProof`] alongside the PCS verifier.

extern crate alloc;

use alloc::{vec, vec::Vec};

use miden_lifted_air::{BaseAir, LiftedAir, MultiAir, Statement};
use miden_stark_transcript::{Channel, VerifierChannel, VerifierTranscript};
// Re-exported here so the crate root does not need a dedicated `transcript` module: callers
// reach these via `proof::` alongside the proof types they parameterize.
pub use miden_stark_transcript::{TranscriptChallenger, TranscriptData, TranscriptError};
use p3_challenger::CanFinalizeDigest;
use p3_field::{ExtensionField, Field, TwoAdicField};
use serde::{Deserialize, Serialize};

use crate::{
    StarkConfig,
    domain::{Coset, DomainError, LiftedDomain, log_quotient_degree},
    lmcs::Lmcs,
    order::TraceOrder,
    pcs::proof::PcsProof,
    util::align::aligned_len,
    verifier::VerifierError,
};

/// Commitment type alias for convenience.
type Commitment<F, EF, SC> = <<SC as StarkConfig<F, EF>>::Lmcs as Lmcs>::Commitment;

/// STARK proof: per-AIR log trace heights (instance order) plus the raw
/// transcript data.
///
/// The proof's AIR ordering — used internally by the prover and verifier to
/// fold multi-AIR constraints — is *not* stored. Both sides reconstruct it
/// deterministically from the heights via the internal trace-order helper,
/// so the proof commits to heights only.
///
/// The heights themselves are not exposed as a direct accessor: parse the
/// proof through [`StarkProof::from_data`] and read them via
/// [`StarkProof::log_trace_heights`].
// Bounds target `Commitment` directly; `SC` itself isn't `Serialize`/`Debug`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "TranscriptData<F, Commitment<F, EF, SC>>: Serialize"))]
#[serde(bound(deserialize = "TranscriptData<F, Commitment<F, EF, SC>>: Deserialize<'de>"))]
pub struct StarkProofData<F: TwoAdicField, EF: ExtensionField<F>, SC: StarkConfig<F, EF>> {
    /// Per-AIR log₂ trace heights, in instance order. Matches
    /// [`Statement::airs`] position-for-position.
    pub(crate) log_trace_heights: Vec<u8>,
    pub(crate) transcript: TranscriptData<F, Commitment<F, EF, SC>>,
}

impl<F, EF, SC> core::fmt::Debug for StarkProofData<F, EF, SC>
where
    F: TwoAdicField + core::fmt::Debug,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    Commitment<F, EF, SC>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StarkProofData")
            .field("log_trace_heights", &self.log_trace_heights)
            .field("transcript", &self.transcript)
            .finish()
    }
}

impl<F, EF, SC> StarkProofData<F, EF, SC>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
{
    /// Number of traces (instances) the proof was produced for.
    pub fn num_traces(&self) -> usize {
        self.log_trace_heights.len()
    }

    /// Number of base-field elements in the transcript.
    pub fn num_field_elements(&self) -> usize {
        self.transcript.fields().len()
    }

    /// Number of commitments in the transcript.
    pub fn num_commitments(&self) -> usize {
        self.transcript.commitments().len()
    }

    /// Total byte size of the proof.
    pub fn size_in_bytes(&self) -> usize {
        self.log_trace_heights.len() + self.transcript.size_in_bytes()
    }
}

/// Transcript digest: the challenger's native binding digest that commits to
/// the entire prover–verifier interaction. The prover and verifier must produce
/// the same digest for the proof to be valid.
pub type StarkDigest<F, EF, SC> =
    <<SC as StarkConfig<F, EF>>::Challenger as CanFinalizeDigest>::Digest;

/// Output of [`crate::prover::prove`]: the proof data and
/// its transcript digest.
pub struct StarkOutput<F: TwoAdicField, EF: ExtensionField<F>, SC: StarkConfig<F, EF>> {
    /// Transcript digest committing to the entire prover–verifier interaction.
    pub digest: StarkDigest<F, EF, SC>,
    /// Proof data consumed by the verifier.
    pub proof: StarkProofData<F, EF, SC>,
}

impl<F, EF, SC> core::fmt::Debug for StarkOutput<F, EF, SC>
where
    F: TwoAdicField + core::fmt::Debug,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
    StarkDigest<F, EF, SC>: core::fmt::Debug,
    Commitment<F, EF, SC>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StarkOutput")
            .field("digest", &self.digest)
            .field("proof", &self.proof)
            .finish()
    }
}

/// Structured transcript view for the full lifted STARK protocol.
///
/// Captures the reconstructed AIR ordering, commitments, sampled challenges,
/// the OOD evaluation point, and the PCS sub-transcript. Constructed via
/// [`from_data`](Self::from_data), which mirrors steps 0–9 of
/// [`verify`](crate::verifier::verify) but skips the constraint check.
pub struct StarkProof<EF, L>
where
    L: Lmcs,
    L::F: Field,
    EF: ExtensionField<L::F>,
{
    /// AIR ordering reconstructed from the proof's log trace heights.
    /// Validated and observed into the challenger by
    /// [`from_data`](Self::from_data). Read its data through
    /// [`log_trace_heights`](Self::log_trace_heights) and
    /// [`air_order`](Self::air_order).
    pub(crate) trace_order: TraceOrder,
    /// Main trace commitment.
    pub main_commit: L::Commitment,
    /// Randomness sampled for auxiliary traces.
    pub randomness: Vec<EF>,
    /// Auxiliary trace commitment.
    pub aux_commit: L::Commitment,
    /// Aux values per AIR instance, in the proof's AIR ordering.
    pub all_aux_values: Vec<Vec<EF>>,
    /// Constraint folding challenge alpha.
    pub alpha: EF,
    /// AIR accumulation challenge beta.
    pub beta: EF,
    /// Quotient polynomial commitment.
    pub quotient_commit: L::Commitment,
    /// Out-of-domain evaluation point z.
    pub z: EF,
    /// PCS sub-proof (DEEP evals, FRI rounds, query openings).
    pub pcs_proof: PcsProof<EF, L>,
}

impl<EF, L> StarkProof<EF, L>
where
    L: Lmcs,
    L::F: TwoAdicField,
    EF: ExtensionField<L::F>,
{
    /// Per-AIR log₂ trace heights in instance order (matches
    /// [`Statement::airs`] position-for-position).
    pub fn log_trace_heights(&self) -> &[u8] {
        self.trace_order.log_heights()
    }

    /// The proof's AIR ordering: position `j` holds the instance index of the
    /// AIR at proof position `j`. Derived deterministically from the heights.
    pub fn air_order(&self) -> Vec<u8> {
        self.trace_order.instance_indices().to_vec()
    }

    /// Parse a STARK transcript from proof data and a challenger.
    ///
    /// Mirrors steps 0–9 of [`verify`](crate::verifier::verify):
    /// 0. Reconstruct + validate AIR ordering from heights, absorb statement-owned inputs, then
    ///    observe the instance count and log trace heights in instance order
    /// 1. Receive main trace commitment
    /// 2. Sample randomness for auxiliary traces
    /// 3. Receive auxiliary trace commitment
    /// 4. Receive aux values (per AIR instance, in proof order)
    /// 5. Sample constraint folding alpha and accumulation beta
    /// 6. Receive quotient commitment
    /// 7. Sample OOD point z
    /// 8. Build commitment widths for PCS
    /// 9. Parse PCS sub-proof via `PcsProof::read_from_channel`
    ///
    /// Does **not** verify constraints or check the quotient identity.
    /// Finalizes the transcript and returns the digest alongside the parsed view.
    #[allow(clippy::type_complexity)]
    pub fn from_data<MA, SC>(
        config: &SC,
        statement: &Statement<L::F, EF, MA>,
        data: &StarkProofData<L::F, EF, SC>,
        mut challenger: SC::Challenger,
    ) -> Result<(Self, StarkDigest<L::F, EF, SC>), VerifierError>
    where
        MA: MultiAir<L::F, EF>,
        SC: StarkConfig<L::F, EF, Lmcs = L>,
    {
        // Shape well-formedness and per-AIR periodic-height feasibility, both
        // against the (untrusted) proof heights — catches malicious
        // `log_h` > usize::BITS and infeasible heights before any later use.
        let trace_order = TraceOrder::from_log_heights::<L::F, EF, _>(
            statement.airs(),
            data.log_trace_heights.clone(),
        )?;
        let air_refs: Vec<&MA::Air> = statement.airs().iter().collect();
        let proof_ordered_airs = trace_order.to_proof_order(&air_refs);

        let log_blowup = config.pcs().log_blowup();
        let log_max_trace_height = trace_order.max_log_height();
        let max_lde_domain = LiftedDomain::<L::F>::try_canonical(log_max_trace_height, log_blowup)?;
        // `Statement::observe` absorbs statement-owned inputs. The protocol then
        // binds the proof's instance count and log trace heights in instance order.
        statement.observe(&mut challenger, trace_order.log_heights());
        trace_order.observe_shape::<L::F, _>(&mut challenger);

        let mut channel = VerifierTranscript::from_data(challenger, &data.transcript);

        let alignment = config.lmcs().alignment();

        // Infer quotient degree from symbolic AIR analysis (max across all AIRs)
        let max_log_quotient_degree = proof_ordered_airs
            .iter()
            .map(|&air| log_quotient_degree::<L::F, EF, _>(air))
            .max()
            .expect("TraceOrder construction rejects empty AIR sets");
        if max_log_quotient_degree > log_blowup {
            return Err(DomainError::ConstraintDegreeTooHigh {
                log_quotient: max_log_quotient_degree,
                log_blowup,
            }
            .into());
        }
        let quotient_degree = 1usize << max_log_quotient_degree as usize;

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

        // 4. Receive aux values from the transcript (one EF element per aux value, per instance).
        let all_aux_values: Vec<Vec<EF>> = proof_ordered_airs
            .iter()
            .map(|air| {
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
        let z: EF = max_lde_domain.sample_ood_point(&mut channel);
        let h = max_lde_domain.trace_subgroup().generator();
        let z_next = z * h;

        // 8. Build commitment widths for PCS.
        //
        // The LMCS commits to rows padded to `alignment` boundary, so DEEP evals and
        // batch openings are stored at aligned widths in the transcript. We must use
        // aligned widths here to parse the transcript correctly.
        // (The verifier's `verify_aligned` does the same alignment internally, then
        // truncates the returned evals back to original widths for constraint checking.)
        let main_widths: Vec<usize> = proof_ordered_airs
            .iter()
            .map(|air| aligned_len(air.width(), alignment))
            .collect();
        let quotient_width = aligned_len(quotient_degree * EF::DIMENSION, alignment);

        let aux_widths: Vec<usize> = proof_ordered_airs
            .iter()
            .map(|air| aligned_len(air.aux_width() * EF::DIMENSION, alignment))
            .collect();

        let commitments = vec![
            (main_commit.clone(), main_widths),
            (aux_commit.clone(), aux_widths),
            (quotient_commit.clone(), vec![quotient_width]),
        ];

        // 9. Parse PCS sub-proof
        let pcs_proof = PcsProof::read_from_channel::<_, 2>(
            config.pcs(),
            config.lmcs(),
            &commitments,
            &max_lde_domain,
            [z, z_next],
            &mut channel,
        )?;

        // 10. Finalize transcript and extract digest
        let digest = channel.finalize()?;

        Ok((
            Self {
                trace_order,
                main_commit,
                randomness,
                aux_commit,
                all_aux_values,
                alpha,
                beta,
                quotient_commit,
                z,
                pcs_proof,
            },
            digest,
        ))
    }
}
