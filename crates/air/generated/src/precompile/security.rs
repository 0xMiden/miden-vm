//! Canonical security API backed by generated relation geometry and source-owned policy.
use crate::vm::security::{COMMITMENT_ALIGNMENT, EIDOS_CHALLENGE_SAMPLE_BITS};
use miden_air_source::precompile::security as source;
use miden_core::{deferred::PvmAirVariant, proof::HashFunction};
use miden_stark::{pcs::PcsParams, security::fixed};
pub use source::*;

/// Security shape of the full canonical relation at the recursive verifier's alignment.
pub const AIR_SHAPE: AirShape = shape(COMMITMENT_ALIGNMENT);
pub const LOOKUP_SHAPE: LookupShape =
    super::geometry(&super::Air::all(), COMMITMENT_ALIGNMENT).lookup;

const fn shape(alignment: usize) -> AirShape {
    super::geometry(&super::Air::all(), alignment).air_shape()
}

/// DEEP terms include each separately padded matrix, the quotient and the two OOD points.
pub const fn num_deep_terms(alignment: usize) -> u32 {
    super::geometry(&super::Air::all(), alignment).num_deep_terms()
}

/// Lookup root-count coefficient, in Q16 bits.
pub const LOOKUP_COEFFICIENT: u64 = fixed::ceil_log2(
    (LOOKUP_SHAPE.max_message_width as u64 + 2) * LOOKUP_SHAPE.fractions_per_row as u64,
);
/// Composition root-count coefficient, in Q16 bits.
pub const COMPOSITION_COEFFICIENT: u64 =
    fixed::ceil_log2(AIR_SHAPE.num_composed_constraints as u64);
/// Q16 upper bound on the log2 of the out-of-domain round's error coefficient.
///
/// The round's error size is `max(d * (H + combo - 1) + (H - 1), (c + 1) * H + combo - 1)` for a
/// trace height `H`, maximum constraint degree `d`, out-of-domain point count `combo`, and
/// quotient chunk count `c <= d`. At `combo = 2` that is at most `(d + 1) * H + (d - 1)`, which
/// `(d + 2) * H` bounds for every trace height at or above `d - 1`. Dividing out `H` leaves this
/// height-independent coefficient, so `OOD_BASE - log_max_height` stays a lower bound on the
/// round.
pub const OOD_COEFFICIENT: u64 =
    fixed::ceil_log2(AIR_SHAPE.max_constraint_degree as u64 + AIR_SHAPE.max_combo as u64);
/// DEEP root-count coefficient, in Q16 bits.
pub const DEEP_COEFFICIENT: u64 = fixed::ceil_log2(match AIR_SHAPE.num_deep_terms {
    Some(terms) => terms as u64,
    None => 0,
});
pub const LOOKUP_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - LOOKUP_COEFFICIENT;
pub const COMPOSITION_TERM: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - COMPOSITION_COEFFICIENT;
pub const OOD_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - OOD_COEFFICIENT;
pub const DEEP_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - DEEP_COEFFICIENT;

/// Builds PVM security parameters from values obtained during proof verification.
///
/// `log_max_height` and `alignment` must come from successful STARK verification, and
/// `hash_fn` from the configuration used to verify the proof, including its challenger.
pub fn proof_security_parameters(
    pcs_params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> ProofSecurityParameters {
    source::proof_security_parameters_with_shape(
        pcs_params,
        log_max_height,
        shape(alignment),
        hash_fn,
    )
}

/// Computes an Eidos chiplet-stack proof's conjectured security level, in bits.
pub fn conjectured_security_level(params: &PcsParams, log_max_height: u32) -> u32 {
    source::conjectured_security_level_with_shape(
        params,
        log_max_height,
        shape(COMMITMENT_ALIGNMENT),
    )
}

/// Computes a chiplet-stack proof's conjectured security level, in bits, for a proof committed
/// under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. [`conjectured_security_level`] is exact only at the Eidos preset's
/// alignment [`COMMITMENT_ALIGNMENT`]; verification calls this instead for every hash function, so
/// a proof committed under a different LMCS (Blake3, alignment 1; Keccak, alignment 17) is graded
/// under its own DEEP term count and collision-resistance cap rather than the Eidos ones.
pub fn conjectured_security_level_for_alignment(
    params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> u32 {
    source::conjectured_security_level_for_alignment_with_shape(
        params,
        log_max_height,
        shape(alignment),
        hash_fn,
    )
}

/// Computes an Eidos chiplet-stack proof's conjectured security level, per protocol round.
///
/// `log_max_height` is the largest chiplet trace height bound by the proof transcript. The lookup
/// term includes the additional fractions added by the fixed `UintVal` and `EcGroup`
/// boundary messages.
///
/// The recursive verifier admits only 7..=150 queries, 0..=31 query/DEEP/folding grinding bits,
/// fixed zero lookup grinding, and a maximum log trace height in `16..=29`. This native function
/// also accepts configurations outside that domain; such inputs are not part of the recursive
/// estimator's contract.
pub fn security_report(params: &ProtocolParams, log_max_height: u32) -> SecurityReport {
    source::security_report_with_shape(params, log_max_height, shape(COMMITMENT_ALIGNMENT))
}

/// Security parameters for the relation authenticated by the selected transcript.
pub fn proof_security_parameters_for(
    pcs_params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
    hash_fn: HashFunction,
    variant: PvmAirVariant,
) -> ProofSecurityParameters {
    let airs: alloc::vec::Vec<_> =
        super::Air::all().into_iter().filter(|air| air.is_in_variant(variant)).collect();
    source::proof_security_parameters_with_shape(
        pcs_params,
        log_max_height,
        super::geometry(&airs, alignment).air_shape(),
        hash_fn,
    )
}
