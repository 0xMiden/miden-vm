//! Canonical security API backed by generated relation geometry and source-owned policy.
use miden_air_source::vm::security as source;
use miden_core::proof::HashFunction;
use miden_stark::pcs::PcsParams;
pub use source::*;

/// Security shape of the full canonical relation at the recursive verifier's alignment.
pub const AIR_SHAPE: AirShape = shape(COMMITMENT_ALIGNMENT);
pub const LOOKUP_SHAPE: LookupShape = super::geometry(&super::AIRS, COMMITMENT_ALIGNMENT).lookup;

const fn shape(alignment: usize) -> AirShape {
    super::geometry(&super::AIRS, alignment).air_shape()
}

/// DEEP terms include each separately padded matrix, the quotient and the two OOD points.
pub const fn num_deep_terms(alignment: usize) -> u32 {
    super::geometry(&super::AIRS, alignment).num_deep_terms()
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

/// Builds MVM security parameters from values obtained during proof verification.
///
/// `log_max_height` and `alignment` must come from successful STARK verification,
/// `num_kernel_procedures` from the authenticated execution claim, and `hash_fn`
/// from the configuration used to verify the proof, including its challenger.
pub fn proof_security_parameters(
    pcs_params: &PcsParams,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> ProofSecurityParameters {
    proof_security_parameters_with_shape(
        pcs_params,
        log_max_height,
        num_kernel_procedures,
        shape(alignment),
        hash_fn,
    )
}

/// Computes an Eidos Miden VM proof's conjectured security level, in whole bits.
///
/// The Fiat-Shamir transcript binds the PCS parameters and AIR log heights. The authenticated
/// kernel witness determines the kernel procedure count. The remaining inputs are fixed by the
/// deployed AIR and commitment configuration. The result therefore describes the proof and claim
/// that were verified rather than an independently supplied parameter preset.
///
/// Mirrored bit-for-bit by the common MASM estimator when supplied with the MVM descriptor. The
/// recursive verifier admits only 7..=150 queries, 0..=31 query/DEEP/folding grinding bits, fixed
/// zero lookup grinding, log trace height in `6..=29`, and 0..=255 kernel procedures. This function
/// also accepts configurations outside that domain; such inputs are not part of the recursive
/// estimator's contract.
pub fn conjectured_security_level(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
) -> u32 {
    conjectured_security_level_with_shape(
        num_queries,
        query_pow_bits,
        deep_pow_bits,
        folding_pow_bits,
        log_max_height,
        num_kernel_procedures,
        shape(COMMITMENT_ALIGNMENT),
    )
}

/// Computes a deployed Miden VM proof's conjectured security level, in whole bits, for a proof
/// committed under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. Not mirrored in MASM: the recursive verifier accepts only Eidos
/// proofs, which `conjectured_security_level` computes at alignment
/// [`COMMITMENT_ALIGNMENT`] (and this function is identical at that alignment, since
/// `num_deep_terms(COMMITMENT_ALIGNMENT)` equals `AIR_SHAPE.num_deep_terms` —
/// `num_deep_terms_matches_the_pinned_alignment` checks it). The native verifier calls this for
/// every hash function, including the non-algebraic ones the recursive verifier never sees, and
/// supplies the hash configuration to select both the collision bound and the sampling support.
pub fn conjectured_security_level_for_alignment(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> u32 {
    conjectured_security_level_for_alignment_with_shape(
        num_queries,
        query_pow_bits,
        deep_pow_bits,
        folding_pow_bits,
        log_max_height,
        num_kernel_procedures,
        shape(alignment),
        hash_fn,
    )
}

/// Computes the conjectured security level of a Miden VM statement proof, for each protocol
/// round.
///
/// `log_max_height` is the largest AIR trace height in the proof; the Fiat-Shamir transcript binds
/// every AIR's log height, so a prover cannot understate it to inflate the reported level.
/// `hash_fn` selects the commitment collision bound and challenger sampling support.
/// `num_kernel_procedures` is the proof's kernel procedure count, transcript-bound through the
/// kernel witness.
pub fn security_report(
    params: &ProtocolParams,
    log_max_height: u32,
    hash_fn: HashFunction,
    num_kernel_procedures: u32,
) -> SecurityReport {
    security_report_with_shape(
        params,
        log_max_height,
        hash_fn,
        num_kernel_procedures,
        shape(COMMITMENT_ALIGNMENT),
    )
}
