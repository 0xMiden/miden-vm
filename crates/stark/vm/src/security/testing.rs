//! Reference reports and synthetic Eidos inputs used by recursive-verifier tests.
use miden_air::vm::{
    config,
    security::{
        AIR_SHAPE, COMMITMENT_ALIGNMENT, CORE_BOUNDARY_LOOKUP_TERMS, LOOKUP_POW_BITS, LOOKUP_SHAPE,
        OOD_POW_BITS,
    },
};
use miden_core::proof::HashFunction;
use miden_stark::security::{
    CHALLENGE_FIELD_BITS, InstanceShape, ProtocolParams, SecurityReport, apply_lookup_correction,
    lookup_boundary_correction, security_report_with_hash,
};

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
    let protocol = ProtocolParams {
        log_blowup: config::LOG_BLOWUP as u32,
        log_folding_arity: config::LOG_FOLDING_ARITY as u32,
        num_queries,
        query_pow_bits,
        ood_pow_bits: OOD_POW_BITS,
        deep_pow_bits,
        folding_pow_bits,
        lookup_pow_bits: LOOKUP_POW_BITS,
    };
    super::mvm_security_parameters_from_protocol(
        protocol,
        u32::from(config::pcs_params().log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    )
    .conjectured_security_level()
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
    let instance = InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: hash_fn.collision_resistance(),
    };
    let report = security_report_with_hash(params, &instance, &AIR_SHAPE, hash_fn);
    let correction = lookup_boundary_correction(
        CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
        LOOKUP_SHAPE.fractions_per_row,
        log_max_height,
    );
    apply_lookup_correction(report, correction)
}
