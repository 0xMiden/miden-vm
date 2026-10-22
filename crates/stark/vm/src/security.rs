//! Security reports for authenticated VM proofs.
#[cfg(test)]
use miden_air::vm::security::{
    BITS_PER_QUERY, COLLISION_RESISTANCE, COMPOSITION_TERM, DEEP_BASE, FIXED_POINT_FRACTIONAL_BITS,
    FIXED_POINT_ONE, FOLDING_BASE, LOOKUP_BASE, OOD_BASE, SECURITY_CAP,
};
use miden_air::vm::{
    config,
    security::{
        AIR_SHAPE, COMMITMENT_ALIGNMENT, CORE_BOUNDARY_LOOKUP_TERMS, LOOKUP_POW_BITS, LOOKUP_SHAPE,
        OOD_POW_BITS, RAW_WIDTHS,
    },
};
use miden_air_definitions::shared::geometry::NUM_OOD_POINTS;
#[cfg(test)]
use miden_air_definitions::vm::geometry::derive_air_shape;
use miden_core::proof::HashFunction;
use miden_stark::security::{
    CHALLENGE_FIELD_BITS, apply_lookup_correction, lookup_boundary_correction, protocol_params,
    security_report_with_hash,
};
pub use miden_stark::{
    pcs::PcsParams,
    security::{
        AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams,
        SecurityReport, SecurityTerm,
    },
};
#[cfg(test)]
use p3_security::budget::report::LOOKUP_LABEL;
#[cfg(test)]
use p3_security::budget::report::QUERY_LABEL;

#[cfg(test)]
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// Number of DEEP-quotient batching terms for a commitment scheme with the given column
/// alignment, holding every other AIR shape input fixed at [`miden_air::vm::security::AIR_SHAPE`]'s
/// stored values.
///
/// Only the per-column padding is alignment-dependent, so this recomputes committed column counts
/// from the compiler's stored raw widths and quotient chunk count. A native verifier
/// computing the security level of a proof committed under a different LMCS (Blake3, alignment 1;
/// Keccak, alignment 17) calls this instead of using the alignment-8
/// [`miden_air::vm::security::AIR_SHAPE`], which is fixed for the Eidos-only recursive verifier.
pub fn num_deep_terms(alignment: usize) -> u32 {
    miden_air_definitions::shared::geometry::num_deep_terms_for_widths(
        RAW_WIDTHS,
        AIR_SHAPE.num_quotient_chunks as usize,
        alignment,
    )
}

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
    mvm_security_parameters_from_protocol(
        protocol_params(pcs_params),
        u32::from(pcs_params.log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        alignment,
        hash_fn,
    )
}

fn mvm_security_parameters_from_protocol(
    protocol_params: ProtocolParams,
    log_final_degree: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> ProofSecurityParameters {
    ProofSecurityParameters {
        protocol_params,
        log_final_degree,
        instance_shape: InstanceShape {
            log_max_height,
            field_bits: CHALLENGE_FIELD_BITS,
            collision_resistance: hash_fn.collision_resistance(),
        },
        hash_fn,
        air_shape: AirShape {
            num_deep_terms: Some(num_deep_terms(alignment)),
            ..AIR_SHAPE
        },
        num_ood_points: NUM_OOD_POINTS,
        num_lookup_boundary_terms: CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
    }
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
    mvm_security_parameters_from_protocol(
        protocol,
        u32::from(config::pcs_params().log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    )
    .conjectured_security_level()
}

/// Computes a deployed Miden VM proof's conjectured security level, in whole bits, for a proof
/// committed under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`miden_air::vm::security::AIR_SHAPE`] otherwise. Not mirrored in MASM: the recursive verifier
/// accepts only Eidos proofs, which `conjectured_security_level` computes at alignment
/// [`miden_air::vm::security::COMMITMENT_ALIGNMENT`] (and this function is identical at that
/// alignment, since `num_deep_terms(COMMITMENT_ALIGNMENT)` equals `AIR_SHAPE.num_deep_terms` —
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
    mvm_security_parameters_from_protocol(
        protocol,
        u32::from(config::pcs_params().log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        alignment,
        hash_fn,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Power-of-two error coefficients make the root-counting bounds exact without using the
    /// estimator's logarithm implementation. The collision cap must be applied after sampling.
    #[test]
    fn eidos_root_counts_use_the_sampling_support_before_capping() {
        use p3_security::budget::report::{COMPOSITION_LABEL, DEEP_COMPOSITION_LABEL};

        let params = ProtocolParams {
            num_queries: 150,
            query_pow_bits: 31,
            deep_pow_bits: 0,
            ..protocol_params(&config::pcs_params())
        };
        let air = AirShape {
            num_composed_constraints: 1024,
            num_deep_terms: Some(1024),
            lookup: Some(LookupShape {
                max_message_width: 6,
                fractions_per_row: 128,
            }),
            ..AIR_SHAPE
        };
        let instance = deployed_instance(20);
        let report = security_report_with_hash(&params, &instance, &air, HashFunction::Eidos);
        for (label, bits) in [
            // The lookup coefficient is (6 + 2) * 128 = 2^10, at height 2^20:
            // error <= 2^30 / 2^126 = 2^-96.
            (LOOKUP_LABEL, 96u32),
            // Each batching coefficient is 2^10, so error <= 2^10 / 2^126 = 2^-116.
            (COMPOSITION_LABEL, 116),
            // DEEP batching also pays the LDE height (20 + 3).
            (DEEP_COMPOSITION_LABEL, 93),
        ] {
            assert_eq!(
                report.terms().iter().find(|term| term.label == label).unwrap().bits,
                u64::from(bits) * 65_536,
                "wrong sampling denominator for {label}"
            );
        }

        // A lower commitment-security assumption caps the 116-bit batching bound at 100.
        // Subtracting two bits from an already capped report would incorrectly give 98.
        let capped = security_report_with_hash(
            &params,
            &InstanceShape { collision_resistance: 100, ..instance },
            &air,
            HashFunction::Eidos,
        );
        assert_eq!(
            capped.terms().iter().find(|term| term.label == COMPOSITION_LABEL).unwrap().bits,
            100 * 65_536
        );

        let full_field = p3_security::budget::security_report(&params, &instance, &air);
        assert_eq!(
            report.terms().iter().find(|term| term.label == QUERY_LABEL),
            full_field.terms().iter().find(|term| term.label == QUERY_LABEL),
            "the FRI query rate must retain the ambient field size"
        );
    }

    #[test]
    fn full_field_challengers_preserve_their_security_bounds() {
        let params = protocol_params(&config::pcs_params());
        for hash_fn in [HashFunction::Blake3_256, HashFunction::Keccak] {
            let parameters = proof_security_parameters(&config::pcs_params(), 20, 0, 8, hash_fn);
            assert_eq!(parameters.hash_fn, hash_fn);
            assert_eq!(
                parameters.instance_shape.collision_resistance,
                hash_fn.collision_resistance()
            );
            assert_eq!(
                security_report_with_hash(&params, &parameters.instance_shape, &AIR_SHAPE, hash_fn),
                p3_security::budget::security_report(
                    &params,
                    &parameters.instance_shape,
                    &AIR_SHAPE
                ),
                "full-field sampling changed for {hash_fn:?}"
            );
        }
    }

    /// Checks that [`miden_air::vm::security::AIR_SHAPE`] matches the current AIRs. A stale shape
    /// can make the reported security level differ from the level implied by the relation being
    /// verified.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// `num_deep_terms` at [`miden_air::vm::security::COMMITMENT_ALIGNMENT`] (algebraic sponges)
    /// must reproduce [`miden_air::vm::security::AIR_SHAPE`]'s stored `num_deep_terms` exactly,
    /// so `conjectured_security_level_for_alignment` computes the same level for an Eidos proof
    /// as `conjectured_security_level`.
    ///
    /// The other two are the deployed non-algebraic configurations' actual alignments: Blake3's
    /// `ChainingHasher` (1, no padding) and Keccak's `SerializingStatefulSponge` over its 17-word
    /// rate (`lcm(8, 17·8)/8 = 17`).
    #[test]
    fn num_deep_terms_matches_the_pinned_alignment() {
        assert_eq!(num_deep_terms(COMMITMENT_ALIGNMENT), AIR_SHAPE.num_deep_terms.unwrap());
        assert_eq!(num_deep_terms(1), 274, "unexpected Blake3 (alignment 1) DEEP term count");
        assert_eq!(num_deep_terms(8), 282, "unexpected algebraic (alignment 8) DEEP term count");
        assert_eq!(num_deep_terms(17), 359, "unexpected Keccak (alignment 17) DEEP term count");
    }

    /// Parameters built for an MVM proof must reproduce the independent MVM security report.
    #[test]
    fn proof_security_parameters_match_mvm_security_report() {
        let pcs_params = config::pcs_params();
        let expected_protocol_params = protocol_params(&pcs_params);
        let security_parameters = proof_security_parameters(
            &pcs_params,
            22,
            255,
            COMMITMENT_ALIGNMENT,
            HashFunction::Eidos,
        );

        assert_eq!(
            security_parameters.conjectured_security_report(),
            security_report(&expected_protocol_params, 22, HashFunction::Eidos, 255)
        );
        assert_eq!(security_parameters.log_final_degree, u32::from(pcs_params.log_final_degree()));
        assert_eq!(security_parameters.num_ood_points, NUM_OOD_POINTS);
    }

    /// Pins the deployed preset's computed security level and binding term at representative trace
    /// heights.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&config::pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (18, 96, QUERY_LABEL),
            (20, 95, LOOKUP_LABEL),
            (22, 93, LOOKUP_LABEL),
            (24, 91, LOOKUP_LABEL),
            (29, 86, LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height, HashFunction::Eidos, 0);
            assert_eq!(
                report.security_level(),
                expected_level,
                "unexpected level at log height {log_height}"
            );
            assert_eq!(
                report.binding_term().label,
                expected_binding,
                "unexpected binding round at log height {log_height}"
            );
        }
    }

    /// Every derived Rust security constant, checked against a fixed numeric snapshot.
    ///
    /// This test does not read the MASM source; it checks that the Rust-side values below have not
    /// silently drifted from the pinned snapshot.
    #[test]
    fn derived_security_constants_match_snapshot() {
        const FP_SHIFT: u32 = 16;
        const FP_ONE: u64 = 65_536;
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_257_536;
        const LOOKUP_BASE_FP: u64 = 7_572_335;
        const COMPOSITION_TERM_FP: u64 = 7_647_953;
        const OOD_BASE_FP: u64 = 8_030_818;
        const DEEP_BASE_FP: u64 = 7_724_102;
        const FOLDING_BASE_FP: u64 = 7_891_519;
        const LOOKUP_POW_BITS_SNAPSHOT: u32 = 0;

        assert_eq!(FIXED_POINT_FRACTIONAL_BITS, FP_SHIFT, "FP_SHIFT is stale");
        assert_eq!(FIXED_POINT_ONE, FP_ONE, "FP_ONE is stale");
        assert_eq!(BITS_PER_QUERY, BITS_PER_QUERY_FP, "BITS_PER_QUERY_FP is stale");
        assert_eq!(SECURITY_CAP, SECURITY_CAP_FP, "SECURITY_CAP_FP is stale");
        assert_eq!(LOOKUP_BASE, LOOKUP_BASE_FP, "LOOKUP_BASE_FP is stale");
        assert_eq!(COMPOSITION_TERM, COMPOSITION_TERM_FP, "COMPOSITION_TERM_FP is stale");
        assert_eq!(OOD_BASE, OOD_BASE_FP, "OOD_BASE_FP is stale");
        assert_eq!(DEEP_BASE, DEEP_BASE_FP, "DEEP_BASE_FP is stale");
        assert_eq!(FOLDING_BASE, FOLDING_BASE_FP, "FOLDING_BASE_FP is stale");
        assert_eq!(
            LOOKUP_POW_BITS, LOOKUP_POW_BITS_SNAPSHOT,
            "Lifted STARK does not support lookup grinding"
        );
    }

    /// Checks every round against values computed independently from its documented formula.
    ///
    /// Final-level and monotonicity tests do not expose an error in a term that never determines
    /// the minimum. These vectors therefore include parameters that move the query, DEEP, and
    /// FRI folding terms away from the security cap and make their individual values
    /// observable.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_179_062, 7_647_953, 7_645_438, 7_920_710, 7_760_447, 6_335_399, 8_257_536],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_261_614, 7_647_953, 6_729_109, 7_003_206, 6_842_943, 6_335_399, 8_257_536],
                95,
            ),
            (
                (27, 17, 12, 4, 23),
                [6_065_006, 7_647_953, 6_532_501, 6_806_598, 6_646_335, 6_335_399, 8_257_536],
                92,
            ),
            (
                (27, 17, 12, 4, 29),
                [5_671_790, 7_647_953, 6_139_285, 6_413_382, 6_253_119, 6_335_399, 8_257_536],
                86,
            ),
            (
                (7, 0, 0, 0, 20),
                [6_261_614, 7_647_953, 6_729_109, 6_216_774, 6_580_799, 1_353_667, 8_257_536],
                20,
            ),
            (
                (150, 31, 31, 31, 29),
                [5_671_790, 7_647_953, 6_139_285, 7_658_566, 8_022_591, 8_257_536, 8_257_536],
                86,
            ),
        ];

        let base = protocol_params(&config::pcs_params());
        for &(
            (num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, log_height),
            rounds,
            level,
        ) in VECTORS
        {
            let params = ProtocolParams {
                num_queries,
                query_pow_bits,
                deep_pow_bits,
                folding_pow_bits,
                ..base
            };
            let report = security_report(&params, log_height, HashFunction::Eidos, 0);

            assert_eq!(
                (*report.terms()).map(|term| term.bits),
                rounds,
                "round-bit mismatch at {params:?}, log height {log_height}"
            );
            assert_eq!(
                report.security_level(),
                level,
                "unexpected level at {params:?}, log height {log_height}"
            );
        }
    }

    /// Pins the height at which lookup overtakes the deployed preset's query bound.
    #[test]
    fn lookup_round_overtakes_the_query_phase_at_height_nineteen() {
        let params = protocol_params(&config::pcs_params());
        let crossover = (6..=30)
            .find(|&log_height| {
                security_report(&params, log_height, HashFunction::Eidos, 0)
                    .binding_term()
                    .label
                    == LOOKUP_LABEL
            })
            .expect("the lookup round must bind at some supported height");

        assert_eq!(crossover, 19, "unexpected lookup/query crossover");
    }

    /// A proof with the maximum kernel witness reports a lower lookup-round bound than a bare one
    /// at the same height, since `emit_chiplets_boundary` adds one lookup fraction per kernel
    /// procedure digest on top of the per-row bus terms `AIR_SHAPE` counts.
    #[test]
    fn lookup_boundary_correction_lowers_the_lookup_term_with_a_full_kernel_witness() {
        let lookup_bits = |report: SecurityReport| {
            report.terms().iter().find(|term| term.label == LOOKUP_LABEL).unwrap().bits
        };

        let params = protocol_params(&config::pcs_params());
        let bare = lookup_bits(security_report(&params, 6, HashFunction::Eidos, 0));
        let full_kernel = lookup_bits(security_report(&params, 6, HashFunction::Eidos, 255));
        assert!(
            full_kernel < bare,
            "a full kernel witness should lower the lookup round's bound, got {full_kernel} vs \
             {bare}"
        );
    }
}
