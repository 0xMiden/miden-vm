//! Conjectured security level computation for the precompile chiplet stack.
//!
//! The chiplet stack proves a different statement from the VM and therefore has its own AIR shape.
//! Both statements use the round-budget formulas in [`miden_stark::security`] and the same
//! challenge field. Their recursive verifiers both use Eidos. Native verification derives alignment
//! and collision resistance from the commitment scheme used for each proof.
//!
//! Production AIR [metadata](miden_air::precompile::protocol::metadata) stores the relation
//! shape used by the security calculation, while
//! `air_shape_matches_symbolic` checks it against the shape obtained from the chiplet AIRs.

use miden_core::proof::HashFunction;
#[cfg(test)]
use miden_stark::security::COMMITMENT_ALIGNMENT;
use miden_stark::security::{CHALLENGE_FIELD_BITS, protocol_params};
pub use miden_stark::{
    pcs::PcsParams,
    security::{
        AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams,
        SecurityReport, SecurityTerm,
    },
};

/// Number of out-of-domain points opened per committed column.
///
/// The chiplet AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = 2;

/// Shape of the chiplet multi-AIR statement used by the security estimator.
///
/// This stored value must equal the shape returned by
/// `miden_air_source::precompile::geometry::derive_air_shape`.
#[cfg(any(test, feature = "testing"))]
const AIR_SHAPE: AirShape = miden_air::precompile::protocol::PROTOCOL.air_shape;

/// Build-compiled security shape of the precompile relation at the given commitment
/// alignment; this does not capture AIRs.
pub fn air_shape_for(alignment: usize) -> AirShape {
    let metadata = miden_air::precompile::protocol::metadata();
    AirShape {
        num_deep_terms: Some(metadata.num_deep_terms(alignment)),
        ..metadata.air_shape
    }
}

/// Number of one-time lookup fractions added at the PVM boundary by the fixed `UintVal` and
/// `EcGroup` messages.
///
/// `fixed_boundary_fraction_count` derives this value from the fixed messages; the descriptor
/// constant must equal the derived count.
pub const FIXED_BOUNDARY_LOOKUP_TERMS: u32 = 19;

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
    ProofSecurityParameters {
        protocol_params: protocol_params(pcs_params),
        log_final_degree: u32::from(pcs_params.log_final_degree()),
        instance_shape: InstanceShape {
            log_max_height,
            field_bits: CHALLENGE_FIELD_BITS,
            collision_resistance: hash_fn.collision_resistance(),
        },
        hash_fn,
        air_shape: air_shape_for(alignment),
        num_ood_points: NUM_OOD_POINTS,
        num_lookup_boundary_terms: FIXED_BOUNDARY_LOOKUP_TERMS,
    }
}

/// Independent reference estimators and constants for regression tests.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests {
    use miden_air::precompile::policy::precompile_pcs_params;
    use miden_air_source::precompile::geometry::derive_air_shape;
    use p3_security::budget::report::{LOOKUP_LABEL, QUERY_LABEL};

    use super::{testing::*, *};

    /// Checks that the production AIR shape matches the current chiplet AIRs. A stale shape can
    /// make the reported security level differ from the level implied by the relation being
    /// verified.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// Checks that the descriptor's fixed boundary count matches the number of fixed `UintVal` and
    /// `EcGroup` messages.
    #[test]
    fn fixed_boundary_fraction_count_matches_snapshot() {
        assert_eq!(
            fixed_boundary_fraction_count(),
            u64::from(FIXED_BOUNDARY_LOOKUP_TERMS),
            "fixed boundary shape mismatch"
        );
    }

    /// Every derived Rust security constant, checked against a fixed numeric snapshot.
    ///
    /// The recursive estimator consumes the raw PVM shape rather than mirroring these Q16 values.
    #[test]
    fn derived_security_constants_match_snapshot() {
        const FP_SHIFT: u32 = 16;
        const FP_ONE: u64 = 65_536;
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_257_536;
        const LOOKUP_BASE_FP: u64 = 7_437_890;
        const COMPOSITION_TERM_FP: u64 = 7_619_008;
        const OOD_BASE_FP: u64 = 8_073_553;
        const DEEP_BASE_FP: u64 = 7_612_920;
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

    /// [`miden_air::precompile::protocol::ProtocolMetadata::num_deep_terms`] at
    /// [`COMMITMENT_ALIGNMENT`] must reproduce the production AIR shape's stored
    /// `num_deep_terms` exactly, so authenticated security parameters compute the same
    /// level for an Eidos proof as the pinned AIR shape.
    #[test]
    fn num_deep_terms_matches_the_reference_alignment() {
        assert_eq!(
            air_shape_for(COMMITMENT_ALIGNMENT),
            AIR_SHAPE,
            "the build-compiled full-relation shape must equal the pinned AIR_SHAPE"
        );
        let metadata = miden_air::precompile::protocol::metadata();
        assert_eq!(
            metadata.num_deep_terms(COMMITMENT_ALIGNMENT),
            AIR_SHAPE.num_deep_terms.unwrap()
        );
        assert_eq!(
            metadata.num_deep_terms(1),
            861,
            "unexpected Blake3 (alignment 1) DEEP term count"
        );
        assert_eq!(
            metadata.num_deep_terms(17),
            1141,
            "unexpected Keccak (alignment 17) DEEP term count"
        );
    }

    /// Parameters built for a PVM proof must reproduce the independent PVM security report.
    #[test]
    fn proof_security_parameters_match_pvm_security_report() {
        let pcs_params = precompile_pcs_params();
        let expected_protocol_params = protocol_params(&pcs_params);
        let security_parameters =
            proof_security_parameters(&pcs_params, 19, COMMITMENT_ALIGNMENT, HashFunction::Eidos);

        assert_eq!(
            security_parameters.conjectured_security_report(),
            security_report(&expected_protocol_params, 19)
        );
        assert_eq!(security_parameters.log_final_degree, u32::from(pcs_params.log_final_degree()));
        assert_eq!(security_parameters.num_ood_points, NUM_OOD_POINTS);
    }

    /// The deployed preset's computed security level, per trace height, with the round that
    /// determines it at each. The chiplet stack emits far more lookup fractions per row than the
    /// VM does, so its lookup round overtakes the query phase at a much shorter trace.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&precompile_pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (16, 96, QUERY_LABEL),
            (18, 95, LOOKUP_LABEL),
            (20, 93, LOOKUP_LABEL),
            (24, 89, LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height);
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

    /// Checks every round against values computed independently from its documented formula.
    ///
    /// The final level alone would not expose a wrong coefficient in a term that does not determine
    /// the minimum. These vectors therefore check all seven terms separately.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_044_577, 7_619_008, 7_693_931, 7_809_528, 7_760_447, 6_335_399, 8_257_536],
                96,
            ),
            (
                (27, 17, 12, 4, 16),
                [6_389_313, 7_619_008, 7_039_549, 7_154_168, 7_105_087, 6_335_399, 8_257_536],
                96,
            ),
            (
                (27, 17, 12, 4, 19),
                [6_192_705, 7_619_008, 6_842_942, 6_957_560, 6_908_479, 6_335_399, 8_257_536],
                94,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_127_169, 7_619_008, 6_777_406, 6_892_024, 6_842_943, 6_335_399, 8_257_536],
                93,
            ),
            (
                (27, 17, 12, 4, 24),
                [5_865_025, 7_619_008, 6_515_262, 6_629_880, 6_580_799, 6_335_399, 8_257_536],
                89,
            ),
            (
                (7, 0, 0, 0, 16),
                [6_389_313, 7_619_008, 7_039_549, 6_367_736, 6_842_943, 1_353_667, 8_257_536],
                20,
            ),
        ];

        let base = protocol_params(&precompile_pcs_params());
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
            let report = security_report(&params, log_height);

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

    /// Taller traces can never be more secure under the same parameters.
    #[test]
    fn security_is_monotone_in_trace_height() {
        let params = protocol_params(&precompile_pcs_params());
        let mut previous = u32::MAX;
        for log_height in 6..=30u32 {
            let level = security_report(&params, log_height).security_level();
            assert!(level <= previous, "level rose at log height {log_height}");
            previous = level;
        }
    }
}
