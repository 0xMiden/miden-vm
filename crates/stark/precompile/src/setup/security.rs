//! Conjectured security level computation for the precompile chiplet stack.
//!
//! The chiplet stack proves a different statement from the VM and therefore has its own AIR shape.
//! Both statements use the round-budget formulas in [`p3_security::budget`] and the same challenge
//! field. Their recursive verifiers both use Eidos. Native verification derives alignment and
//! collision resistance from the commitment scheme used for each proof.
//!
//! Production AIR [metadata](miden_air::precompile::protocol::metadata) stores the relation
//! shape used by the security calculation, while
//! `air_shape_matches_symbolic` checks it against the shape obtained from the chiplet AIRs.

use miden_air::precompile::policy::{LOG_BLOWUP, LOG_FOLDING_ARITY};
use miden_core::proof::HashFunction;
use miden_stark::security::{
    CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, COMMITMENT_ALIGNMENT, EIDOS_CHALLENGE_SAMPLE_BITS,
    protocol_params, security_report_with_hash,
};
pub use miden_stark::{
    pcs::PcsParams,
    security::{
        AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams,
        SecurityReport, SecurityTerm,
    },
};
use p3_security::{budget::report::LOOKUP_LABEL, fixed};

/// Number of out-of-domain points opened per committed column.
///
/// The chiplet AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = 2;

/// Shape of the chiplet multi-AIR statement used by the security estimator.
///
/// This stored value must equal the shape returned by
/// `miden_air_source::precompile::geometry::derive_air_shape`.
const AIR_SHAPE: AirShape = miden_air::precompile::protocol::PROTOCOL.air_shape;

/// Lookup shape generated from the authored AIR metadata.
pub const LOOKUP_SHAPE: LookupShape = match AIR_SHAPE.lookup {
    Some(shape) => shape,
    None => panic!("canonical AIR has lookup arguments"),
};

/// Build-compiled security shape of the precompile relation at the given commitment
/// alignment; this does not capture AIRs.
pub fn air_shape_for(alignment: usize) -> AirShape {
    let metadata = miden_air::precompile::protocol::metadata();
    AirShape {
        num_deep_terms: Some(metadata.num_deep_terms(alignment)),
        ..metadata.air_shape
    }
}

// SECURITY MODEL CONSTANTS
// ================================================================================================
//
// The MASM recursive estimator consumes the raw AIR shape. Tests in
// `crates/lib/core/tests/stark/security.rs` compare it with the native calculation over the ranges
// accepted by the recursive verifiers. `derived_security_constants_match_snapshot` checks the
// native constants independently.

/// Fractional bits in the fixed-point representation shared with the MASM estimator.
pub const FIXED_POINT_FRACTIONAL_BITS: u32 = fixed::FRACTIONAL_BITS;

/// Fixed-point representation of one, shared with the MASM estimator.
pub const FIXED_POINT_ONE: u64 = fixed::ONE;

/// Conjectured security contributed per FRI query, in fixed point.
pub const BITS_PER_QUERY: u64 = fixed::bits_per_query(LOG_BLOWUP as u32, CHALLENGE_FIELD_BITS);

/// Upper bound on every reported level, in fixed point.
pub const SECURITY_CAP: u64 = deployed_instance(0).cap();

/// Q16 upper bound on the log2 of the lookup round's error coefficient.
pub const LOOKUP_COEFFICIENT: u64 = fixed::ceil_log2(
    (LOOKUP_SHAPE.max_message_width as u64 + 2) * LOOKUP_SHAPE.fractions_per_row as u64,
);

/// Q16 upper bound on the log2 of the constraint-composition round's error coefficient.
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

/// Q16 upper bound on the log2 of the DEEP round's error coefficient.
pub const DEEP_COEFFICIENT: u64 = fixed::ceil_log2(match AIR_SHAPE.num_deep_terms {
    Some(n) => n as u64,
    None => 0,
});

/// Q16 upper bound on the log2 of the FRI folding round's error coefficient.
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << LOG_FOLDING_ARITY) - 1));

/// Lookup grinding applied before the lookup challenges are sampled.
///
/// Lifted STARK samples them directly after the main-trace commitment and exposes no
/// lookup-grinding parameter.
pub const LOOKUP_POW_BITS: u32 = 0;

/// Number of one-time lookup fractions added at the PVM boundary by the fixed `UintVal` and
/// `EcGroup` messages.
///
/// `fixed_boundary_fraction_count` derives this value from the fixed messages; the descriptor
/// constant must equal the derived count.
pub const FIXED_BOUNDARY_LOOKUP_TERMS: u32 = 19;

/// The Eidos challenge-support bound less the lookup round's coefficient, in fixed point.
pub const LOOKUP_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - LOOKUP_COEFFICIENT;

/// The Eidos challenge-support bound less the constraint-composition round's coefficient, in
/// fixed point.
pub const COMPOSITION_TERM: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - COMPOSITION_COEFFICIENT;

/// The Eidos challenge-support bound less the out-of-domain round's coefficient, in fixed
/// point.
pub const OOD_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - OOD_COEFFICIENT;

/// The Eidos challenge-support bound less the DEEP round's coefficient, in fixed point.
pub const DEEP_BASE: u64 = EIDOS_CHALLENGE_SAMPLE_BITS - DEEP_COEFFICIENT;

/// The Eidos challenge-support bound less the FRI folding round's coefficient and fixed
/// blowup, in fixed point.
///
/// The common MASM estimator uses the whole-bit floor of this value when proving that FRI folding
/// cannot determine the result. Its `FRI_FOLDING_BASE_BITS` constant must equal that floor.
pub const FOLDING_BASE: u64 =
    EIDOS_CHALLENGE_SAMPLE_BITS - FOLDING_COEFFICIENT - fixed::from_bits(LOG_BLOWUP as u32);

/// `log2(e)`, rounded up, in Q16 fixed point.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// The instance shape of a deployed PVM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// Counts the lookup fractions added at the PVM boundary by fixed protocol data: one
/// `UintVal` fraction per fixed uint ([`miden_air_source::precompile::fixed::fixed_uintval_msgs`])
/// and one `EcGroup` fraction per fixed curve group
/// ([`miden_air_source::precompile::fixed::fixed_ecgroup_msgs`]). These are additional to the
/// per-row fractions recorded in the production AIR shape.
fn fixed_boundary_fraction_count() -> u64 {
    (miden_air_source::precompile::fixed::fixed_uintval_msgs().count()
        + miden_air_source::precompile::fixed::fixed_ecgroup_msgs().count()) as u64
}

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// The generic lookup bound counts `fractions_per_row * 2^log_max_height` terms. The PVM boundary
/// also adds one lookup fraction for every fixed `UintVal` and `EcGroup` message, for a total
/// of [`fixed_boundary_fraction_count`] additional terms per proof. These terms are not included
/// in the production AIR shape's per-row count, so their contribution is accounted for separately.
/// Both divisions round up, which keeps the correction conservative.
fn fixed_boundary_correction(log_max_height: u32) -> u64 {
    let numerator = fixed_boundary_fraction_count() * LOG2_E;
    numerator
        .div_ceil(LOOKUP_SHAPE.fractions_per_row as u64)
        .div_ceil(1u64 << log_max_height)
}

/// Applies the contribution from the fixed `UintVal` and `EcGroup` boundary messages to the lookup
/// term.
fn apply_fixed_boundary_correction(report: SecurityReport, log_max_height: u32) -> SecurityReport {
    let correction = fixed_boundary_correction(log_max_height);
    let terms = (*report.terms()).map(|term| {
        if term.label == LOOKUP_LABEL {
            SecurityTerm::new(term.label, term.bits.saturating_sub(correction))
        } else {
            term
        }
    });
    SecurityReport::new(terms)
}

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
    let instance = deployed_instance(log_max_height);
    let report = security_report_with_hash(params, &instance, &AIR_SHAPE, HashFunction::Eidos);
    apply_fixed_boundary_correction(report, log_max_height)
}

/// Computes an Eidos chiplet-stack proof's conjectured security level, in bits.
pub fn conjectured_security_level(params: &PcsParams, log_max_height: u32) -> u32 {
    proof_security_parameters(params, log_max_height, COMMITMENT_ALIGNMENT, HashFunction::Eidos)
        .conjectured_security_level()
}

/// Computes a chiplet-stack proof's conjectured security level, in bits, for a proof committed
/// under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// the production AIR shape otherwise. [`conjectured_security_level`] is exact only at the Eidos
/// preset's alignment [`COMMITMENT_ALIGNMENT`]; verification calls this instead for every hash
/// function, so a proof committed under a different LMCS (Blake3, alignment 1; Keccak, alignment
/// 17) is graded under its own DEEP term count and collision-resistance cap rather than the Eidos
/// ones.
pub fn conjectured_security_level_for_alignment(
    params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
    hash_fn: HashFunction,
) -> u32 {
    proof_security_parameters(params, log_max_height, alignment, hash_fn)
        .conjectured_security_level()
}

#[cfg(test)]
mod tests {
    use miden_air::precompile::policy::precompile_pcs_params;
    use miden_air_source::precompile::geometry::derive_air_shape;
    use p3_security::budget::report::QUERY_LABEL;

    use super::*;

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
    /// `num_deep_terms` exactly, so [`conjectured_security_level_for_alignment`] computes the same
    /// level for an Eidos proof as [`conjectured_security_level`].
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
