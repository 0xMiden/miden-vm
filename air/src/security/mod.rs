//! Conjectured security level computation for the Miden VM STARK configuration.
//!
//! The AIR shape entering the security calculation is stored in [`AIR_SHAPE`], allowing the MASM
//! estimator to use it without evaluating the AIRs symbolically. [`derive_air_shape`] performs
//! that evaluation in Rust, and `air_shape_matches_symbolic` checks the stored value against it.
//!
//! The round budget itself is relation-generic and lives in [`model`], which the precompile
//! chiplet stack instantiates with its own AIR set and shape.

pub mod model;

use miden_crypto::stark::pcs::PcsParams;
use p3_security::budget::{AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport};

pub use self::model::{
    CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, COMMITMENT_ALIGNMENT, FIXED_POINT_FRACTIONAL_BITS,
    FIXED_POINT_ONE, LOG2_E, LOOKUP_POW_BITS, SECURITY_CAP, protocol_params,
};
use crate::{AIRS, MidenAir, config, constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH};

/// Security parameters of a verified Miden STARK proof.
///
/// Native MVM and PVM verifiers return these parameters after deriving them from the proof, the
/// commitment scheme used to verify it, and the AIR relation selected by the verifier. Callers
/// pass the returned value to a security estimator and apply their own acceptance policy.
/// Constructing this type directly does not authenticate its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSecurityParameters {
    /// Protocol parameters bound by the proof transcript.
    pub protocol_params: ProtocolParams,
    /// Log2 of the configured final FRI polynomial degree.
    pub log_final_degree: u32,
    /// Instance shape derived from the proof and its commitment scheme.
    pub instance_shape: InstanceShape,
    /// Security-relevant shape of the AIR relation and commitment scheme.
    pub air_shape: AirShape,
    /// Number of out-of-domain points opened per committed column.
    pub num_ood_points: u32,
    /// Lookup fractions consumed once per proof in addition to the per-row fractions.
    pub num_lookup_boundary_terms: u32,
}

impl ProofSecurityParameters {
    /// Computes the conjectured security report for the verified proof.
    ///
    /// The same estimator handles MVM and PVM proofs because the parameters include the protocol,
    /// instance, and AIR shapes. Callers must use parameters returned by the verifier that
    /// authenticated the proof rather than values assembled independently.
    pub fn conjectured_security_report(&self) -> SecurityReport {
        model::security_report(
            &self.protocol_params,
            &self.instance_shape,
            &self.air_shape,
            self.num_lookup_boundary_terms,
        )
    }

    /// Returns the conjectured security level for the verified proof.
    pub fn conjectured_security_level(&self) -> u32 {
        self.conjectured_security_report().security_level()
    }
}

// MIDEN VM AIR SHAPE
// ================================================================================================

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = model::NUM_OOD_POINTS;

/// Shape of the Miden VM multi-AIR statement used by the security estimator.
///
/// This is stored rather than derived during verification. `air_shape_matches_symbolic` checks it
/// against the shape obtained by symbolically evaluating the AIRs.
pub const AIR_SHAPE: AirShape = AirShape {
    num_composed_constraints: 427,
    max_constraint_degree: 9,
    num_deep_terms: Some(138),
    lookup: LookupShape {
        fractions_per_row: 28,
        max_message_width: 16,
    },
};

/// Computes the AIR shape by symbolically evaluating every AIR in the statement.
///
/// Tests compare [`AIR_SHAPE`] with this result. The symbolic pass allocates and evaluates every
/// AIR, so verifiers use the checked constant instead of calling this function.
pub fn derive_air_shape() -> AirShape {
    model::derive_air_shape(
        &AIRS,
        MIDEN_MAX_MESSAGE_WIDTH as u32,
        |air| MidenAir::column_shape(*air).iter().sum(),
        COMMITMENT_ALIGNMENT,
    )
}

/// Number of DEEP-quotient batching terms for a commitment scheme with the given column
/// alignment, holding every other AIR shape input fixed at [`AIR_SHAPE`]'s stored values.
///
/// A native verifier computing the security level of a proof committed under a different LMCS
/// (Blake3, alignment 1; Keccak, alignment 17) calls this instead of using the alignment-8
/// [`AIR_SHAPE`], which is fixed for the Poseidon2-only recursive verifier.
pub fn num_deep_terms(alignment: usize) -> u32 {
    model::num_deep_terms(&AIRS, AIR_SHAPE.max_constraint_degree as usize, alignment)
}

// SECURITY MODEL CONSTANTS
// ================================================================================================
//
// Each value instantiates the corresponding formula in [`model`] at the Miden VM's stored shape
// and FRI configuration. `derived_security_constants_match_snapshot` checks them against a fixed
// numeric snapshot.

/// Conjectured security contributed per FRI query, in fixed point.
pub const BITS_PER_QUERY: u64 = model::bits_per_query(config::LOG_BLOWUP as u32);

/// Q16 upper bound on the log2 of the lookup round's error coefficient.
pub const LOOKUP_COEFFICIENT: u64 = model::lookup_coefficient(&AIR_SHAPE);

/// Q16 upper bound on the log2 of the constraint-composition round's error coefficient.
pub const COMPOSITION_COEFFICIENT: u64 = model::composition_coefficient(&AIR_SHAPE);

/// Q16 upper bound on the log2 of the out-of-domain round's error coefficient.
pub const OOD_COEFFICIENT: u64 = model::ood_coefficient(&AIR_SHAPE);

/// Q16 upper bound on the log2 of the DEEP round's error coefficient.
pub const DEEP_COEFFICIENT: u64 = model::deep_coefficient(&AIR_SHAPE);

/// Q16 upper bound on the log2 of the FRI folding round's error coefficient.
pub const FOLDING_COEFFICIENT: u64 = model::folding_coefficient(config::LOG_FOLDING_ARITY as u32);

/// Challenge-field bound less the lookup round's coefficient, in fixed point.
pub const LOOKUP_BASE: u64 = model::lookup_base(&AIR_SHAPE);

/// Challenge-field bound less the constraint-composition round's coefficient.
pub const COMPOSITION_TERM: u64 = model::composition_term(&AIR_SHAPE);

/// Challenge-field bound less the out-of-domain round's coefficient.
pub const OOD_BASE: u64 = model::ood_base(&AIR_SHAPE);

/// Challenge-field bound less the DEEP round's coefficient, in fixed point.
pub const DEEP_BASE: u64 = model::deep_base(&AIR_SHAPE);

/// Challenge-field bound less the FRI folding round's coefficient and fixed blowup.
pub const FOLDING_BASE: u64 =
    model::folding_base(config::LOG_BLOWUP as u32, config::LOG_FOLDING_ARITY as u32);

/// Number of lookup fractions `emit_core_boundary` emits unconditionally: the block-hash seed and
/// the two log-deferred-root terminals. Matches `sys::vm::mod.masm`'s
/// `CORE_BOUNDARY_LOOKUP_TERMS`.
pub const CORE_BOUNDARY_LOOKUP_TERMS: u32 = 3;

// SECURITY LEVEL
// ================================================================================================

/// Builds MVM security parameters from values obtained during proof verification.
///
/// `log_max_height` and `alignment` must come from successful STARK verification,
/// `num_kernel_procedures` from the authenticated execution claim, and `collision_resistance`
/// from the commitment hash used to verify the proof.
pub fn proof_security_parameters(
    pcs_params: &PcsParams,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
    collision_resistance: u32,
) -> ProofSecurityParameters {
    mvm_security_parameters_from_protocol(
        protocol_params(pcs_params),
        u32::from(pcs_params.log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        alignment,
        collision_resistance,
    )
}

fn mvm_security_parameters_from_protocol(
    protocol_params: ProtocolParams,
    log_final_degree: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
    collision_resistance: u32,
) -> ProofSecurityParameters {
    ProofSecurityParameters {
        protocol_params,
        log_final_degree,
        instance_shape: InstanceShape {
            log_max_height,
            field_bits: CHALLENGE_FIELD_BITS,
            collision_resistance,
        },
        air_shape: AirShape {
            num_deep_terms: Some(num_deep_terms(alignment)),
            ..AIR_SHAPE
        },
        num_ood_points: NUM_OOD_POINTS,
        num_lookup_boundary_terms: CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
    }
}

/// Computes a Poseidon2 Miden VM proof's conjectured security level, in whole bits.
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
    conjectured_security_level_for_alignment(
        num_queries,
        query_pow_bits,
        deep_pow_bits,
        folding_pow_bits,
        log_max_height,
        num_kernel_procedures,
        COMMITMENT_ALIGNMENT,
    )
}

/// Computes a deployed Miden VM proof's conjectured security level, in whole bits, for a proof
/// committed under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. Not mirrored in MASM: the recursive verifier accepts only Poseidon2
/// proofs, which `conjectured_security_level` computes at alignment
/// [`COMMITMENT_ALIGNMENT`] (and this function is identical at that alignment, since
/// `num_deep_terms(COMMITMENT_ALIGNMENT)` equals `AIR_SHAPE.num_deep_terms` —
/// `num_deep_terms_matches_the_pinned_alignment` checks it). This helper assumes the commitment
/// scheme has [`COLLISION_RESISTANCE`] bits; verification returns [`ProofSecurityParameters`] built
/// with the collision resistance of the proof's actual hash function.
pub fn conjectured_security_level_for_alignment(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
) -> u32 {
    let protocol = ProtocolParams {
        log_blowup: config::LOG_BLOWUP as u32,
        log_folding_arity: config::LOG_FOLDING_ARITY as u32,
        num_queries,
        query_pow_bits,
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
        COLLISION_RESISTANCE,
    )
    .conjectured_security_level()
}

/// Computes the conjectured security level of a Miden VM statement proof, for each protocol
/// round.
///
/// `log_max_height` is the largest AIR trace height in the proof; the Fiat-Shamir transcript binds
/// every AIR's log height, so a prover cannot understate it to inflate the reported level.
/// `collision_resistance` is that of the commitment hash, in bits. `num_kernel_procedures` is the
/// proof's kernel procedure count, transcript-bound through the kernel witness.
pub fn security_report(
    params: &ProtocolParams,
    log_max_height: u32,
    collision_resistance: u32,
    num_kernel_procedures: u32,
) -> SecurityReport {
    let instance = InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance,
    };
    model::security_report(
        params,
        &instance,
        &AIR_SHAPE,
        CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
    )
}

#[cfg(test)]
mod tests {
    use p3_security::budget::report::LOOKUP_LABEL;

    use super::*;

    /// Checks that [`AIR_SHAPE`] matches the current AIRs. A stale shape can make the reported
    /// security level differ from the level implied by the relation being verified.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// `num_deep_terms` at [`COMMITMENT_ALIGNMENT`] (algebraic sponges) must reproduce
    /// [`AIR_SHAPE`]'s stored `num_deep_terms` exactly, so
    /// `conjectured_security_level_for_alignment` computes the same level for a Poseidon2 proof
    /// as `conjectured_security_level`.
    ///
    /// The other two are the deployed non-algebraic configurations' actual alignments: Blake3's
    /// `ChainingHasher` (1, no padding) and Keccak's `SerializingStatefulSponge` over its 17-word
    /// rate (`lcm(8, 17·8)/8 = 17`).
    #[test]
    fn num_deep_terms_matches_the_pinned_alignment() {
        assert_eq!(num_deep_terms(COMMITMENT_ALIGNMENT), AIR_SHAPE.num_deep_terms.unwrap());
        assert_eq!(num_deep_terms(1), 123, "Blake3 (alignment 1) DEEP term count moved");
        assert_eq!(num_deep_terms(8), 138, "algebraic (alignment 8) DEEP term count moved");
        assert_eq!(num_deep_terms(17), 172, "Keccak (alignment 17) DEEP term count moved");
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
            COLLISION_RESISTANCE,
        );

        assert_eq!(
            security_parameters.conjectured_security_report(),
            security_report(&expected_protocol_params, 22, COLLISION_RESISTANCE, 255)
        );
        assert_eq!(security_parameters.log_final_degree, u32::from(pcs_params.log_final_degree()));
        assert_eq!(security_parameters.num_ood_points, NUM_OOD_POINTS);
    }

    /// The deployed preset's computed security level, per trace height, with the round that
    /// determines it at each. The preset was calibrated against the query phase alone; this test
    /// checks what it actually computes once the trace-height-dependent rounds are counted, so any
    /// parameter or AIR change that moves the real figure is visible rather than absorbed into an
    /// unchanged constant.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&config::pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (20, 96, p3_security::budget::report::QUERY_LABEL),
            (22, 96, p3_security::budget::report::QUERY_LABEL),
            (24, 95, LOOKUP_LABEL),
            (29, 90, LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height, 128, 0);
            assert_eq!(
                report.security_level(),
                expected_level,
                "level moved at log height {log_height}"
            );
            assert_eq!(
                report.binding_term().label,
                expected_binding,
                "binding round moved at log height {log_height}"
            );
        }
    }

    /// Every derived Rust security constant, checked against a fixed numeric snapshot.
    ///
    /// This test does not read the MASM source; it checks that the Rust-side values below have not
    /// silently drifted from the reviewed snapshot.
    #[test]
    fn derived_security_constants_match_snapshot() {
        const FP_SHIFT: u32 = 16;
        const FP_ONE: u64 = 65_536;
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_388_606;
        const LOOKUP_BASE_FP: u64 = 7_800_270;
        const COMPOSITION_TERM_FP: u64 = 7_815_946;
        const OOD_BASE_FP: u64 = 8_170_900;
        const DEEP_BASE_FP: u64 = 7_922_741;
        const FOLDING_BASE_FP: u64 = 8_022_589;
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
            "Lifted STARK does not currently support lookup grinding"
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
                [7_406_895, 7_815_946, 7_777_684, 8_388_606, 7_891_517, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_489_549, 7_815_946, 6_860_180, 8_388_606, 6_974_013, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 23),
                [6_292_941, 7_815_946, 6_663_572, 8_388_606, 6_777_405, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 29),
                [5_899_725, 7_815_946, 6_270_356, 8_388_606, 6_384_189, 6_335_399, 8_388_606],
                90,
            ),
            (
                (7, 0, 0, 0, 20),
                [6_489_549, 7_815_946, 6_860_180, 7_922_741, 6_711_869, 1_353_667, 8_388_606],
                20,
            ),
            (
                (150, 31, 31, 31, 29),
                [5_899_725, 7_815_946, 6_270_356, 8_388_606, 8_153_661, 8_388_606, 8_388_606],
                90,
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
            let report = security_report(&params, log_height, COLLISION_RESISTANCE, 0);

            assert_eq!(
                (*report.terms()).map(|term| term.bits),
                rounds,
                "round bits moved at {params:?}, log height {log_height}"
            );
            assert_eq!(
                report.security_level(),
                level,
                "level moved at {params:?}, log height {log_height}"
            );
        }
    }

    /// The lookup round overtakes the query phase as the bottleneck somewhere in the low twenties,
    /// which is what makes the computed security level height-dependent at all. This test checks
    /// the crossover height against a fixed value: below it the preset reaches its design target,
    /// above it it does not.
    #[test]
    fn lookup_round_overtakes_the_query_phase_in_the_low_twenties() {
        let params = protocol_params(&config::pcs_params());
        let crossover = (6..=30)
            .find(|&log_height| {
                security_report(&params, log_height, 128, 0).binding_term().label == LOOKUP_LABEL
            })
            .expect("the lookup round must bind at some supported height");

        assert_eq!(crossover, 23, "lookup/query crossover moved");
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
        let bare = lookup_bits(security_report(&params, 6, 128, 0));
        let full_kernel = lookup_bits(security_report(&params, 6, 128, 255));
        assert!(
            full_kernel < bare,
            "a full kernel witness should lower the lookup round's bound, got {full_kernel} vs \
             {bare}"
        );
    }
}
