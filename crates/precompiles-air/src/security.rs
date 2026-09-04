//! Conjectured security level computation for the precompile chiplet stack.
//!
//! The chiplet stack proves a different statement from the VM and therefore has its own AIR shape.
//! Both statements use the same round-budget formulas and challenge field. Their recursive
//! verifiers both use Poseidon2. Native verification derives alignment and collision resistance
//! from the commitment scheme used for each proof.
//!
//! [`AIR_SHAPE`] stores the relation shape used by the security calculation, while
//! `air_shape_matches_symbolic` checks it against the shape obtained from the chiplet AIRs.

pub use miden_air::security::{
    AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, SecurityReport,
    SecurityTerm,
};
use miden_air::security::{CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, COMMITMENT_ALIGNMENT};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_crypto::stark::pcs::PcsParams;
use miden_lifted_air::{BaseAir, ConstraintCounts, ConstraintDegrees, LiftedAir};
use p3_security::{budget::report::LOOKUP_LABEL, fixed};

use crate::{
    ChipletAir,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir},
    logup::{LookupAir, ProverLookupBuilder},
    primitives::byte_pair_lut::BytePairLutAir,
    relations::MAX_MESSAGE_WIDTH,
    stark_config::{LOG_BLOWUP, LOG_FOLDING_ARITY},
    transcript::{eval::TranscriptEvalAir, poseidon2::Poseidon2Air},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Number of out-of-domain points opened per committed column.
///
/// The chiplet AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = 2;

/// Base field elements per challenge-field element.
const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

/// Shape of the chiplet multi-AIR statement used by the security estimator.
///
/// `air_shape_matches_symbolic` checks this stored value against the current chiplet AIRs.
pub const AIR_SHAPE: AirShape = AirShape {
    num_composed_constraints: 591,
    max_constraint_degree: 5,
    num_deep_terms: Some(770),
    lookup: LookupShape {
        fractions_per_row: 247,
        max_message_width: 18,
    },
};

/// Computes the AIR shape by symbolically evaluating every chiplet AIR.
///
/// Tests compare [`AIR_SHAPE`] with this result. The symbolic pass allocates and evaluates every
/// chiplet AIR, so [`security_report`] uses the checked constant instead of calling this function.
pub fn derive_air_shape() -> AirShape {
    let airs = ChipletAir::all();
    let num_airs = airs.len();

    let mut num_constraints = 0;
    let mut max_constraint_degree = 0;
    let mut num_columns = 0;
    let mut fractions_per_row = 0;

    for air in airs {
        num_constraints += ConstraintCounts::from_air::<Felt, QuadFelt, _>(&air).total();
        max_constraint_degree =
            max_constraint_degree.max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air).max());
        num_columns += column_count(&air, COMMITMENT_ALIGNMENT);
        fractions_per_row += fractions_per_row_of(air);
    }
    num_columns += quotient_column_count(max_constraint_degree, COMMITMENT_ALIGNMENT);

    AirShape {
        // One batching slot per AIR beyond the first sits alongside the constraints themselves:
        // constraints are folded by powers of one challenge and the AIRs by a second, so a
        // single-AIR statement needs no cross-AIR batching challenge.
        num_composed_constraints: (num_constraints + num_airs - 1) as u32,
        max_constraint_degree: max_constraint_degree as u32,
        num_deep_terms: Some(num_columns as u32 + NUM_OOD_POINTS),
        lookup: LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MAX_MESSAGE_WIDTH as u32,
        },
    }
}

/// Number of DEEP-quotient batching terms for a commitment scheme with the given column
/// alignment, holding every other AIR shape input fixed at [`AIR_SHAPE`]'s stored values.
///
/// Only the per-column padding is alignment-dependent, so this recomputes committed column counts
/// from the chiplet AIRs' own width accessors — no symbolic constraint pass — reusing
/// [`AIR_SHAPE`]'s `max_constraint_degree` for the quotient group's chunk count. Native
/// verification of a proof committed under a non-algebraic LMCS (Blake3, alignment 1; Keccak,
/// alignment 17) calls this instead of using the alignment-[`COMMITMENT_ALIGNMENT`] [`AIR_SHAPE`]
/// fixed for the Poseidon2 preset.
pub fn num_deep_terms(alignment: usize) -> u32 {
    let mut num_columns = 0;
    for air in ChipletAir::all() {
        num_columns += column_count(&air, alignment);
    }
    num_columns += quotient_column_count(AIR_SHAPE.max_constraint_degree as usize, alignment);

    num_columns as u32 + NUM_OOD_POINTS
}

/// Committed base columns for one chiplet: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
fn column_count(air: &ChipletAir, alignment: usize) -> usize {
    aligned(BaseAir::<Felt>::preprocessed_width(air), alignment)
        + aligned(BaseAir::<Felt>::width(air), alignment)
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXTENSION_DEGREE, alignment)
}

/// Committed base columns in the quotient group: one chunk per unit of degree above the vanishing
/// polynomial, rounded up to a power of two, committed as a single extension-valued matrix.
fn quotient_column_count(max_constraint_degree: usize, alignment: usize) -> usize {
    let chunks = max_constraint_degree.saturating_sub(1).max(1).next_power_of_two();

    aligned(chunks * EXTENSION_DEGREE, alignment)
}

/// Pads a committed width up to the commitment scheme's column alignment.
///
/// The DEEP reduction batches every element of each opened, alignment-padded row, so padding also
/// contributes batching slots.
fn aligned(width: usize, alignment: usize) -> usize {
    width.next_multiple_of(alignment)
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
    (AIR_SHAPE.lookup.max_message_width as u64 + 2) * AIR_SHAPE.lookup.fractions_per_row as u64,
);

/// Q16 upper bound on the log2 of the constraint-composition round's error coefficient.
pub const COMPOSITION_COEFFICIENT: u64 =
    fixed::ceil_log2(AIR_SHAPE.num_composed_constraints as u64);

/// Q16 upper bound on the log2 of the out-of-domain round's error coefficient.
pub const OOD_COEFFICIENT: u64 = fixed::ceil_log2(AIR_SHAPE.max_constraint_degree as u64 + 1);

/// Q16 upper bound on the log2 of the DEEP round's error coefficient.
pub const DEEP_COEFFICIENT: u64 = fixed::ceil_log2(match AIR_SHAPE.num_deep_terms {
    Some(n) => n as u64,
    None => 0,
});

/// Q16 upper bound on the log2 of the FRI folding round's error coefficient.
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << LOG_FOLDING_ARITY) - 1));

/// Lookup grinding applied before the lookup challenges are sampled.
///
/// Lifted STARK currently samples them directly after the main-trace commitment and exposes no
/// lookup-grinding parameter.
pub const LOOKUP_POW_BITS: u32 = 0;

/// Number of one-time lookup fractions added at the PVM boundary by the fixed `UintVal` and
/// `EcGroup` messages.
///
/// `fixed_boundary_fraction_count` derives this value from the fixed messages. A test below checks
/// that the descriptor constant remains equal to the derived count.
pub const FIXED_BOUNDARY_LOOKUP_TERMS: u32 = 8;

/// The configured challenge-field bound less the lookup round's coefficient, in fixed point.
pub const LOOKUP_BASE: u64 = CHALLENGE_FIELD_BITS - LOOKUP_COEFFICIENT;

/// The configured challenge-field bound less the constraint-composition round's coefficient, in
/// fixed point.
pub const COMPOSITION_TERM: u64 = CHALLENGE_FIELD_BITS - COMPOSITION_COEFFICIENT;

/// The configured challenge-field bound less the out-of-domain round's coefficient, in fixed
/// point.
pub const OOD_BASE: u64 = CHALLENGE_FIELD_BITS - OOD_COEFFICIENT;

/// The configured challenge-field bound less the DEEP round's coefficient, in fixed point.
pub const DEEP_BASE: u64 = CHALLENGE_FIELD_BITS - DEEP_COEFFICIENT;

/// The configured challenge-field bound less the FRI folding round's coefficient and fixed
/// blowup, in fixed point.
///
/// The common MASM estimator uses the whole-bit floor of this value when proving that FRI folding
/// cannot determine the result. Drift tests keep the MASM constant used by that proof synchronized
/// with this value.
pub const FOLDING_BASE: u64 =
    CHALLENGE_FIELD_BITS - FOLDING_COEFFICIENT - fixed::from_bits(LOG_BLOWUP as u32);

/// `log2(e)`, rounded down, in Q16 fixed point.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// The instance shape of a deployed PVM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// Lookup fractions one chiplet emits per row, summed over its auxiliary lookup columns.
///
/// `LookupAir` is generic over its builder, so reading a shape means naming one; the choice does
/// not affect the result, since the shapes are per-AIR constants.
fn fractions_per_row_of(air: ChipletAir) -> usize {
    type ShapeBuilder<'a> = ProverLookupBuilder<'a, Felt, QuadFelt>;

    fn shape_of<A>(air: A) -> usize
    where
        A: for<'a> LookupAir<ShapeBuilder<'a>>,
    {
        LookupAir::<ShapeBuilder<'_>>::column_shape(&air).iter().sum()
    }

    match air {
        ChipletAir::ChunkNodeSponge => shape_of(ChunkNodeSpongeAir),
        ChipletAir::Poseidon2 => shape_of(Poseidon2Air),
        ChipletAir::KeccakRound => shape_of(KeccakRoundAir),
        ChipletAir::BytePairLut => shape_of(BytePairLutAir),
        ChipletAir::TranscriptEval => shape_of(TranscriptEvalAir),
        ChipletAir::UintStoreMul => shape_of(UintStoreMulAir),
        ChipletAir::UintAdd => shape_of(UintAddAir),
        ChipletAir::EcPointStoreGroups => shape_of(EcPointStoreGroupsAir),
        ChipletAir::EcGroupAdd => shape_of(EcGroupAddAir),
        ChipletAir::EcMsm => shape_of(EcMsmAir),
    }
}

/// Counts the lookup fractions added at the PVM boundary by fixed protocol data: one
/// `UintVal` fraction per fixed uint ([`crate::fixed::fixed_uintval_msgs`]) and one `EcGroup`
/// fraction per fixed curve group ([`crate::fixed::fixed_ecgroup_msgs`]). These are additional to
/// the per-row fractions recorded in [`AIR_SHAPE`].
fn fixed_boundary_fraction_count() -> u64 {
    (crate::fixed::fixed_uintval_msgs().count() + crate::fixed::fixed_ecgroup_msgs().count()) as u64
}

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// The generic lookup bound counts `fractions_per_row * 2^log_max_height` terms. The PVM boundary
/// also adds one lookup fraction for every fixed `UintVal` and `EcGroup` message, for a total
/// of [`fixed_boundary_fraction_count`] additional terms per proof. These terms are not included
/// in [`AIR_SHAPE`]'s per-row count, so their contribution is accounted for separately. Both
/// divisions round up, which keeps the correction conservative.
fn fixed_boundary_correction(log_max_height: u32) -> u64 {
    let numerator = fixed_boundary_fraction_count() * LOG2_E;
    numerator
        .div_ceil(AIR_SHAPE.lookup.fractions_per_row as u64)
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

/// Maps PCS parameters onto the protocol parameters the round budget reads.
pub fn protocol_params(params: &PcsParams) -> ProtocolParams {
    ProtocolParams {
        log_blowup: u32::from(params.log_blowup()),
        log_folding_arity: u32::from(params.log_folding_arity()),
        num_queries: params.num_queries() as u32,
        query_pow_bits: params.query_pow_bits() as u32,
        deep_pow_bits: params.deep_pow_bits() as u32,
        folding_pow_bits: params.folding_pow_bits() as u32,
        // The chiplet stack samples its lookup challenges directly after the main-trace
        // commitment, with no grinding in between.
        lookup_pow_bits: LOOKUP_POW_BITS,
    }
}

/// Builds PVM security parameters from values obtained during proof verification.
///
/// `log_max_height` and `alignment` must come from successful STARK verification, and
/// `collision_resistance` from the commitment hash used to verify the proof.
pub fn proof_security_parameters(
    pcs_params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
    collision_resistance: u32,
) -> ProofSecurityParameters {
    ProofSecurityParameters {
        protocol_params: protocol_params(pcs_params),
        log_final_degree: u32::from(pcs_params.log_final_degree()),
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
        num_lookup_boundary_terms: FIXED_BOUNDARY_LOOKUP_TERMS,
    }
}

/// Computes a Poseidon2 chiplet-stack proof's conjectured security level, per protocol round.
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
    let report = p3_security::budget::security_report(params, &instance, &AIR_SHAPE);
    apply_fixed_boundary_correction(report, log_max_height)
}

/// Computes a Poseidon2 chiplet-stack proof's conjectured security level, in bits.
pub fn conjectured_security_level(params: &PcsParams, log_max_height: u32) -> u32 {
    proof_security_parameters(params, log_max_height, COMMITMENT_ALIGNMENT, COLLISION_RESISTANCE)
        .conjectured_security_level()
}

/// Computes a chiplet-stack proof's conjectured security level, in bits, for a proof committed
/// under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. [`conjectured_security_level`] uses the Poseidon2 preset's alignment
/// [`COMMITMENT_ALIGNMENT`]. This helper accepts a different alignment but still assumes the
/// commitment scheme has [`COLLISION_RESISTANCE`] bits; verification returns
/// [`ProofSecurityParameters`] built with both properties of the proof's actual hash function.
pub fn conjectured_security_level_for_alignment(
    params: &PcsParams,
    log_max_height: u32,
    alignment: usize,
) -> u32 {
    proof_security_parameters(params, log_max_height, alignment, COLLISION_RESISTANCE)
        .conjectured_security_level()
}

#[cfg(test)]
mod tests {
    use p3_security::budget::report::QUERY_LABEL;

    use super::*;
    use crate::stark_config::precompile_pcs_params;

    /// Checks that [`AIR_SHAPE`] matches the current chiplet AIRs. A stale shape can make the
    /// reported security level differ from the level implied by the relation being verified.
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
            "fixed boundary shape moved"
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
        const SECURITY_CAP_FP: u64 = 8_388_606;
        const LOOKUP_BASE_FP: u64 = 7_584_459;
        const COMPOSITION_TERM_FP: u64 = 7_785_215;
        const OOD_BASE_FP: u64 = 8_219_197;
        const DEEP_BASE_FP: u64 = 7_760_199;
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

    /// [`num_deep_terms`] at [`COMMITMENT_ALIGNMENT`] must reproduce [`AIR_SHAPE`]'s stored
    /// `num_deep_terms` exactly, so [`conjectured_security_level_for_alignment`] computes the same
    /// level for a Poseidon2 proof as [`conjectured_security_level`].
    #[test]
    fn num_deep_terms_matches_the_reference_alignment() {
        assert_eq!(num_deep_terms(COMMITMENT_ALIGNMENT), AIR_SHAPE.num_deep_terms.unwrap());
    }

    /// Parameters built for a PVM proof must reproduce the independent PVM security report.
    #[test]
    fn proof_security_parameters_match_pvm_security_report() {
        let pcs_params = precompile_pcs_params();
        let expected_protocol_params = protocol_params(&pcs_params);
        let security_parameters =
            proof_security_parameters(&pcs_params, 19, COMMITMENT_ALIGNMENT, COLLISION_RESISTANCE);

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
            (18, 96, QUERY_LABEL),
            (20, 95, LOOKUP_LABEL),
            (24, 91, LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height);
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
                [7_191_195, 7_785_215, 7_825_981, 8_388_606, 7_891_517, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 16),
                [6_535_882, 7_785_215, 7_170_621, 8_388_606, 7_236_157, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 19),
                [6_339_274, 7_785_215, 6_974_013, 8_388_606, 7_039_549, 6_335_399, 8_388_606],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_273_738, 7_785_215, 6_908_477, 8_388_606, 6_974_013, 6_335_399, 8_388_606],
                95,
            ),
            (
                (27, 17, 12, 4, 24),
                [6_011_594, 7_785_215, 6_646_333, 8_388_606, 6_711_869, 6_335_399, 8_388_606],
                91,
            ),
            (
                (7, 0, 0, 0, 16),
                [6_535_882, 7_785_215, 7_170_621, 7_760_199, 6_974_013, 1_353_667, 8_388_606],
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
                "round bits moved at {params:?}, log height {log_height}"
            );
            assert_eq!(
                report.security_level(),
                level,
                "level moved at {params:?}, log height {log_height}"
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
