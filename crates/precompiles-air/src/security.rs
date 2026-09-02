//! Conjectured security level computation for the precompile chiplet stack.
//!
//! The chiplet stack proves a different statement from the VM's, with its own AIRs, bus width, and
//! PCS preset, so it needs its own shape — but the round budget itself is shared with the VM
//! through [`p3_security::budget`], and so are the challenge field and commitment hash.
//!
//! The AIR shape is stored as the constant [`AIR_SHAPE`] and guarded against drift by
//! `air_shape_matches_symbolic`, matching how the VM side does it.

pub use miden_air::security::ProofSecurityParameters;
use miden_air::security::{CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, COMMITMENT_ALIGNMENT};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_crypto::stark::pcs::PcsParams;
use miden_lifted_air::{BaseAir, ConstraintCounts, ConstraintDegrees, LiftedAir};
use p3_security::{
    budget::{
        AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm,
        report::LOOKUP_LABEL,
    },
    fixed,
};

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

/// Shape of the chiplet multi-AIR statement, as it enters the round budget.
///
/// Guarded against drift by `air_shape_matches_symbolic`.
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
/// This is the source of truth for [`AIR_SHAPE`]; it allocates and runs the full symbolic pass, so
/// [`security_report`] uses the constant instead of calling this function.
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
/// The DEEP reduction runs over the rows the LMCS committed, so padding takes batching slots too.
fn aligned(width: usize, alignment: usize) -> usize {
    width.next_multiple_of(alignment)
}

// MIRRORED CONSTANTS
// ================================================================================================
//
// The MASM recursive verifier computes the same round budget and cannot run this code, so it
// carries the resulting round bases as literals. Each base is derived here rather than chosen. The
// output cross-test in `crates/lib/core/tests/sys` compares the two implementations' final
// computed security level, while `derived_security_constants_match_snapshot` below and
// `pvm_security_masm_matches_air` check every active literal independently of which round
// determines the minimum.

/// Fractional bits in the fixed-point representation shared with the MASM estimator.
pub const FIXED_POINT_FRACTIONAL_BITS: u32 = fixed::FRACTIONAL_BITS;

/// Fixed-point representation of one, shared with the MASM estimator.
pub const FIXED_POINT_ONE: u64 = fixed::ONE;

/// Conjectured security contributed per FRI query, in fixed point.
pub const BITS_PER_QUERY: u64 = fixed::bits_per_query(LOG_BLOWUP as u32, CHALLENGE_FIELD_BITS);

/// Ceiling any reported level is capped at, in fixed point.
pub const SECURITY_CAP: u64 = deployed_instance(0).cap();

/// `log2` of the lookup round's error coefficient, in fixed point.
pub const LOOKUP_COEFFICIENT: u64 = fixed::ceil_log2(
    (AIR_SHAPE.lookup.max_message_width as u64 + 2) * AIR_SHAPE.lookup.fractions_per_row as u64,
);

/// `log2` of the constraint-composition round's error coefficient, in fixed point.
pub const COMPOSITION_COEFFICIENT: u64 =
    fixed::ceil_log2(AIR_SHAPE.num_composed_constraints as u64);

/// `log2` of the out-of-domain round's error coefficient, in fixed point.
pub const OOD_COEFFICIENT: u64 = fixed::ceil_log2(AIR_SHAPE.max_constraint_degree as u64 + 1);

/// `log2` of the DEEP round's error coefficient, in fixed point.
pub const DEEP_COEFFICIENT: u64 = fixed::ceil_log2(match AIR_SHAPE.num_deep_terms {
    Some(n) => n as u64,
    None => 0,
});

/// `log2` of the FRI folding round's error coefficient, in fixed point.
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << LOG_FOLDING_ARITY) - 1));

/// Lookup grinding applied before the lookup challenges are sampled.
///
/// The deployed chiplet stack samples them directly after the main-trace commitment.
pub const LOOKUP_POW_BITS: u32 = 0;

/// Number of fixed-environment lookup fractions consumed once per PVM proof.
///
/// `fixed_boundary_fraction_count` derives this value from the fixed messages, and the drift
/// test below keeps the exported descriptor constant tied to that source of truth.
pub const FIXED_BOUNDARY_LOOKUP_TERMS: u32 = 8;

/// `log2|E|` less the lookup round's coefficient, in fixed point.
pub const LOOKUP_BASE: u64 = CHALLENGE_FIELD_BITS - LOOKUP_COEFFICIENT;

/// `sys::pvm::mod.masm`'s `COMPOSITION_TERM_FP`.
pub const COMPOSITION_TERM: u64 = CHALLENGE_FIELD_BITS - COMPOSITION_COEFFICIENT;

/// `sys::pvm::mod.masm`'s `OOD_BASE_FP`.
pub const OOD_BASE: u64 = CHALLENGE_FIELD_BITS - OOD_COEFFICIENT;

/// `sys::pvm::mod.masm`'s `DEEP_BASE_FP`.
pub const DEEP_BASE: u64 = CHALLENGE_FIELD_BITS - DEEP_COEFFICIENT;

/// The common MASM estimator's `FOLDING_BASE_FP`, including the fixed blowup.
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

/// Number of fixed-environment lookup fractions the verifier boundary consumes once per proof: one
/// `UintVal` fraction per fixed uint ([`crate::fixed::fixed_uintval_msgs`]) and one `EcGroup`
/// fraction per fixed curve group ([`crate::fixed::fixed_ecgroup_msgs`]). [`AIR_SHAPE`]'s
/// `lookup.fractions_per_row` counts only the fractions each row of trace emits, not these.
fn fixed_boundary_fraction_count() -> u64 {
    (crate::fixed::fixed_uintval_msgs().count() + crate::fixed::fixed_ecgroup_msgs().count()) as u64
}

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// `boundary` is [`fixed_boundary_fraction_count`]. Bounding a malicious trace cannot assume it
/// supplies providers matching the verifier's fixed-environment consumes, so the generic lookup
/// bound — which assumes exactly `fractions_per_row · 2^log_max_height` fractions — is corrected
/// down by this amount to account for the `boundary` extra fractions the verifier always consumes.
/// Both divisions round up, so the correction never understates the true log term, keeping the
/// corrected round conservative.
fn fixed_boundary_correction(log_max_height: u32) -> u64 {
    let numerator = fixed_boundary_fraction_count() * LOG2_E;
    numerator
        .div_ceil(AIR_SHAPE.lookup.fractions_per_row as u64)
        .div_ceil(1u64 << log_max_height)
}

/// Corrects a report's lookup round for the fixed-environment boundary fractions
/// [`fixed_boundary_correction`] counts.
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

/// Computes a chiplet-stack proof's conjectured security level, per protocol round.
///
/// `log_max_height` is the largest chiplet trace height in the proof; the Fiat-Shamir transcript
/// binds every AIR's log height, so a prover cannot understate it to inflate the reported level.
/// The lookup round is corrected for the fixed-environment boundary fractions the verifier
/// consumes on top of [`AIR_SHAPE`]'s per-row fractions.
/// The recursive verifier admits only 7..=150 queries, 0..=31 query/DEEP/folding grinding bits,
/// fixed zero lookup grinding, and a maximum log trace height in `16..=29`. This native function
/// also accepts configurations outside that domain; such inputs are not part of the recursive
/// estimator's contract.
pub fn security_report(params: &ProtocolParams, log_max_height: u32) -> SecurityReport {
    let instance = deployed_instance(log_max_height);
    let report = p3_security::budget::security_report(params, &instance, &AIR_SHAPE);
    apply_fixed_boundary_correction(report, log_max_height)
}

/// Computes a chiplet-stack proof's conjectured security level, in bits.
pub fn conjectured_security_level(params: &PcsParams, log_max_height: u32) -> u32 {
    proof_security_parameters(params, log_max_height, COMMITMENT_ALIGNMENT, COLLISION_RESISTANCE)
        .conjectured_security_level()
}

/// Computes a chiplet-stack proof's conjectured security level, in bits, for a proof committed
/// under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. [`conjectured_security_level`] is exact only at the Poseidon2 preset's
/// alignment [`COMMITMENT_ALIGNMENT`]; verification calls this instead for every hash function, so
/// a proof committed under a different LMCS (Blake3, alignment 1; Keccak, alignment 17) is graded
/// under its own DEEP term count rather than the Poseidon2 one.
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

    /// [`AIR_SHAPE`] must track the chiplet AIRs. A chiplet change that adds constraints, columns,
    /// or lookup fractions moves the conjectured level, and [`security_report`] uses the constant
    /// rather than recomputing it — so drift here silently overstates security.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// Pin the fixed-boundary shape so any environment change receives an explicit security
    /// review, even while its rounded correction remains unchanged.
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
    /// `sys::pvm::mod.masm` carries the corresponding descriptor bases as literals;
    /// `pvm_security_masm_matches_air` checks them directly against these constants.
    #[test]
    fn derived_security_constants_match_snapshot() {
        const FP_SHIFT: u32 = 16;
        const FP_ONE: u64 = 65_536;
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_323_072;
        const LOOKUP_BASE_FP: u64 = 7_584_459;
        const COMPOSITION_TERM_FP: u64 = 7_785_215;
        const OOD_BASE_FP: u64 = 8_219_197;
        const DEEP_BASE_FP: u64 = 7_760_199;
        const FOLDING_BASE_FP: u64 = 8_022_589;

        assert_eq!(FIXED_POINT_FRACTIONAL_BITS, FP_SHIFT, "FP_SHIFT is stale");
        assert_eq!(FIXED_POINT_ONE, FP_ONE, "FP_ONE is stale");
        assert_eq!(BITS_PER_QUERY, BITS_PER_QUERY_FP, "BITS_PER_QUERY_FP is stale");
        assert_eq!(SECURITY_CAP, SECURITY_CAP_FP, "SECURITY_CAP_FP is stale");
        assert_eq!(LOOKUP_BASE, LOOKUP_BASE_FP, "LOOKUP_BASE_FP is stale");
        assert_eq!(COMPOSITION_TERM, COMPOSITION_TERM_FP, "COMPOSITION_TERM_FP is stale");
        assert_eq!(OOD_BASE, OOD_BASE_FP, "OOD_BASE_FP is stale");
        assert_eq!(DEEP_BASE, DEEP_BASE_FP, "DEEP_BASE_FP is stale");
        assert_eq!(FOLDING_BASE, FOLDING_BASE_FP, "FOLDING_BASE_FP is stale");
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

    /// Every round's computed bit count, against values computed outside this crate from the
    /// closed forms each round documents.
    ///
    /// The chiplet shape enters the same round budget the VM's does, so this checks that the
    /// shape is wired into it correctly — a term composed with the wrong coefficient or size
    /// still computes the deployed preset at level 96 and still falls with height.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_191_195, 7_785_215, 7_825_981, 8_323_072, 7_891_517, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 16),
                [6_535_882, 7_785_215, 7_170_621, 8_323_072, 7_236_157, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 19),
                [6_339_274, 7_785_215, 6_974_013, 8_323_072, 7_039_549, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_273_738, 7_785_215, 6_908_477, 8_323_072, 6_974_013, 6_335_399, 8_323_072],
                95,
            ),
            (
                (27, 17, 12, 4, 24),
                [6_011_594, 7_785_215, 6_646_333, 8_323_072, 6_711_869, 6_335_399, 8_323_072],
                91,
            ),
            (
                (7, 0, 0, 0, 16),
                [6_535_882, 7_785_215, 7_170_621, 7_760_199, 6_974_013, 1_353_667, 8_323_072],
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
