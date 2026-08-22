//! Conjectured security grading for the precompile chiplet stack.
//!
//! The chiplet stack proves a different statement from the VM's, with its own AIRs, bus width, and
//! PCS preset, so it needs its own shape — but the round budget itself is shared with the VM
//! through [`p3_security::budget`], and so are the challenge field and commitment hash.
//!
//! The AIR shape is pinned as a constant and guarded against drift by `air_shape_matches_symbolic`,
//! matching how the VM side does it.

use miden_air::security::{CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, COMMITMENT_ALIGNMENT};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, ExtensionField, QuadFelt},
};
use miden_crypto::stark::pcs::PcsParams;
use miden_lifted_air::{BaseAir, ConstraintCounts, ConstraintDegrees, LiftedAir};
use p3_security::budget::{AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport};

use crate::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir},
    logup::{LookupAir, ProverLookupBuilder},
    primitives::byte_pair_lut::BytePairLutAir,
    relations::MAX_MESSAGE_WIDTH,
    session::ChipletAir,
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
    num_composed_constraints: 586,
    max_constraint_degree: 5,
    num_deep_terms: Some(770),
    lookup: LookupShape {
        fractions_per_row: 244,
        max_message_width: 18,
    },
};

/// Computes the AIR shape by symbolically evaluating every chiplet AIR.
///
/// This is the source of truth for [`AIR_SHAPE`]; it allocates and runs the full symbolic pass, so
/// grading reads the pinned constant instead of calling it.
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
        num_columns += column_count(&air);
        fractions_per_row += fractions_per_row_of(air);
    }
    num_columns += quotient_column_count(max_constraint_degree);

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

/// Committed base columns for one chiplet: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
fn column_count(air: &ChipletAir) -> usize {
    aligned(BaseAir::<Felt>::preprocessed_width(air))
        + aligned(BaseAir::<Felt>::width(air))
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXTENSION_DEGREE)
}

/// Committed base columns in the quotient group: one chunk per unit of degree above the vanishing
/// polynomial, rounded up to a power of two, committed as a single extension-valued matrix.
fn quotient_column_count(max_constraint_degree: usize) -> usize {
    let chunks = max_constraint_degree.saturating_sub(1).max(1).next_power_of_two();

    aligned(chunks * EXTENSION_DEGREE)
}

/// Pads a committed width up to the commitment scheme's column alignment.
///
/// The DEEP reduction runs over the rows the LMCS committed, so padding takes batching slots too.
fn aligned(width: usize) -> usize {
    width.next_multiple_of(COMMITMENT_ALIGNMENT)
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
        lookup_pow_bits: 0,
    }
}

/// Grades a chiplet-stack proof, returning the per-round conjectured breakdown.
///
/// `log_max_height` is the largest chiplet trace height in the proof; the Fiat-Shamir transcript
/// binds every AIR's log height, so a prover cannot understate it to inflate the reported level.
pub fn security_report(params: &ProtocolParams, log_max_height: u32) -> SecurityReport {
    let instance = InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    };
    p3_security::budget::security_report(params, &instance, &AIR_SHAPE)
}

/// Grades a chiplet-stack proof, returning its conjectured security level in bits.
pub fn conjectured_security_level(params: &PcsParams, log_max_height: u32) -> u32 {
    security_report(&protocol_params(params), log_max_height).security_level()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark_config::precompile_pcs_params;

    /// The pinned AIR shape must track the chiplet AIRs. A chiplet change that adds constraints,
    /// columns, or lookup fractions moves the conjectured level, and grading reads the constant
    /// rather than recomputing it — so drift here silently overstates security.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// The deployed preset's grade, per trace height, with the round that binds at each. The
    /// chiplet stack emits far more lookup fractions per row than the VM does, so its lookup
    /// round overtakes the query phase at a much shorter trace.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&precompile_pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (16, 96, p3_security::budget::report::QUERY_LABEL),
            (18, 96, p3_security::budget::report::QUERY_LABEL),
            (20, 95, p3_security::budget::report::LOOKUP_LABEL),
            (24, 91, p3_security::budget::report::LOOKUP_LABEL),
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

    /// Every round's attained bits, against values computed outside this crate from the closed
    /// forms each round documents.
    ///
    /// The chiplet shape enters the same round budget the VM's does, so this pins that the shape
    /// is wired into it correctly — a term composed with the wrong coefficient or size still
    /// grades the deployed preset at 96 and still falls with height.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_192_399, 7_786_018, 7_825_981, 8_323_072, 7_891_517, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 16),
                [6_537_039, 7_786_018, 7_170_621, 8_323_072, 7_236_157, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 19),
                [6_340_431, 7_786_018, 6_974_013, 8_323_072, 7_039_549, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_274_895, 7_786_018, 6_908_477, 8_323_072, 6_974_013, 6_335_399, 8_323_072],
                95,
            ),
            (
                (27, 17, 12, 4, 24),
                [6_012_751, 7_786_018, 6_646_333, 8_323_072, 6_711_869, 6_335_399, 8_323_072],
                91,
            ),
            (
                (7, 0, 0, 0, 16),
                [6_537_039, 7_786_018, 7_170_621, 7_760_199, 6_974_013, 1_353_667, 8_323_072],
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
