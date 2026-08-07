//! Conjectured security grading for the Miden VM STARK configuration.
//!
//! The AIR shape entering the round budget is pinned as a constant so the MASM recursive verifier
//! can grade proofs against the same numbers without running a symbolic pass in-VM. The constants
//! are not hand-maintained: [`derive_air_shape`] computes them from the AIRs themselves, and
//! `air_shape_matches_symbolic` fails the build's test run if an AIR change moves them.

use miden_core::field::{BasedVectorSpace, PrimeField64, QuadFelt};
use miden_crypto::stark::pcs::PcsParams;
use miden_security::{AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, fixed};

use crate::{
    AIRS, ConstraintCounts, ConstraintDegrees, Felt, MidenAir, config,
    constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH,
};

/// Log2 of the challenge field size, in fixed point, rounded down.
///
/// The challenge field is the quadratic extension of the Goldilocks base field, so this is
/// `2 · log2(p)` — a shade under 128, and rounded down so no round is credited a bit it does not
/// have.
pub const CHALLENGE_FIELD_BITS: u64 = 2 * fixed::floor_log2(Felt::ORDER_U64);

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = 2;

/// Base field elements per challenge-field element.
const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

/// Column alignment of the commitment scheme, in base field elements.
///
/// The commitment sponge absorbs whole rates, so a committed matrix is padded up to a multiple of
/// the rate.
pub const COMMITMENT_ALIGNMENT: usize = config::SPONGE_RATE;

/// Shape of the Miden VM multi-AIR statement, as it enters the round budget.
///
/// Pinned rather than derived at runtime so the native and in-VM verifiers grade identically.
/// Guarded against drift by `air_shape_matches_symbolic`.
pub const AIR_SHAPE: AirShape = AirShape {
    num_composed_constraints: 426,
    max_constraint_degree: 9,
    num_deep_terms: 138,
    lookup: LookupShape {
        fractions_per_row: 28,
        max_message_width: 16,
    },
};

/// Computes the AIR shape by symbolically evaluating every AIR in the statement.
///
/// This is the source of truth for [`AIR_SHAPE`]; it allocates and runs the full symbolic pass, so
/// the verifiers read the pinned constant instead of calling it.
pub fn derive_air_shape() -> AirShape {
    let mut num_constraints = 0;
    let mut max_constraint_degree = 0;
    let mut num_columns = 0;
    let mut fractions_per_row = 0;

    for air in AIRS {
        num_constraints += ConstraintCounts::from_air::<Felt, QuadFelt, _>(&air).total();
        max_constraint_degree =
            max_constraint_degree.max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air).max());
        num_columns += column_count(air);
        fractions_per_row += air.column_shape().iter().sum::<usize>();
    }
    num_columns += quotient_column_count(max_constraint_degree);

    AirShape {
        // One batching slot per AIR sits alongside the constraints themselves: constraints are
        // folded by powers of one challenge and the AIRs by a second.
        num_composed_constraints: (num_constraints + AIRS.len()) as u32,
        max_constraint_degree: max_constraint_degree as u32,
        num_deep_terms: num_columns as u32 + NUM_OOD_POINTS,
        lookup: LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
        },
    }
}

/// Committed base columns for one AIR: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
fn column_count(air: MidenAir) -> usize {
    use miden_crypto::stark::air::{BaseAir, LiftedAir};

    aligned(BaseAir::<Felt>::preprocessed_width(&air))
        + aligned(BaseAir::<Felt>::width(&air))
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(&air) * EXTENSION_DEGREE)
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

// MIRRORED CONSTANTS
// ================================================================================================
//
// The MASM recursive verifier grades proofs with the same round budget and cannot run this code,
// so it carries these values as literals. Each is derived here rather than chosen. The cross-test
// in `crates/lib/core/tests/sys` compares only outputs, which expose whichever round is the
// minimum, so `masm_literals_match_the_derived_constants` below pins each literal on its own.

/// Conjectured security contributed per FRI query, in fixed point.
pub const BITS_PER_QUERY: u64 =
    fixed::bits_per_query(config::LOG_BLOWUP as u32, CHALLENGE_FIELD_BITS);

/// Collision resistance of the commitment hash, in whole bits.
///
/// A digest is `DIGEST_WIDTH` field elements wide, and birthday collisions cost half its entropy.
pub const COLLISION_RESISTANCE: u32 =
    fixed::to_bits(config::DIGEST_WIDTH as u64 * fixed::floor_log2(Felt::ORDER_U64)) / 2;

/// Ceiling any reported level is capped at, in fixed point.
pub const SECURITY_CAP: u64 = deployed_instance(0).cap();

/// `log2` of the lookup round's error coefficient, in fixed point.
pub const LOOKUP_COEFFICIENT: u64 = fixed::ceil_log2(
    2 * AIR_SHAPE.lookup.max_message_width as u64 * AIR_SHAPE.lookup.fractions_per_row as u64,
);

/// `log2` of the constraint-composition round's error coefficient, in fixed point.
pub const COMPOSITION_COEFFICIENT: u64 =
    fixed::ceil_log2(AIR_SHAPE.num_composed_constraints as u64);

/// `log2` of the out-of-domain round's error coefficient, in fixed point.
pub const OOD_COEFFICIENT: u64 = fixed::ceil_log2(AIR_SHAPE.max_constraint_degree as u64 + 1);

/// `log2` of the DEEP round's error coefficient, in fixed point.
pub const DEEP_COEFFICIENT: u64 = fixed::ceil_log2(AIR_SHAPE.num_deep_terms as u64);

/// `log2` of the FRI folding round's error coefficient, in fixed point.
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << config::LOG_FOLDING_ARITY) - 1));

/// The instance shape of a deployed Miden VM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// Grades a deployed Miden VM proof, returning its conjectured security level in whole bits.
///
/// Every input is bound by the Fiat-Shamir transcript — the PCS parameters through
/// `observe_protocol_params`, the AIR log heights through the multi-AIR statement — so a proof
/// cannot be graded under parameters or a shape it was not produced with. The blowup, folding
/// arity, AIR shape, challenge field, and commitment hash are fixed by the deployed configuration
/// and enter as the constants above.
///
/// Mirrored bit-for-bit by `sys::vm::compute_conjectured_security_level`, which admits only the
/// recursive verifier's domain — at most 150 queries, grinding below 32 bits, log trace height in
/// `6..30`. This function grades outside it too, so a configuration past it traps in the VM.
pub fn conjectured_security_level(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
) -> u32 {
    let params = ProtocolParams {
        log_blowup: config::LOG_BLOWUP as u32,
        log_folding_arity: config::LOG_FOLDING_ARITY as u32,
        num_queries,
        query_pow_bits,
        deep_pow_bits,
        folding_pow_bits,
        lookup_pow_bits: 0,
    };
    miden_security::security_report(&params, &deployed_instance(log_max_height), &AIR_SHAPE)
        .security_level()
}

/// Maps PCS parameters onto the protocol parameters the round budget reads.
///
/// The transcript observes every field of [`PcsParams`], so grading a proof under these parameters
/// grades it under the parameters it was produced with.
pub fn protocol_params(params: &PcsParams) -> ProtocolParams {
    ProtocolParams {
        log_blowup: u32::from(params.log_blowup()),
        log_folding_arity: u32::from(params.log_folding_arity()),
        num_queries: params.num_queries() as u32,
        query_pow_bits: params.query_pow_bits() as u32,
        deep_pow_bits: params.deep_pow_bits() as u32,
        folding_pow_bits: params.folding_pow_bits() as u32,
        // The protocol samples the lookup challenges directly after the main-trace commitment,
        // with no grinding in between.
        lookup_pow_bits: 0,
    }
}

/// Grades a proof of the Miden VM statement, returning the per-round conjectured breakdown.
///
/// `log_max_height` is the largest AIR trace height in the proof; the Fiat-Shamir transcript binds
/// every AIR's log height, so a prover cannot understate it to inflate the reported level.
/// `collision_resistance` is that of the commitment hash, in bits.
pub fn security_report(
    params: &ProtocolParams,
    log_max_height: u32,
    collision_resistance: u32,
) -> SecurityReport {
    let instance = InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance,
    };
    miden_security::security_report(params, &instance, &AIR_SHAPE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned AIR shape must track the AIRs. An AIR change that adds constraints, columns, or
    /// lookup fractions moves the conjectured level, and both verifiers read the constant rather
    /// than recomputing it — so drift here silently overstates security.
    #[test]
    fn air_shape_matches_symbolic() {
        assert_eq!(AIR_SHAPE, derive_air_shape(), "AIR_SHAPE in security.rs is stale");
    }

    /// The deployed preset's grade, per trace height, with the round that binds at each. The
    /// preset was calibrated against the query phase alone; this pins what it actually attains
    /// once the trace-height-dependent rounds are counted, so any parameter or AIR change that
    /// moves the real figure is visible rather than absorbed into an unchanged constant.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&config::pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (20, 96, miden_security::report::QUERY_LABEL),
            (22, 96, miden_security::report::LOOKUP_LABEL),
            (24, 94, miden_security::report::LOOKUP_LABEL),
            (29, 89, miden_security::report::LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height, 128);
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

    /// Every literal in `sys::vm::mod.masm`, pinned against the constant it mirrors.
    ///
    /// Under the deployed shape the lookup round sits below every other algebraic term and the
    /// cap across the whole swept domain, so the output cross-test observes two of these seven
    /// literals; the rest would drift unnoticed.
    #[test]
    fn masm_literals_match_the_derived_constants() {
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_323_072;
        const LOOKUP_BASE_FP: u64 = 7_745_871;
        const COMPOSITION_TERM_FP: u64 = 7_816_168;
        const OOD_BASE_FP: u64 = 8_170_900;
        const DEEP_BASE_FP: u64 = 7_922_741;
        const FOLDING_BASE_FP: u64 = 8_022_589;

        assert_eq!(BITS_PER_QUERY, BITS_PER_QUERY_FP, "BITS_PER_QUERY_FP is stale");
        assert_eq!(SECURITY_CAP, SECURITY_CAP_FP, "SECURITY_CAP_FP is stale");
        assert_eq!(
            CHALLENGE_FIELD_BITS - LOOKUP_COEFFICIENT,
            LOOKUP_BASE_FP,
            "LOOKUP_BASE_FP is stale"
        );
        assert_eq!(
            CHALLENGE_FIELD_BITS - COMPOSITION_COEFFICIENT,
            COMPOSITION_TERM_FP,
            "COMPOSITION_TERM_FP is stale"
        );
        assert_eq!(CHALLENGE_FIELD_BITS - OOD_COEFFICIENT, OOD_BASE_FP, "OOD_BASE_FP is stale");
        assert_eq!(CHALLENGE_FIELD_BITS - DEEP_COEFFICIENT, DEEP_BASE_FP, "DEEP_BASE_FP is stale");
        assert_eq!(
            CHALLENGE_FIELD_BITS
                - FOLDING_COEFFICIENT
                - miden_security::fixed::from_bits(config::LOG_BLOWUP as u32),
            FOLDING_BASE_FP,
            "FOLDING_BASE_FP is stale"
        );
    }

    /// Every round's attained bits, against values computed outside this crate from the closed
    /// forms each round documents.
    ///
    /// The tests around it assert properties of the derivation they exercise — a term composed
    /// with the wrong coefficient, size, or grinding site satisfies monotonicity and still grades
    /// the deployed preset at 96. These rows are the independent check. They cover parameters the
    /// deployed preset never reaches, so the DEEP and folding terms leave the cap and the query
    /// term reaches it, rather than only the two rounds that bind in practice.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_352_655, 7_816_168, 7_777_684, 8_323_072, 7_891_517, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_435_151, 7_816_168, 6_860_180, 8_323_072, 6_974_013, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 23),
                [6_238_543, 7_816_168, 6_663_572, 8_323_072, 6_777_405, 6_335_399, 8_323_072],
                95,
            ),
            (
                (27, 17, 12, 4, 29),
                [5_845_327, 7_816_168, 6_270_356, 8_323_072, 6_384_189, 6_335_399, 8_323_072],
                89,
            ),
            (
                (7, 0, 0, 0, 20),
                [6_435_151, 7_816_168, 6_860_180, 7_922_741, 6_711_869, 1_353_667, 8_323_072],
                20,
            ),
            (
                (150, 31, 31, 31, 29),
                [5_845_327, 7_816_168, 6_270_356, 8_323_072, 8_153_661, 8_323_072, 8_323_072],
                89,
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
            let report = security_report(&params, log_height, COLLISION_RESISTANCE);

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
    /// which is what makes the grade height-dependent at all. Pinning the crossover keeps that
    /// boundary honest: below it the preset attains its design target, above it it does not.
    #[test]
    fn lookup_round_overtakes_the_query_phase_in_the_low_twenties() {
        let params = protocol_params(&config::pcs_params());
        let crossover = (6..=30)
            .find(|&log_height| {
                security_report(&params, log_height, 128).binding_term().label
                    == miden_security::report::LOOKUP_LABEL
            })
            .expect("the lookup round must bind at some supported height");

        assert_eq!(crossover, 22, "lookup/query crossover moved");
    }
}
