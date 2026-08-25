//! Conjectured security level computation for the Miden VM STARK configuration.
//!
//! The AIR shape entering the round budget is stored as the constant [`AIR_SHAPE`] so the MASM
//! recursive verifier can compute the same security level without running a symbolic pass in-VM.
//! The constant is not hand-maintained: [`derive_air_shape`] computes it from the AIRs themselves,
//! and `air_shape_matches_symbolic` fails the build's test run if an AIR change moves it.

use miden_core::field::{BasedVectorSpace, PrimeField64, QuadFelt};
use miden_crypto::stark::pcs::PcsParams;
use p3_security::{
    budget::{
        AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm,
        report::LOOKUP_LABEL,
    },
    fixed,
};

use crate::{
    AIRS, ConstraintCounts, ConstraintDegrees, Felt, MidenAir, config,
    constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH,
};

/// Log2 of the challenge field size, in fixed point, rounded down.
///
/// The challenge field is the quadratic extension of the Goldilocks base field, so this is
/// `2 · log2(p)` — a shade under 128, and rounded down so no round is credited a bit it does not
/// have.
pub const CHALLENGE_FIELD_BITS: u64 = EXTENSION_DEGREE as u64 * fixed::floor_log2(Felt::ORDER_U64);

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
/// Stored as a constant rather than derived at runtime, so the native and in-VM verifiers compute
/// the same security level. Guarded against drift by `air_shape_matches_symbolic`.
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
/// This is the source of truth for [`AIR_SHAPE`]; it allocates and runs the full symbolic pass, so
/// the verifiers use the constant instead of calling this function.
pub fn derive_air_shape() -> AirShape {
    let mut num_constraints = 0;
    let mut max_constraint_degree = 0;
    let mut num_columns = 0;
    let mut fractions_per_row = 0;

    for air in AIRS {
        num_constraints += ConstraintCounts::from_air::<Felt, QuadFelt, _>(&air).total();
        max_constraint_degree =
            max_constraint_degree.max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air).max());
        num_columns += column_count(air, COMMITMENT_ALIGNMENT);
        fractions_per_row += air.column_shape().iter().sum::<usize>();
    }
    num_columns += quotient_column_count(max_constraint_degree, COMMITMENT_ALIGNMENT);

    AirShape {
        // One batching slot per AIR beyond the first sits alongside the constraints themselves:
        // constraints are folded by powers of one challenge and the AIRs by a second, so a
        // single-AIR statement needs no cross-AIR batching challenge.
        num_composed_constraints: (num_constraints + AIRS.len() - 1) as u32,
        max_constraint_degree: max_constraint_degree as u32,
        num_deep_terms: Some(num_columns as u32 + NUM_OOD_POINTS),
        lookup: LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
        },
    }
}

/// Number of DEEP-quotient batching terms for a commitment scheme with the given column
/// alignment, holding every other AIR shape input fixed at [`AIR_SHAPE`]'s stored values.
///
/// Only the per-column padding is alignment-dependent, so this recomputes committed column counts
/// from the AIRs' own width accessors — no symbolic constraint pass — reusing
/// `AIR_SHAPE::max_constraint_degree` for the quotient group's chunk count. A native verifier
/// computing the security level of a proof committed under a different LMCS (Blake3, alignment 1;
/// Keccak, alignment 17) calls this instead of using the alignment-8 [`AIR_SHAPE`], which is fixed
/// for the Poseidon2-only recursive verifier.
pub fn num_deep_terms(alignment: usize) -> u32 {
    let mut num_columns = 0;
    for air in AIRS {
        num_columns += column_count(air, alignment);
    }
    num_columns += quotient_column_count(AIR_SHAPE.max_constraint_degree as usize, alignment);

    num_columns as u32 + NUM_OOD_POINTS
}

/// Committed base columns for one AIR: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
fn column_count(air: MidenAir, alignment: usize) -> usize {
    use miden_crypto::stark::air::{BaseAir, LiftedAir};

    aligned(BaseAir::<Felt>::preprocessed_width(&air), alignment)
        + aligned(BaseAir::<Felt>::width(&air), alignment)
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(&air) * EXTENSION_DEGREE, alignment)
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
// carries these values as literals. Each is derived here rather than chosen. The output cross-test
// in `crates/lib/core/tests/sys` compares only the two implementations' final computed security
// level, which exposes whichever round attains the minimum — so it alone would not catch drift in
// a constant that never determines that minimum. `derived_security_constants_match_snapshot`
// below checks every one of these constants against a fixed numeric snapshot instead,
// independently of which round determines the minimum.

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
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << config::LOG_FOLDING_ARITY) - 1));

/// `sys::vm::mod.masm`'s `LOOKUP_BASE_FP`: `log2|E|` less the lookup round's coefficient, in fixed
/// point.
pub const LOOKUP_BASE: u64 = CHALLENGE_FIELD_BITS - LOOKUP_COEFFICIENT;

/// `sys::vm::mod.masm`'s `COMPOSITION_TERM_FP`: `log2|E|` less the constraint-composition round's
/// coefficient, in fixed point.
pub const COMPOSITION_TERM: u64 = CHALLENGE_FIELD_BITS - COMPOSITION_COEFFICIENT;

/// `sys::vm::mod.masm`'s `OOD_BASE_FP`: `log2|E|` less the out-of-domain round's coefficient, in
/// fixed point.
pub const OOD_BASE: u64 = CHALLENGE_FIELD_BITS - OOD_COEFFICIENT;

/// `sys::vm::mod.masm`'s `DEEP_BASE_FP`: `log2|E|` less the DEEP round's coefficient, in fixed
/// point.
pub const DEEP_BASE: u64 = CHALLENGE_FIELD_BITS - DEEP_COEFFICIENT;

/// `sys::vm::mod.masm`'s `FOLDING_BASE_FP`: `log2|E|` less the FRI folding round's coefficient and
/// the fixed blowup, in fixed point.
pub const FOLDING_BASE: u64 =
    CHALLENGE_FIELD_BITS - FOLDING_COEFFICIENT - fixed::from_bits(config::LOG_BLOWUP as u32);

/// The instance shape of a deployed Miden VM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// `log2(e)`, rounded down, in fixed point. Matches `sys::vm::mod.masm`'s `LOG2_E_FP`.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// Number of lookup fractions `emit_core_boundary` emits unconditionally: the block-hash seed and
/// the two log-deferred-root terminals. Matches `sys::vm::mod.masm`'s
/// `CORE_BOUNDARY_LOOKUP_TERMS`.
pub const CORE_BOUNDARY_LOOKUP_TERMS: u32 = 3;

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// `boundary` is the number of one-time lookup fractions `emit_core_boundary` and
/// `emit_chiplets_boundary` add on top of the per-row bus terms [`AIR_SHAPE`]'s
/// `lookup.fractions_per_row` already counts — the block-hash seed, the two log-deferred-root
/// terminals, and one `kernel_rom_init` per kernel procedure digest. Both divisions round up, so
/// the correction is never smaller than the true log term, keeping the corrected round
/// conservative. The two-step division order (first by `fractions_per_row`, then by
/// `2^log_max_height`) is what `sys::vm::lookup_boundary_correction` mirrors bit-for-bit: a single
/// combined divisor overflows a `u32` at the deployed shape's larger heights.
fn lookup_boundary_correction(num_kernel_procedures: u32, log_max_height: u32) -> u64 {
    let boundary = CORE_BOUNDARY_LOOKUP_TERMS as u64 + num_kernel_procedures as u64;
    let numerator = boundary * LOG2_E;
    numerator
        .div_ceil(AIR_SHAPE.lookup.fractions_per_row as u64)
        .div_ceil(1u64 << log_max_height)
}

/// Corrects a report's lookup round for the one-time boundary fractions
/// `emit_core_boundary`/`emit_chiplets_boundary` add on top of the per-row bus terms
/// [`AIR_SHAPE`] counts.
fn apply_lookup_boundary_correction(
    report: SecurityReport,
    num_kernel_procedures: u32,
    log_max_height: u32,
) -> SecurityReport {
    let correction = lookup_boundary_correction(num_kernel_procedures, log_max_height);
    let terms = (*report.terms()).map(|term| {
        if term.label == LOOKUP_LABEL {
            SecurityTerm::new(term.label, term.bits.saturating_sub(correction))
        } else {
            term
        }
    });
    SecurityReport::new(terms)
}

/// Computes a deployed Miden VM proof's conjectured security level, in whole bits.
///
/// Every input is bound by the Fiat-Shamir transcript — the PCS parameters through
/// `observe_protocol_params`, the AIR log heights through the multi-AIR statement, the kernel
/// procedure count through the kernel witness authenticated against the claim — so the computed
/// level always reflects the parameters and shape the proof was actually produced with. The
/// blowup, folding arity, AIR shape, challenge field, and commitment hash are fixed by the
/// deployed configuration and enter as the constants above.
///
/// Mirrored bit-for-bit by `sys::vm::compute_conjectured_security_level`, which admits only the
/// recursive verifier's domain — at most 150 queries, grinding below 32 bits, log trace height in
/// `6..30`. This function also accepts configurations outside that domain; a proof past it would
/// trap in the VM.
pub fn conjectured_security_level(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
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
    let report = p3_security::budget::security_report(
        &params,
        &deployed_instance(log_max_height),
        &AIR_SHAPE,
    );
    apply_lookup_boundary_correction(report, num_kernel_procedures, log_max_height).security_level()
}

/// Computes a deployed Miden VM proof's conjectured security level, in whole bits, for a proof
/// committed under a commitment scheme with the given column alignment.
///
/// Every AIR shape input but `num_deep_terms` is alignment-independent, so this reuses
/// [`AIR_SHAPE`] otherwise. Not mirrored in MASM: the recursive verifier accepts only Poseidon2
/// proofs, which `conjectured_security_level` already computes exactly at alignment
/// [`COMMITMENT_ALIGNMENT`] (and this function is identical at that alignment, since
/// `num_deep_terms(COMMITMENT_ALIGNMENT)` equals `AIR_SHAPE.num_deep_terms` —
/// `num_deep_terms_matches_the_pinned_alignment` checks it). The native verifier calls this for
/// every hash function, including the non-algebraic ones the recursive verifier never sees.
pub fn conjectured_security_level_for_alignment(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    alignment: usize,
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
    let air_shape = AirShape {
        num_deep_terms: Some(num_deep_terms(alignment)),
        ..AIR_SHAPE
    };
    let report = p3_security::budget::security_report(
        &params,
        &deployed_instance(log_max_height),
        &air_shape,
    );
    apply_lookup_boundary_correction(report, num_kernel_procedures, log_max_height).security_level()
}

/// Maps PCS parameters onto the protocol parameters the round budget reads.
///
/// The transcript observes every field of [`PcsParams`], so computing a proof's security level
/// under these parameters uses the parameters it was actually produced with.
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
    let report = p3_security::budget::security_report(params, &instance, &AIR_SHAPE);
    apply_lookup_boundary_correction(report, num_kernel_procedures, log_max_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`AIR_SHAPE`] must track the AIRs. An AIR change that adds constraints, columns, or lookup
    /// fractions moves the conjectured level, and both verifiers use the constant rather than
    /// recomputing it — so drift here silently overstates security.
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
    /// `sys::vm::mod.masm` carries the same values as literals; `security_masm_matches_air`
    /// checks those literals directly against these constants. This test does not read the MASM
    /// source — it only checks that the Rust-side values below have not silently drifted from the
    /// snapshot.
    ///
    /// Under the deployed shape the lookup round sits below every other algebraic term and the
    /// cap across the whole swept domain, so the output cross-test in `crates/lib/core/tests/sys`
    /// observes only two of these seven constants; the rest would drift unnoticed there.
    #[test]
    fn derived_security_constants_match_snapshot() {
        const BITS_PER_QUERY_FP: u64 = 193_381;
        const SECURITY_CAP_FP: u64 = 8_323_072;
        const LOOKUP_BASE_FP: u64 = 7_800_270;
        const COMPOSITION_TERM_FP: u64 = 7_815_946;
        const OOD_BASE_FP: u64 = 8_170_900;
        const DEEP_BASE_FP: u64 = 7_922_741;
        const FOLDING_BASE_FP: u64 = 8_022_589;

        assert_eq!(BITS_PER_QUERY, BITS_PER_QUERY_FP, "BITS_PER_QUERY_FP is stale");
        assert_eq!(SECURITY_CAP, SECURITY_CAP_FP, "SECURITY_CAP_FP is stale");
        assert_eq!(LOOKUP_BASE, LOOKUP_BASE_FP, "LOOKUP_BASE_FP is stale");
        assert_eq!(COMPOSITION_TERM, COMPOSITION_TERM_FP, "COMPOSITION_TERM_FP is stale");
        assert_eq!(OOD_BASE, OOD_BASE_FP, "OOD_BASE_FP is stale");
        assert_eq!(DEEP_BASE, DEEP_BASE_FP, "DEEP_BASE_FP is stale");
        assert_eq!(FOLDING_BASE, FOLDING_BASE_FP, "FOLDING_BASE_FP is stale");
    }

    /// Every round's computed bit count, against values computed outside this crate from the
    /// closed forms each round documents.
    ///
    /// The tests around it assert properties of the derivation they exercise — a term composed
    /// with the wrong coefficient, size, or grinding site satisfies monotonicity and still
    /// computes the deployed preset at level 96. These rows are the independent check. They cover
    /// parameters the deployed preset never reaches, so the DEEP and folding terms leave the cap
    /// and the query term reaches it, rather than only the two rounds that determine the level in
    /// practice.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_406_895, 7_815_946, 7_777_684, 8_323_072, 7_891_517, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_489_549, 7_815_946, 6_860_180, 8_323_072, 6_974_013, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 23),
                [6_292_941, 7_815_946, 6_663_572, 8_323_072, 6_777_405, 6_335_399, 8_323_072],
                96,
            ),
            (
                (27, 17, 12, 4, 29),
                [5_899_725, 7_815_946, 6_270_356, 8_323_072, 6_384_189, 6_335_399, 8_323_072],
                90,
            ),
            (
                (7, 0, 0, 0, 20),
                [6_489_549, 7_815_946, 6_860_180, 7_922_741, 6_711_869, 1_353_667, 8_323_072],
                20,
            ),
            (
                (150, 31, 31, 31, 29),
                [5_899_725, 7_815_946, 6_270_356, 8_323_072, 8_153_661, 8_323_072, 8_323_072],
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
