//! Relation-generic conjectured-security model.
//!
//! Both Miden STARK relations — the VM statement and the precompile chiplet stack — instantiate
//! the [`p3_security`] round budget the same way: the same committed-column accounting, the same
//! out-of-domain point count, the same Q16 constants derived from an [`AirShape`], and the same
//! correction for lookup fractions consumed once per proof rather than once per row. They differ
//! only in their AIR set, their stored [`AirShape`], their FRI configuration, and how many
//! one-time lookup fractions their boundary emits, so those enter as parameters.
//!
//! The relations' own modules — [`crate::security`] for the VM and `miden_precompiles_air`'s for
//! the chiplet stack — hold those inputs and expose the estimator entry points.

use miden_core::field::{BasedVectorSpace, PrimeField64, QuadFelt};
use miden_crypto::{
    hash::poseidon2::Poseidon2,
    stark::{
        air::{BaseAir, ConstraintCounts, ConstraintDegrees, LiftedAir},
        pcs::PcsParams,
    },
};
use p3_security::{
    budget::{
        AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm,
        report::LOOKUP_LABEL,
    },
    fixed,
};

use crate::{Felt, config};

// FIELD AND COMMITMENT CONSTANTS
// ================================================================================================

/// Conservative Q16 lower bound on the log2 of the challenge-field cardinality.
///
/// The challenge field is the quadratic extension of the Goldilocks base field. This value doubles
/// the rounded-down Q16 value for the base field. Rounding before doubling keeps the result
/// conservative.
pub const CHALLENGE_FIELD_BITS: u64 = EXTENSION_DEGREE as u64 * fixed::floor_log2(Felt::ORDER_U64);

/// Base field elements per challenge-field element.
pub const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

/// Collision resistance of the Poseidon2 commitment used by the recursive verifiers.
pub const COLLISION_RESISTANCE: u32 = Poseidon2::COLLISION_RESISTANCE;

/// Column alignment of the commitment scheme, in base field elements.
///
/// The commitment sponge absorbs whole rates, so a committed matrix is padded up to a multiple of
/// the rate.
pub const COMMITMENT_ALIGNMENT: usize = config::SPONGE_RATE;

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs of both relations use `local` and `next` rotations only.
pub const NUM_OOD_POINTS: u32 = 2;

// AIR SHAPE DERIVATION
// ================================================================================================

/// Pads a committed width up to the commitment scheme's column alignment.
///
/// The DEEP reduction batches every element of each opened, alignment-padded row, so padding also
/// contributes batching slots.
fn aligned(width: usize, alignment: usize) -> usize {
    width.next_multiple_of(alignment)
}

/// Committed base columns for one AIR: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
pub fn column_count<A>(air: &A, alignment: usize) -> usize
where
    A: BaseAir<Felt> + LiftedAir<Felt, QuadFelt>,
{
    aligned(BaseAir::<Felt>::preprocessed_width(air), alignment)
        + aligned(BaseAir::<Felt>::width(air), alignment)
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXTENSION_DEGREE, alignment)
}

/// Committed base columns in the quotient group: one chunk per unit of degree above the vanishing
/// polynomial, rounded up to a power of two, committed as a single extension-valued matrix.
pub fn quotient_column_count(max_constraint_degree: usize, alignment: usize) -> usize {
    let chunks = max_constraint_degree.saturating_sub(1).max(1).next_power_of_two();

    aligned(chunks * EXTENSION_DEGREE, alignment)
}

/// Computes a relation's AIR shape by symbolically evaluating every AIR in it.
///
/// The two relations reach an AIR's per-row lookup fraction count through different traits, so it
/// is read by the `fractions_per_row_of` callback. `max_message_width` is the relation's widest
/// lookup message.
///
/// The symbolic pass allocates and evaluates every AIR, so verifiers use their relation's checked
/// shape constant instead of calling this function.
pub fn derive_air_shape<A>(
    airs: &[A],
    max_message_width: u32,
    fractions_per_row_of: impl Fn(&A) -> usize,
    alignment: usize,
) -> AirShape
where
    A: BaseAir<Felt> + LiftedAir<Felt, QuadFelt>,
{
    let mut num_constraints = 0;
    let mut max_constraint_degree = 0;
    let mut num_columns = 0;
    let mut fractions_per_row = 0;

    for air in airs {
        num_constraints += ConstraintCounts::from_air::<Felt, QuadFelt, _>(air).total();
        max_constraint_degree =
            max_constraint_degree.max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(air).max());
        num_columns += column_count(air, alignment);
        fractions_per_row += fractions_per_row_of(air);
    }
    num_columns += quotient_column_count(max_constraint_degree, alignment);

    AirShape {
        // One batching slot per AIR beyond the first sits alongside the constraints themselves:
        // constraints are folded by powers of one challenge and the AIRs by a second, so a
        // single-AIR statement needs no cross-AIR batching challenge.
        num_composed_constraints: (num_constraints + airs.len() - 1) as u32,
        max_constraint_degree: max_constraint_degree as u32,
        num_deep_terms: Some(num_columns as u32 + NUM_OOD_POINTS),
        lookup: LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width,
        },
    }
}

/// Number of DEEP-quotient batching terms for a commitment scheme with the given column alignment,
/// holding the relation's maximum constraint degree fixed at its stored value.
///
/// Only the per-column padding is alignment-dependent, so this recomputes committed column counts
/// from the AIRs' own width accessors — no symbolic constraint pass. A native verifier computing
/// the security level of a proof committed under a different LMCS (Blake3, alignment 1; Keccak,
/// alignment 17) calls this instead of using the relation's stored shape, which is fixed at
/// [`COMMITMENT_ALIGNMENT`] for the Poseidon2-only recursive verifiers.
pub fn num_deep_terms<A>(airs: &[A], max_constraint_degree: usize, alignment: usize) -> u32
where
    A: BaseAir<Felt> + LiftedAir<Felt, QuadFelt>,
{
    let mut num_columns = 0;
    for air in airs {
        num_columns += column_count(air, alignment);
    }
    num_columns += quotient_column_count(max_constraint_degree, alignment);

    num_columns as u32 + NUM_OOD_POINTS
}

// SECURITY MODEL CONSTANTS
// ================================================================================================
//
// The MASM recursive estimator consumes the raw AIR shape. Tests in
// `crates/lib/core/tests/stark/security.rs` compare it with the native calculation over the ranges
// accepted by the recursive verifiers. Each relation's `derived_security_constants_match_snapshot`
// checks its own instantiation of these formulas independently.

/// Fractional bits in the fixed-point representation shared with the MASM estimator.
pub const FIXED_POINT_FRACTIONAL_BITS: u32 = fixed::FRACTIONAL_BITS;

/// Fixed-point representation of one, shared with the MASM estimator.
pub const FIXED_POINT_ONE: u64 = fixed::ONE;

/// `log2(e)`, rounded down, in fixed point. Matches the common MASM estimator's `LOG2_E_FP`.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// Upper bound on every reported level, in fixed point.
pub const SECURITY_CAP: u64 = deployed_instance(0).cap();

/// Lookup grinding applied before the lookup challenges are sampled.
///
/// Lifted STARK currently samples them directly after the main-trace commitment and exposes no
/// lookup-grinding parameter.
pub const LOOKUP_POW_BITS: u32 = 0;

/// The instance shape of a deployed proof at the given maximum AIR log height.
pub const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// Conjectured security contributed per FRI query, in fixed point.
pub const fn bits_per_query(log_blowup: u32) -> u64 {
    fixed::bits_per_query(log_blowup, CHALLENGE_FIELD_BITS)
}

/// Q16 upper bound on the log2 of the lookup round's error coefficient.
pub const fn lookup_coefficient(shape: &AirShape) -> u64 {
    fixed::ceil_log2(
        (shape.lookup.max_message_width as u64 + 2) * shape.lookup.fractions_per_row as u64,
    )
}

/// Q16 upper bound on the log2 of the constraint-composition round's error coefficient.
pub const fn composition_coefficient(shape: &AirShape) -> u64 {
    fixed::ceil_log2(shape.num_composed_constraints as u64)
}

/// Q16 upper bound on the log2 of the out-of-domain round's error coefficient.
pub const fn ood_coefficient(shape: &AirShape) -> u64 {
    fixed::ceil_log2(shape.max_constraint_degree as u64 + 1)
}

/// Q16 upper bound on the log2 of the DEEP round's error coefficient.
pub const fn deep_coefficient(shape: &AirShape) -> u64 {
    fixed::ceil_log2(match shape.num_deep_terms {
        Some(n) => n as u64,
        None => 0,
    })
}

/// Q16 upper bound on the log2 of the FRI folding round's error coefficient.
pub const fn folding_coefficient(log_folding_arity: u32) -> u64 {
    fixed::ceil_log2(2 * ((1 << log_folding_arity) - 1))
}

/// The configured challenge-field bound less the lookup round's coefficient, in fixed point.
pub const fn lookup_base(shape: &AirShape) -> u64 {
    CHALLENGE_FIELD_BITS - lookup_coefficient(shape)
}

/// The configured challenge-field bound less the constraint-composition round's coefficient, in
/// fixed point.
pub const fn composition_term(shape: &AirShape) -> u64 {
    CHALLENGE_FIELD_BITS - composition_coefficient(shape)
}

/// The configured challenge-field bound less the out-of-domain round's coefficient, in fixed
/// point.
pub const fn ood_base(shape: &AirShape) -> u64 {
    CHALLENGE_FIELD_BITS - ood_coefficient(shape)
}

/// The configured challenge-field bound less the DEEP round's coefficient, in fixed point.
pub const fn deep_base(shape: &AirShape) -> u64 {
    CHALLENGE_FIELD_BITS - deep_coefficient(shape)
}

/// The configured challenge-field bound less the FRI folding round's coefficient and fixed blowup,
/// in fixed point.
///
/// The common MASM estimator uses the whole-bit floor of this value when proving that FRI folding
/// cannot determine the result. Drift tests keep the MASM constant used by that proof synchronized
/// with this value.
pub const fn folding_base(log_blowup: u32, log_folding_arity: u32) -> u64 {
    CHALLENGE_FIELD_BITS - folding_coefficient(log_folding_arity) - fixed::from_bits(log_blowup)
}

// SECURITY REPORT
// ================================================================================================

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
        // Both relations sample their lookup challenges directly after the main-trace commitment,
        // with no grinding in between.
        lookup_pow_bits: LOOKUP_POW_BITS,
    }
}

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// `num_boundary_terms` is the number of one-time lookup fractions consumed on top of the per-row
/// terms counted by `fractions_per_row`. Both divisions round up, so the correction is never
/// smaller than the true log term, keeping the corrected round conservative. The two-step division
/// order (first by `fractions_per_row`, then by `2^log_max_height`) is what the common MASM
/// estimator mirrors bit-for-bit: a single combined divisor overflows a `u32` at the deployed
/// shape's larger heights.
pub fn lookup_boundary_correction(
    num_boundary_terms: u32,
    fractions_per_row: u32,
    log_max_height: u32,
) -> u64 {
    if num_boundary_terms == 0 {
        return 0;
    }
    assert!(fractions_per_row > 0, "lookup boundary terms require per-row lookup fractions");
    let height = 1u64
        .checked_shl(log_max_height)
        .expect("maximum trace height must fit in a u64");
    (u64::from(num_boundary_terms) * LOG2_E)
        .div_ceil(u64::from(fractions_per_row))
        .div_ceil(height)
}

/// Lowers `report`'s lookup term by `correction`, leaving every other round unchanged.
pub fn apply_lookup_correction(report: SecurityReport, correction: u64) -> SecurityReport {
    let terms = (*report.terms()).map(|term| {
        if term.label == LOOKUP_LABEL {
            SecurityTerm::new(term.label, term.bits.saturating_sub(correction))
        } else {
            term
        }
    });
    SecurityReport::new(terms)
}

/// Computes a relation's conjectured security report, per protocol round.
///
/// `num_boundary_terms` counts the lookup fractions the relation's boundary consumes once per
/// proof, on top of the per-row fractions recorded in `air_shape`; their contribution is applied
/// by [`lookup_boundary_correction`].
pub fn security_report(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air_shape: &AirShape,
    num_boundary_terms: u32,
) -> SecurityReport {
    let report = p3_security::budget::security_report(params, instance, air_shape);
    let correction = lookup_boundary_correction(
        num_boundary_terms,
        air_shape.lookup.fractions_per_row,
        instance.log_max_height,
    );
    apply_lookup_correction(report, correction)
}
