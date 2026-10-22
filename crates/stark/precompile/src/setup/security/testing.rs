//! Independent Eidos security references and MASM comparison constants.
use miden_air::precompile::policy::{LOG_BLOWUP, LOG_FOLDING_ARITY};
use miden_core::proof::HashFunction;
use miden_stark::security::{
    CHALLENGE_FIELD_BITS, COLLISION_RESISTANCE, EIDOS_CHALLENGE_SAMPLE_BITS,
    security_report_with_hash,
};
use p3_security::{budget::report::LOOKUP_LABEL, fixed};

use super::{AIR_SHAPE, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm};

/// Lookup shape generated from the authored AIR metadata.
pub const LOOKUP_SHAPE: LookupShape = match AIR_SHAPE.lookup {
    Some(shape) => shape,
    None => panic!("canonical AIR has lookup arguments"),
};

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
pub(super) fn fixed_boundary_fraction_count() -> u64 {
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
