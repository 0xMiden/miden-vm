//! Generated security geometry and constants for the production Miden VM relation.
//!
//! The AIR shape entering the security calculation is stored in [`AIR_SHAPE`], allowing the MASM
//! estimator to use it without evaluating the AIRs symbolically. Runtime security reporting lives
//! in the VM STARK backend. Independent comparison checks use
//! `miden_air_source::vm::geometry::derive_air_shape`.

use miden_core::proof::HashFunction;
/// Types describing the generated AIR and lookup shapes.
pub use miden_stark::security::{AirShape, LookupShape};
use miden_stark::security::{CHALLENGE_FIELD_BITS, EIDOS_CHALLENGE_SAMPLE_BITS};
use p3_security::{budget::InstanceShape, fixed};

use crate::vm::config;

/// Column alignment of the commitment scheme, in base field elements.
///
/// The commitment sponge absorbs whole rates, so a committed matrix is padded up to a multiple of
/// the rate.
pub const COMMITMENT_ALIGNMENT: usize = config::SPONGE_RATE;

/// Shape of the Miden VM multi-AIR statement used by the security estimator.
///
/// This is stored rather than derived during verification. `air_shape_matches_symbolic` checks it
/// against the shape obtained by symbolically evaluating the AIRs.
pub const AIR_SHAPE: AirShape = include!(concat!(env!("OUT_DIR"), "/air_shape.rs"));

/// Lookup shape generated from the authored AIR metadata.
pub const LOOKUP_SHAPE: LookupShape = match AIR_SHAPE.lookup {
    Some(shape) => shape,
    None => panic!("canonical AIR has lookup arguments"),
};

/// Raw `(preprocessed, main, auxiliary)` widths of each AIR, compiled from the AIR definitions.
pub const RAW_WIDTHS: &[(usize, usize, usize)] =
    &include!(concat!(env!("OUT_DIR"), "/raw_widths.rs"));

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
pub const BITS_PER_QUERY: u64 =
    fixed::bits_per_query(config::LOG_BLOWUP as u32, CHALLENGE_FIELD_BITS);

/// Collision resistance of the canonical Eidos commitment hash, in whole bits.
///
/// Eidos exposes a 252-bit packed digest, so birthday collisions cost 126 bits.
pub const COLLISION_RESISTANCE: u32 = HashFunction::Eidos.collision_resistance();

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
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << config::LOG_FOLDING_ARITY) - 1));

/// Grinding applied before the out-of-domain point is sampled.
///
/// Lifted STARK samples the point directly after the quotient commitment; its DEEP grinding runs
/// only after the out-of-domain evaluations are bound.
pub const OOD_POW_BITS: u32 = 0;

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
    EIDOS_CHALLENGE_SAMPLE_BITS - FOLDING_COEFFICIENT - fixed::from_bits(config::LOG_BLOWUP as u32);

/// The instance shape of a deployed Miden VM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// `log2(e)`, rounded up, in fixed point. Matches the common MASM estimator's `LOG2_E_FP`.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// Number of lookup fractions `emit_core_boundary` emits unconditionally: the block-hash seed and
/// the two log-deferred-root terminals. Matches `sys::vm::mod.masm`'s
/// `CORE_BOUNDARY_LOOKUP_TERMS`.
pub const CORE_BOUNDARY_LOOKUP_TERMS: u32 = 3;
