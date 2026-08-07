//! Inputs to the round budget: protocol parameters, instance shape, and AIR shape.
//!
//! These mirror the security-relevant subset of the runtime configuration rather than wrapping it.
//! The runtime types live in crates this one must not depend on, and the caller is the only site
//! with visibility into both sides, so it assembles these explicitly.

use crate::fixed;

/// Protocol parameters that enter the round budget.
///
/// Every field is bound into the Fiat-Shamir transcript by `observe_protocol_params`, so a proof
/// cannot be graded under parameters it was not produced with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolParams {
    /// Log2 of the LDE blowup factor; the FRI rate is `2^-log_blowup`.
    pub log_blowup: u32,
    /// Log2 of the FRI folding arity.
    pub log_folding_arity: u32,
    /// Number of FRI query repetitions.
    pub num_queries: u32,
    /// Grinding bits before query index sampling.
    pub query_pow_bits: u32,
    /// Grinding bits before DEEP challenge sampling.
    pub deep_pow_bits: u32,
    /// Grinding bits before each FRI folding challenge.
    pub folding_pow_bits: u32,
    /// Grinding bits before the lookup challenges are sampled.
    ///
    /// The lookup round's error grows linearly in trace length, so this is the only grinding site
    /// whose absence degrades with instance size.
    pub lookup_pow_bits: u32,
}

/// Shape of the proof instance being graded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InstanceShape {
    /// Log2 of the largest AIR trace height in the proof.
    ///
    /// Lifting commits every matrix at the maximum height and tests a single FRI instance against
    /// it, and shorter AIRs are opened at powers of the same out-of-domain point. Every
    /// degree-dependent error therefore scales with this height, not with each AIR's own.
    pub log_max_height: u32,
    /// Log2 of the challenge field size, in fixed point.
    pub field_bits: u64,
    /// Collision resistance of the commitment hash, in whole bits.
    pub collision_resistance: u32,
}

impl InstanceShape {
    /// The ceiling any reported level is capped at: no argument compiled with this transcript can
    /// exceed the smaller of the challenge-field size and the commitment hash's collision
    /// resistance.
    pub const fn cap(&self) -> u64 {
        let collision = fixed::from_bits(self.collision_resistance);
        if collision < self.field_bits {
            collision
        } else {
            self.field_bits
        }
    }
}

/// Shape of the lookup argument, aggregated over every AIR in the proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupShape {
    /// Total lookup fractions emitted per row, summed over all AIRs.
    ///
    /// Bounds the number of distinct bus messages an adversary can place in an unbalanced multiset
    /// at `fractions_per_row · 2^log_max_height`. Boundary messages, which come from public inputs
    /// rather than trace rows, are not counted here; see the lookup round in `conjectured`.
    pub fractions_per_row: u32,
    /// Maximum message width, i.e. the highest power of the second lookup challenge a denominator
    /// can reach.
    pub max_message_width: u32,
}

/// Shape of the AIRs being proved, aggregated over every AIR in the proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AirShape {
    /// Total constraints batched into the composition polynomial, plus one slot per AIR for the
    /// cross-AIR batching challenge.
    pub num_composed_constraints: u32,
    /// Maximum constraint degree over all AIRs.
    pub max_constraint_degree: u32,
    /// Total committed columns opened by the DEEP quotient, plus one slot per out-of-domain point.
    pub num_deep_terms: u32,
    /// Lookup argument shape.
    pub lookup: LookupShape,
}
