// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden; source mapping and changes are recorded in provenance/README.md.

//! Numeric geometry supplied by the compiled relation and verified proof.

/// Shape of the proof instance being graded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InstanceShape {
    /// Log2 of the largest AIR trace height in the proof.
    ///
    /// A lifted (multi-AIR) statement commits every matrix at the maximum height and tests a
    /// single FRI instance against it, with shorter AIRs opened at powers of the same
    /// out-of-domain point; every degree-dependent error therefore scales with this height, not
    /// with each AIR's own. A single-AIR statement uses its own trace height directly.
    pub log_max_height: u32,
    /// Log2 of the challenge field size, in fixed point.
    /// Must be in `1..=fixed::from_bits(u32::MAX)`; values outside the supported
    /// whole-bit range are malformed and report zero security.
    pub field_bits: u64,
    /// Collision resistance of the commitment hash, in whole bits.
    pub collision_resistance: u32,
}

impl InstanceShape {
    /// The ceiling any reported level is capped at: no argument compiled with this transcript can
    /// exceed the smaller of the challenge-field size and the commitment hash's collision
    /// resistance.
    pub const fn cap(&self) -> u64 {
        if self.field_bits == 0 || self.field_bits > super::fixed::from_bits(u32::MAX) {
            return 0;
        }
        let collision = super::fixed::from_bits(self.collision_resistance);
        if collision < self.field_bits {
            collision
        } else {
            self.field_bits
        }
    }
}

/// Shape of a LogUp-style lookup argument, aggregated over every AIR in the proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupShape {
    /// Total lookup fractions emitted per row, summed over all AIRs.
    ///
    /// Bounds the number of distinct bus messages an adversary can place in an unbalanced
    /// multiset at `fractions_per_row · 2^log_max_height`.
    pub fractions_per_row: u32,
    /// Maximum message width, i.e. the highest power of the second lookup challenge a denominator
    /// can reach.
    pub max_message_width: u32,
}

/// Shape of the AIRs being proved, aggregated over every AIR in the proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AirShape {
    /// Total constraints batched into the composition polynomial, plus one slot for each AIR
    /// beyond the first when a second challenge batches multiple AIRs together (`0` slots for a
    /// single-AIR statement, which needs no cross-AIR batching challenge).
    pub num_composed_constraints: u32,
    /// Maximum constraint degree over all AIRs.
    pub max_constraint_degree: u32,
    /// Exact committed quotient chunk count, including ZK degree padding and doubling.
    pub num_quotient_chunks: u32,
    /// Maximum number of out-of-domain points referenced per committed column — one per distinct
    /// point the AIR's rotations induce: `2` for an AIR that opens `local` and `next`, `1` for an
    /// AIR whose constraints all read a single row, and higher for a wider rotation set.
    ///
    /// Read by the out-of-domain round, independent of [`Self::num_deep_terms`].
    pub max_combo: u32,
    /// Total committed columns opened by a DEEP-quotient batching argument, plus one slot per
    /// out-of-domain point, or `None` when the protocol performs no α/β column-batching reduction
    /// over its committed openings. The budget's out-of-domain round is charged regardless of this
    /// field; `None` only waives the separate DEEP-composition round.
    pub num_deep_terms: Option<u32>,
    /// Lookup argument shape, or `None` when the protocol has no lookup round.
    /// A present shape with zero fractions is invalid and reports zero security.
    pub lookup: Option<LookupShape>,
}
