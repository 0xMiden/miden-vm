// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden; source mapping and changes are recorded in ../provenance/README.md.

//! Independent floating-point reference calculations for numerical regression tests.
//!
//! These are explicit numerical helpers, not a protocol-generic or production AIR adapter.

use super::{SecurityCase, fixed};
use crate::security::{ErrorBits, ProvenSecurityReport, ProvenSecurityTerm, budget, proven};
pub use crate::security::{
    fri::{FriRegime, commit_phase_error_udr, conjectured_error},
    proven::{AirParameters, InstanceParameters, composition_error, deep_ali_error},
    proximity::{LDR_M_CAP, batching_error_udr, list_size_ldr_m},
};

/// Reference grinding placement. Raw cases may exercise sites the Miden PCS does not expose.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrindingSites {
    pub out_of_domain: usize,
    pub batch_combination: usize,
    pub lookup_challenge: usize,
}
impl GrindingSites {
    pub const NONE: Self = Self {
        out_of_domain: 0,
        batch_combination: 0,
        lookup_challenge: 0,
    };
}

/// Add the cost of resampling a challenge after its grinding round.
pub const fn boost(error: ErrorBits, pow_bits: usize) -> ErrorBits {
    ErrorBits::from_log2(error.bits() + pow_bits as f64)
}

const LOGUP_LABEL: &str = "logup-fingerprint";
use libm::log2;

/// Shape of a LogUp lookup argument, as seen by its soundness bound.
#[derive(Copy, Clone, Debug)]
pub struct LogUpAir {
    /// Number of bus messages emitted per trace row, summed across all buses
    /// (global + local interactions). Each is one denominator factor.
    pub num_interactions: usize,
    /// Widest message payload tuple (`max_message_width`) — the degree of the
    /// `beta`-compression.
    pub max_message_width: usize,
}

/// `-log2(ε_logup)` in bits, following `ε_logup ≤ N·(W + 2) / |EF|` with
/// `N = num_interactions · 2^log_trace_length` and `W = max_message_width`.
///
/// The `W + 2` covers both ways a sampled `(alpha, beta)` breaks the argument: a root of the
/// cleared numerator, and a vanishing denominator that lets a message be dropped.
///
/// Returns 0 bits for degenerate inputs (no interactions, or unknown field
/// size). Prefer [`security_term`], which omits the term entirely when there
/// are no interactions rather than reporting a binding 0-bit bound.
pub fn fingerprint_error(air: &LogUpAir, shape: &InstanceParameters) -> ErrorBits {
    if air.num_interactions == 0 || shape.modulus_bits == 0 {
        return ErrorBits::from_log2(0.0);
    }
    let log_n = shape.log_trace_length as f64 + log2(air.num_interactions as f64);
    let width = air.max_message_width.max(1) as f64;
    let bits = shape.modulus_bits as f64 - log_n - log2(width + 2.0);
    ErrorBits::from_log2(bits.max(0.0))
}

/// The LogUp fingerprint term for use in `extras`, or `None` when the AIR has
/// no interactions (no lookup argument, hence no term).
///
/// `grinding.lookup_challenge` is the grind sited immediately before
/// `(alpha, beta)` are sampled; it boosts this term and nothing else.
pub fn security_term(
    air: &LogUpAir,
    shape: &InstanceParameters,
    grinding: &GrindingSites,
) -> Option<ProvenSecurityTerm> {
    if air.num_interactions == 0 {
        return None;
    }
    Some(ProvenSecurityTerm::new(
        LOGUP_LABEL,
        boost(fingerprint_error(air, shape), grinding.lookup_challenge),
    ))
}

/// Previous reference policy: compose the same lookup bound in both decoding regimes.
///
/// Miden's production report instead charges each candidate's list size before selecting the
/// strongest complete bound. Retaining this distinction detects loss of that accounting.
pub fn unscaled_lookup_report(case: &SecurityCase) -> (ProvenSecurityReport, f64) {
    let inputs = case.numerical_inputs();
    let lookup_bits = budget::lookup_bits(&inputs);
    (
        proven::report_without_lookup_list_loss(&inputs, lookup_bits),
        lookup_bits as f64 / fixed::ONE as f64,
    )
}
