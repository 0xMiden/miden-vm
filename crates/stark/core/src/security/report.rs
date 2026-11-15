// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden; source mapping and changes are recorded in provenance/README.md.

//! Fixed-point conjectured reports and floating-point proven reports.

use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::Serialize;

/// Label for the lookup / permutation-argument bus-challenge round.
pub const LOOKUP_LABEL: &str = "lookup-challenge";
/// Label for the constraint-batching round.
pub const COMPOSITION_LABEL: &str = "constraint-composition";
/// Label for the out-of-domain evaluation round.
pub const OUT_OF_DOMAIN_LABEL: &str = "out-of-domain";
/// Label for the DEEP-quotient batching round.
pub const DEEP_COMPOSITION_LABEL: &str = "deep-composition";
/// Label for the FRI commit-phase folding rounds.
pub const FOLDING_LABEL: &str = "fri-folding";
/// Label for the FRI query round.
pub const QUERY_LABEL: &str = "fri-query";
/// Label for the commitment-collision cap.
pub const COLLISION_LABEL: &str = "commitment-collision";

/// Number of rounds a [`SecurityReport`] carries.
pub const NUM_TERMS: usize = 7;

/// Proven AIR-composition round.
pub const ALI_LABEL: &str = "air-composition";
/// Proven DEEP-ALI round.
pub const DEEP_LABEL: &str = "deep-ali";
/// Proven low-degree-test round.
pub const LDT_LABEL: &str = "low-degree-test";
/// Proven opening-batching round.
pub const BATCH_LABEL: &str = "batch-combination";
/// Reference low-degree-test query phase.
pub const LDT_QUERY_LABEL: &str = "ldt-query-phase";
/// Reference low-degree-test commit phase.
pub const LDT_COMMIT_LABEL: &str = "ldt-commit-phase";

/// One round's contribution, as `-log2(error)` in fixed point.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecurityTerm {
    /// Which round this bounds.
    pub label: &'static str,
    /// Attained bits for the round, grinding included, in fixed point.
    pub bits: u64,
}

impl SecurityTerm {
    /// Builds a term from a label and its fixed-point bit count.
    pub const fn new(label: &'static str, bits: u64) -> Self {
        Self { label, bits }
    }
}

/// The per-round soundness breakdown of one proof configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecurityReport {
    terms: [SecurityTerm; NUM_TERMS],
}

impl SecurityReport {
    /// Builds a report from its rounds.
    pub const fn new(terms: [SecurityTerm; NUM_TERMS]) -> Self {
        Self { terms }
    }

    /// Every round.
    pub const fn terms(&self) -> &[SecurityTerm; NUM_TERMS] {
        &self.terms
    }

    /// The round that binds — the one attaining the minimum.
    ///
    /// Ties resolve to the earliest such round, so the reported bottleneck is the one an
    /// adversary reaches first.
    pub const fn binding_term(&self) -> SecurityTerm {
        let mut binding = self.terms[0];
        let mut index = 1;
        while index < NUM_TERMS {
            if self.terms[index].bits < binding.bits {
                binding = self.terms[index];
            }
            index += 1;
        }
        binding
    }

    /// Attained conjectured security, in fixed point.
    pub const fn attained(&self) -> u64 {
        self.binding_term().bits
    }

    /// Attained conjectured security in whole bits, rounded down.
    pub const fn security_level(&self) -> u32 {
        super::fixed::to_bits(self.attained())
    }
}

use libm::log2;

/// `-log2(error_probability)`. Higher = tighter bound.
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
pub struct ErrorBits(pub f64);

impl ErrorBits {
    pub const fn from_log2(bits: f64) -> Self {
        Self(bits)
    }

    pub fn from_prob(p: f64) -> Self {
        Self(-log2(p))
    }

    /// `-log2(sum of error probabilities)`. Tight composition; use this
    /// when terms are independent or the union bound is the operative
    /// bound.
    pub fn sum(errors: &[Self]) -> Self {
        let total: f64 = errors.iter().map(|e| pow2_neg(e.0)).sum();
        Self::from_prob(total)
    }

    /// Minimum bits across terms. Loose but cheap — equivalent to taking
    /// the largest single error probability.
    #[allow(clippy::missing_const_for_fn)] // iterator / f64::min are not const
    pub fn min(errors: &[Self]) -> Self {
        let m = errors.iter().map(|e| e.0).fold(f64::INFINITY, f64::min);
        Self(m)
    }

    pub const fn bits(self) -> f64 {
        self.0
    }

    pub fn floor(self) -> usize {
        libm::floor(self.0) as usize
    }
}

fn pow2_neg(bits: f64) -> f64 {
    libm::pow(2.0, -bits)
}

/// A single named soundness contribution, in `−log2(error)` bits.
///
/// The label names the error source, and the crate charging it picks the name.
///
/// A protocol composing two instances of one scheme sees that label twice.
///
/// Naming the instance is what the component is for.
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
#[serde(rename = "SecurityTerm")]
pub struct ProvenSecurityTerm {
    /// Error source this term charges.
    pub label: &'static str,
    /// Which of the composing protocol's parts charged it, when there is a choice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<&'static str>,
    /// The bound itself, in `−log2(error)` bits.
    pub bits: ErrorBits,
}

impl ProvenSecurityTerm {
    /// A term charged by whatever crate owns the error source.
    ///
    /// The composing protocol is the only side that can name a component, so this leaves none.
    pub const fn new(label: &'static str, bits: ErrorBits) -> Self {
        Self { label, component: None, bits }
    }

    /// The same term, attributed to one part of the composing protocol.
    #[must_use]
    pub const fn in_component(mut self, component: &'static str) -> Self {
        self.component = Some(component);
        self
    }
}

/// The proximity regime a [`RegimeReport`] was evaluated in.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum Regime {
    /// Unique-decoding regime (list size 1).
    UniqueDecoding,
    /// List-decoding regime at proximity parameter `m`.
    ListDecoding { m: usize },
    /// Conjectured random-words regime, at list size one.
    ///
    /// Correlated agreement is assumed up to list-decoding capacity.
    ///
    Conjectured,
    /// Legacy conjectured regime, on the pre-random-words ethSTARK query bound.
    ///
    /// For FRI this omits the folding round.
    ///
    Legacy,
}

/// Full soundness breakdown within a single proximity regime.
///
/// The terms hold every contribution, plus the commitment-collision cap.
///
/// The attained security is the minimum over all of them.
///
/// A collision, or any single binding error, forges the proof.
///
/// A report retains the bound for one selected decoding regime.
///
/// Reports preserve their explicit regime and ordered terms.
///
/// Each has one regime, so neither needs a [`ProvenSecurityReport`] envelope to maximize over.
#[derive(Clone, Debug, Serialize)]
pub struct RegimeReport {
    pub regime: Regime,
    terms: Vec<ProvenSecurityTerm>,
}

impl RegimeReport {
    /// Builds a report from its labeled terms.
    ///
    /// The terms must be non-empty.
    ///
    /// Every normal regime carries AIR, DEEP, low-degree-test and collision terms.
    pub(super) fn new(regime: Regime, terms: Vec<ProvenSecurityTerm>) -> Self {
        debug_assert!(!terms.is_empty(), "a regime report must carry at least one term");
        Self { regime, terms }
    }

    /// Every soundness contribution in this regime, cap included.
    pub fn terms(&self) -> &[ProvenSecurityTerm] {
        &self.terms
    }

    /// The binding term, which is the one with the fewest bits.
    ///
    /// A regime always carries at least four terms, so there is always one.
    pub fn binding(&self) -> ProvenSecurityTerm {
        self.terms
            .iter()
            .copied()
            .min_by(|a, b| a.bits.bits().partial_cmp(&b.bits.bits()).unwrap_or(Ordering::Equal))
            .expect("a regime report always carries the ALI/DEEP/LDT/collision terms")
    }

    /// Attained security in this regime, in bits.
    pub fn security_bits(&self) -> f64 {
        self.binding().bits.bits()
    }
}

/// Proven-soundness report across both proximity regimes.
///
/// Each regime is an independent lower bound on round-by-round soundness.
///
/// So the attained security is the larger of the two.
#[derive(Clone, Debug, Serialize)]
#[serde(rename = "SecurityReport")]
pub struct ProvenSecurityReport {
    pub udr: RegimeReport,
    /// Absent when no valid list-decoding regime exists for the instance.
    pub ldr: Option<RegimeReport>,
}

impl ProvenSecurityReport {
    /// Attained proven security in bits: the better of the two regimes.
    pub fn security_bits(&self) -> f64 {
        let ldr = self.ldr.as_ref().map_or(0.0, RegimeReport::security_bits);
        self.udr.security_bits().max(ldr)
    }

    /// The winning regime and its binding term.
    pub fn binding(&self) -> (Regime, ProvenSecurityTerm) {
        match &self.ldr {
            Some(ldr) if ldr.security_bits() > self.udr.security_bits() => {
                (ldr.regime, ldr.binding())
            },
            _ => (self.udr.regime, self.udr.binding()),
        }
    }
}

impl SecurityReport {
    pub(super) const fn zero() -> Self {
        Self::new([
            SecurityTerm::new(LOOKUP_LABEL, 0),
            SecurityTerm::new(COMPOSITION_LABEL, 0),
            SecurityTerm::new(OUT_OF_DOMAIN_LABEL, 0),
            SecurityTerm::new(DEEP_COMPOSITION_LABEL, 0),
            SecurityTerm::new(FOLDING_LABEL, 0),
            SecurityTerm::new(QUERY_LABEL, 0),
            SecurityTerm::new(COLLISION_LABEL, 0),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn report_ties_keep_the_first_term_and_unique_decoding_regime() {
        let fixed = SecurityReport::new([
            SecurityTerm::new("first", 7),
            SecurityTerm::new("second", 7),
            SecurityTerm::new("third", 8),
            SecurityTerm::new("fourth", 8),
            SecurityTerm::new("fifth", 8),
            SecurityTerm::new("sixth", 8),
            SecurityTerm::new("seventh", 8),
        ]);
        assert_eq!(fixed.binding_term().label, "first");
        let terms = || {
            vec![
                ProvenSecurityTerm::new("first", ErrorBits::from_log2(7.0)),
                ProvenSecurityTerm::new("second", ErrorBits::from_log2(7.0)),
            ]
        };
        let proven = ProvenSecurityReport {
            udr: RegimeReport::new(Regime::UniqueDecoding, terms()),
            ldr: Some(RegimeReport::new(Regime::ListDecoding { m: 3 }, terms())),
        };
        assert_eq!(proven.udr.binding().label, "first");
        assert_eq!(proven.binding().0, Regime::UniqueDecoding);
        assert_eq!(proven.udr.terms()[1].label, "second");
    }
}
