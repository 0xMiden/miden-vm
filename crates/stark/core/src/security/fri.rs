// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden's concrete FRI security calculation; see provenance/README.md.

//! FRI low-degree-test soundness.
//!
//! Conjectured regime: random-words bound, [2025/2010] §1.5.
//! Proven regime: round-by-round, [2024/1553] Theorems 2 & 3, with the
//! DKT26 Johnson line-MCA commit bound ([2026/2056] Theorem 5.12 and
//! Appendix B.1–B.2, extended to powers batching through the order-zero
//! case of §7.2, Equation (88)). Its characteristic-free transfer is Lemma
//! 5.3, not the positive-order powers-batching corollary in that section.
use alloc::vec::Vec;

use libm::{log2, pow};

use super::{
    ErrorBits,
    proven::{AirParameters, InstanceParameters},
    proximity::{
        LDR_M_CAP, alpha_ldr_m, alpha_udr, compute_upper_m, gamma_ldr_m,
        johnson_exceptional_line_count_log2,
    },
};

/// Private numerical FRI inputs resolved from the PCS parameters and actual final domain.
///
/// The last partially filled folding round is included before these values are assembled.
#[derive(Copy, Clone, Debug)]
pub struct FriRegime {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}

impl FriRegime {
    const fn folding_factor(self) -> f64 {
        (1usize << self.max_log_arity) as f64
    }
}

/// Conjectured low-degree-test soundness (random-words, [2025/2010] §1.5).
///
/// `b = num_queries · (−log2(ρ + η)) + query_pow`,
/// with `η ≈ (log2(e/ρ) · ρ) / log2(q)`.
#[cfg(any(test, feature = "testing"))]
pub fn conjectured_error(regime: &FriRegime, shape: &InstanceParameters) -> ErrorBits {
    if regime.log_blowup == 0 || shape.modulus_bits == 0 {
        return ErrorBits::from_log2(regime.query_pow_bits as f64);
    }
    let log_blowup_f = regime.log_blowup as f64;
    let rho = pow(2.0, -log_blowup_f);
    let log2_e_over_rho = core::f64::consts::LOG2_E + log_blowup_f;
    let eta = (log2_e_over_rho * rho) / shape.modulus_bits as f64;
    let effective = rho + eta;
    if effective <= 0.0 || effective >= 1.0 {
        return ErrorBits::from_log2(regime.query_pow_bits as f64);
    }
    let bits_per_query = -log2(effective);
    let bits = regime.num_queries as f64 * bits_per_query + regime.query_pow_bits as f64;
    ErrorBits::from_log2(bits)
}

/// FRI commit-phase per-round error in the conjectured regime.
///
/// Identical to [`commit_phase_error_udr`], and deliberately so: the bound
/// counts the folding challenges that are *exceptional* for a given committed
/// word, and that count does not depend on the decoding regime. What the
/// random-words conjecture buys is the removal of the list-size multiplier
/// `L⁺` that the Johnson-bound analysis pays (see
/// the conjectured round budget) — it does not assert that a
/// bad folding challenge cannot exist. Dropping the round entirely, as an
/// LDT-only conjectured number does, therefore overstates security for a large
/// LDE domain over a small field.
///
/// Returns `None` when no fold occurs, in which case there is no such round.
#[cfg(test)]
fn conjectured_commit_phase_error(
    regime: &FriRegime,
    shape: &InstanceParameters,
) -> Option<ErrorBits> {
    commit_phase_error_udr(regime, shape)
}

/// FRI commit-phase per-round error in UDR.
///
/// ε ≤ (folding − 1)·(n + 1) / |F|, applied when at least one fold occurs.
/// Slightly conservative versus `soundcalc`'s tighter `(γn + 1)` factor.
///
/// Returns `None` when `regime.max_log_arity` is `0` (folding factor `1`,
/// i.e. no fold at all) — such a regime has no commit-phase round, rather
/// than being indistinguishable from arity 2.
pub fn commit_phase_error_udr(regime: &FriRegime, shape: &InstanceParameters) -> Option<ErrorBits> {
    let folding_minus_one = regime.folding_factor() - 1.0;
    if folding_minus_one <= 0.0 {
        return None;
    }
    let lde_log = shape.log_trace_length + regime.log_blowup;
    let num_layers = lde_log.saturating_sub(regime.log_final_poly_len) / regime.max_log_arity;
    if num_layers == 0 {
        return None;
    }
    let n = (1u64 << lde_log) as f64;
    let bits = shape.modulus_bits as f64 - log2(folding_minus_one * (n + 1.0))
        + regime.commit_pow_bits as f64;
    Some(ErrorBits::from_log2(bits.max(0.0)))
}

/// FRI commit-phase per-round error in LDR with explicit proximity
/// parameter `m`. DKT26 Theorem 5.12 and Appendix B.1–B.2 give the
/// Johnson-regime line-MCA count `C = 8·n·(m + 1/2)^3/(3·rho_minus)`;
/// multiplying by `folding − 1` accounts for the polynomial-curve degree of
/// a folding round. We also retain the independent `n/|F|` bound from
/// [2024/1553] and take the minimum of their security bits. Round-by-
/// round soundness is dominated by round 0 (largest `n`), so we use
/// `n = lde_domain_size` for every round.
/// For positive-degree codes at `m >= 3`, MCA gives fewer security bits and
/// determines this minimum. Reconstruction can instead cap the separate
/// constant-code bound.
///
/// Returns `None` when `regime.max_log_arity` is `0` (folding factor `1`,
/// i.e. no fold at all) — such a regime has no commit-phase round, rather
/// than being indistinguishable from arity 2.
pub fn commit_phase_error_ldr_m(
    regime: &FriRegime,
    shape: &InstanceParameters,
    m: usize,
) -> Option<ErrorBits> {
    let rho = pow(2.0, -(regime.log_blowup as f64));
    let pp = gamma_ldr_m(regime.log_blowup, m);
    if pp <= 0.0 {
        return Some(ErrorBits::from_log2(0.0));
    }
    let folding_minus_one = regime.folding_factor() - 1.0;
    if folding_minus_one <= 0.0 {
        return None;
    }
    let lde_log = shape.log_trace_length + regime.log_blowup;
    let line_count_log =
        johnson_exceptional_line_count_log2(shape.log_trace_length, regime.log_blowup, m);
    let bits_linear = shape.modulus_bits as f64 - line_count_log - log2(folding_minus_one)
        + regime.commit_pow_bits as f64;

    let log_n_plus_one = lde_log as f64 + log2(1.0 + pow(2.0, -(lde_log as f64)));

    let bits_n_over_q = shape.modulus_bits as f64
        - log2(regime.folding_factor())
        - log_n_plus_one
        - log2(2.0 * m as f64 + 1.0)
        + 0.5 * log2(rho)
        + regime.commit_pow_bits as f64;

    Some(ErrorBits::from_log2(bits_linear.min(bits_n_over_q).max(0.0)))
}

/// FRI query-phase error: ε ≤ αᵏ, contributing `query_pow − k·log2(α)` bits.
pub fn query_phase_error(alpha: f64, num_queries: usize, query_pow_bits: usize) -> ErrorBits {
    if !alpha.is_finite() || alpha <= 0.0 || alpha >= 1.0 {
        return ErrorBits::from_log2(0.0);
    }
    let bits = query_pow_bits as f64 - log2(pow(alpha, num_queries as f64));
    ErrorBits::from_log2(bits)
}

/// Proven LDT-only error in the UDR regime. Combines commit-phase and
/// query-phase contributions; AIR/DEEP terms compose at the protocol
/// call site.
pub fn proven_error_udr(
    regime: &FriRegime,
    air: &AirParameters,
    shape: &InstanceParameters,
) -> ErrorBits {
    if regime.log_blowup == 0 || shape.log_trace_length == 0 || shape.modulus_bits == 0 {
        return ErrorBits::from_log2(0.0);
    }
    let alpha = alpha_udr(shape.log_trace_length, regime.log_blowup, air.max_combo);
    let lde = (1u64 << (shape.log_trace_length + regime.log_blowup)) as f64;
    let k = (1u64 << shape.log_trace_length) as f64;
    if k + air.max_combo as f64 >= alpha * lde {
        return ErrorBits::from_log2(0.0);
    }
    let query = query_phase_error(alpha, regime.num_queries, regime.query_pow_bits);
    commit_phase_error_udr(regime, shape).map_or(query, |commit| ErrorBits::min(&[commit, query]))
}

/// Proven LDT-only error in the LDR regime with explicit `m`.
pub fn proven_error_ldr_m(
    regime: &FriRegime,
    air: &AirParameters,
    shape: &InstanceParameters,
    m: usize,
) -> ErrorBits {
    if regime.log_blowup == 0 || shape.log_trace_length == 0 || shape.modulus_bits == 0 {
        return ErrorBits::from_log2(0.0);
    }
    let alpha = alpha_ldr_m(regime.log_blowup, m);
    if alpha >= 1.0 {
        return ErrorBits::from_log2(0.0);
    }
    let pp = gamma_ldr_m(regime.log_blowup, m);
    if pp <= 0.0 {
        return ErrorBits::from_log2(0.0);
    }
    let lde = (1u64 << (shape.log_trace_length + regime.log_blowup)) as f64;
    let k = (1u64 << shape.log_trace_length) as f64;
    if k + air.max_combo as f64 >= (1.0 - pp) * lde {
        return ErrorBits::from_log2(0.0);
    }
    let query = query_phase_error(alpha, regime.num_queries, regime.query_pow_bits);
    commit_phase_error_ldr_m(regime, shape, m)
        .map_or(query, |commit| ErrorBits::min(&[commit, query]))
}

/// Search `m ∈ [3, min(compute_upper_m, LDR_M_CAP)]` for the value
/// maximising LDR security; returns `(best_m, ldt_error_at_best_m)`.
///
/// Optimizes `min(commit, query)` only — the LDT-only error — not the full
/// `min(ALI, DEEP, commit, query)` composite ultimately reported by
/// the complete Miden security report. In practice ALI/DEEP don't bind at
/// the optimum, so the chosen `m` matches what optimizing the full
/// composite would pick, but this function does not verify that.
#[cfg(test)]
fn best_ldr_m(
    regime: &FriRegime,
    air: &AirParameters,
    shape: &InstanceParameters,
) -> Option<(usize, ErrorBits)> {
    ldr_candidates(regime, air, shape)
        .into_iter()
        .max_by(|a, b| a.1.bits().partial_cmp(&b.1.bits()).unwrap_or(core::cmp::Ordering::Equal))
}

/// Every admissible `m ∈ [3, min(compute_upper_m, LDR_M_CAP)]` with the
/// LDT-only error attained there, in increasing order of `m`.
///
/// The complete Miden report evaluates every candidate because lookup and opening-batching
/// losses depend on the same `m`. Selecting a FRI-only optimum first would lose that dependency.
///
/// Empty when the trace is too small to admit any valid `m`.
pub fn ldr_candidates(
    regime: &FriRegime,
    air: &AirParameters,
    shape: &InstanceParameters,
) -> Vec<(usize, ErrorBits)> {
    let trace_length = 1usize << shape.log_trace_length;
    let m_max = core::cmp::min(compute_upper_m(trace_length, air.max_combo), LDR_M_CAP);
    let m_min = 3usize;
    if m_max < m_min {
        return Vec::new();
    }
    (m_min..=m_max)
        .map(|m| (m, proven_error_ldr_m(regime, air, shape, m)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benchmark_regime() -> FriRegime {
        FriRegime {
            log_blowup: 1,
            num_queries: 100,
            log_final_poly_len: 0,
            max_log_arity: 3,
            commit_pow_bits: 0,
            query_pow_bits: 16,
        }
    }

    fn benchmark_shape() -> InstanceParameters {
        InstanceParameters {
            log_trace_length: 20,
            modulus_bits: 252,
            collision_resistance: 128,
            num_batched_functions: 1,
        }
    }

    fn benchmark_air() -> AirParameters {
        AirParameters {
            num_constraints: 1,
            max_constraint_degree: 2,
            num_quotient_chunks: 1,
            max_combo: 2,
        }
    }

    /// Regression vector for the benchmark configuration: log_blowup=1,
    /// num_queries=100, query_pow=16, commit_pow=0, max_log_arity=3,
    /// |F|=252 bits, trace 2^20, num_constraints=1, max_deg=2,
    /// max_combo=2 → UDR=57 bits, LDR=65 bits.
    #[test]
    fn proven_security_regression_benchmark_high_arity() {
        let regime = benchmark_regime();
        let air = benchmark_air();
        let shape = benchmark_shape();

        let udr_ldt = proven_error_udr(&regime, &air, &shape);
        let ldr_ldt = best_ldr_m(&regime, &air, &shape).unwrap().1;

        assert_eq!(udr_ldt.bits().floor() as usize, 57);
        assert_eq!(ldr_ldt.bits().floor() as usize, 65);
    }

    /// The conjectured commit-phase round is a real constraint, not a
    /// formality: over a 128-bit field with a 2^26 LDE domain it lands near 100
    /// bits, below a 128-bit target, so an LDT-only conjectured number that
    /// omits it overstates security. It also matches the UDR bound exactly —
    /// the conjecture removes the list-size multiplier, not the count of
    /// exceptional folding challenges.
    #[test]
    fn conjectured_commit_phase_binds_below_a_128_bit_target() {
        let regime = FriRegime {
            log_blowup: 3,
            num_queries: 27,
            log_final_poly_len: 0,
            max_log_arity: 2,
            commit_pow_bits: 0,
            query_pow_bits: 16,
        };
        let shape = InstanceParameters {
            log_trace_length: 23,
            modulus_bits: 128,
            collision_resistance: 128,
            num_batched_functions: 1,
        };

        let commit = conjectured_commit_phase_error(&regime, &shape).expect("folds occur");
        // |F| - log2(3 * (2^26 + 1)) = 128 - 27.585
        assert!(
            (commit.bits() - (128.0 - libm::log2(3.0 * (65_536.0 * 1024.0 + 1.0)))).abs() < 1e-9
        );
        assert!(commit.bits() < 128.0, "got {}", commit.bits());
        assert_eq!(commit.bits(), commit_phase_error_udr(&regime, &shape).unwrap().bits());
    }

    /// Commit-phase grinding is credited to the commit-phase term and to
    /// nothing else, and a fold-free configuration has no such round at all.
    #[test]
    fn conjectured_commit_phase_credits_only_its_own_grinding() {
        let base = benchmark_regime();
        let shape = benchmark_shape();

        let ground = FriRegime { commit_pow_bits: 12, ..base };
        let b0 = conjectured_commit_phase_error(&base, &shape).expect("folds occur");
        let b12 = conjectured_commit_phase_error(&ground, &shape).expect("folds occur");
        assert!((b12.bits() - b0.bits() - 12.0).abs() < 1e-12);
        // The query phase is untouched by it.
        assert_eq!(
            conjectured_error(&ground, &shape).bits(),
            conjectured_error(&base, &shape).bits()
        );

        // Folding down to the full domain leaves no commit round.
        let no_folds = FriRegime {
            log_final_poly_len: shape.log_trace_length + base.log_blowup,
            ..base
        };
        assert!(conjectured_commit_phase_error(&no_folds, &shape).is_none());
    }

    /// `max_log_arity: 0` (folding factor 1) is a genuinely fold-free regime,
    /// not a stand-in for arity 2: both the UDR and LDR commit-phase bounds
    /// must report no round rather than silently clamping to arity 2's
    /// `folding_minus_one = 1`.
    #[test]
    fn arity_one_reports_no_commit_round_rather_than_impersonating_arity_two() {
        let base = benchmark_regime();
        let shape = benchmark_shape();
        let air = benchmark_air();
        let no_arity = FriRegime { max_log_arity: 0, ..base };

        assert!(commit_phase_error_udr(&no_arity, &shape).is_none());
        assert!(commit_phase_error_ldr_m(&no_arity, &shape, 10).is_none());
        assert!(conjectured_commit_phase_error(&no_arity, &shape).is_none());

        // The UDR/LDR composites fall back to the query-phase error alone.
        assert_eq!(
            proven_error_udr(&no_arity, &air, &shape).bits(),
            query_phase_error(
                alpha_udr(shape.log_trace_length, no_arity.log_blowup, air.max_combo),
                no_arity.num_queries,
                no_arity.query_pow_bits,
            )
            .bits()
        );
    }

    /// FRI-only Johnson line-MCA vector: k = 2^20, blowup = 8,
    /// arity = 4, m = 3, commit grinding = 28, query grinding = 17, and
    /// 81 queries over a conservative 127-bit field. This is an LDT-only
    /// example, not a complete VM security claim.
    #[test]
    fn johnson_line_mca_fri_example_keeps_curve_and_grinding_terms() {
        let regime = FriRegime {
            log_blowup: 3,
            num_queries: 81,
            log_final_poly_len: 0,
            max_log_arity: 2,
            commit_pow_bits: 28,
            query_pow_bits: 17,
        };
        let shape = InstanceParameters {
            log_trace_length: 20,
            modulus_bits: 127,
            collision_resistance: 128,
            num_batched_functions: 1,
        };

        let commit = commit_phase_error_ldr_m(&regime, &shape, 3)
            .expect("arity four has folding rounds")
            .bits();
        let alpha = alpha_ldr_m(regime.log_blowup, 3);
        let query = query_phase_error(alpha, regime.num_queries, regime.query_pow_bits).bits();
        let ldt = proven_error_ldr_m(&regime, &benchmark_air(), &shape, 3).bits();
        assert!((ldt - 120.4862138717).abs() < 1e-9, "commit={commit}, query={query}, ldt={ldt}",);
        assert!((commit - 120.57793385796532).abs() < 1e-9, "got {commit}");

        let ungrounded = FriRegime { commit_pow_bits: 0, ..regime };
        let ungrounded_commit = commit_phase_error_ldr_m(&ungrounded, &shape, 3)
            .expect("arity four has folding rounds")
            .bits();
        assert!((commit - ungrounded_commit - 28.0).abs() < 1e-9);
        assert_eq!(
            query_phase_error(alpha, regime.num_queries, regime.query_pow_bits).bits(),
            query_phase_error(alpha, ungrounded.num_queries, ungrounded.query_pow_bits).bits()
        );
    }

    #[test]
    fn conjectured_bounded_by_collision_resistance() {
        let regime = FriRegime {
            log_blowup: 8,
            num_queries: 32,
            log_final_poly_len: 0,
            max_log_arity: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
        };
        let shape = InstanceParameters {
            log_trace_length: 16,
            modulus_bits: 128,
            collision_resistance: 128,
            num_batched_functions: 1,
        };
        let bits = conjectured_error(&regime, &shape)
            .bits()
            .min(shape.collision_resistance as f64)
            .min(shape.modulus_bits as f64)
            .floor() as usize;
        assert_eq!(bits, 128);
    }
}
