// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden's concrete FRI security calculation; see provenance/README.md.

//! Proximity-gap and list-size helpers shared across low-degree-test
//! modules.
//!
//! - UDR (unique-decoding regime): agreement parameter α = (1 + ρ⁺)/2,
//!   list size L⁺ = 1.
//! - LDR (list-decoding regime, BCHKS25 explicit-m): α = (1 + 1/(2m))·√ρ,
//!   proximity parameter γ = 1 − α, list size L⁺ = (m + 1/2)/√ρ.
//!
//! References:
//! - [2020/654] Proximity Gaps for Reed–Solomon Codes
//! - [2024/1553] On the Security of STARKs with FRI
//! - [2025/2055] BCHKS25 Theorem 4.2
//! - \[DKT26\] Reed–Solomon Codes Beyond Johnson, Theorem 5.12 and
//!   Appendix B.1–B.2 (<https://eprint.iacr.org/2026/2056>)

use libm::{floor, log2, pow, sqrt};

/// Performance cap on the proximity parameter `m` searched in LDR
/// analyses. Matches Ethereum's `soundcalc`.
pub const LDR_M_CAP: usize = 1000;

/// `log₂(C)` for the Johnson-regime exceptional line count from DKT26
/// Theorem 5.12 and Appendix B.1–B.2:
///
/// `C = 8 · n · (m + 1/2)^3 / (3 · ρ⁻)`, where
/// `n = 2^(log_degree + log_inv_rate)` and
/// `ρ⁻ = (2^log_degree - 1) / n`.
///
/// The bound is for one received line. A polynomial curve of degree `ell`
/// contributes `ell · C`; callers apply that curve-degree factor. The
/// positive-degree case uses the actual finite Johnson rate `ρ⁻`, rather than
/// the nominal rate `2^log_degree / n`. The logarithmic form avoids integer
/// shifts and sums overflowing for large domains.
///
/// The chosen agreement parameter
/// `alpha = (1 + 1/(2m))·sqrt(k/n)` gives `eta0 >= sqrt(rho_minus)/(2m)`;
/// therefore an explicit `m >= 3` can be larger than the theorem's minimum
/// and still satisfies the DKT26 Appendix B.1 interpolant.
///
/// # Polynomial-curve extension derived here
///
/// The paper states Proposition B.1 for a line. To extend its dimension
/// count, put `D = k - 1`, `t = m + 1/2`, `s = t·sqrt(n/D)` and choose
/// `M = ceil(Ds)`, `B = ceil(s) - 1`, `H = ceil(ell·s²/3) - 1`.
/// Use monomials `X^i Y^j Z^h` with `i + D·j < Ds` and
/// `ell·j + h < ell·s²/3`. Since `s²/3 > s > B >= m`, no slice is truncated.
/// Translation by a degree-`ell` curve bounds the challenge degree of each
/// multiplicity constraint indexed by `(a,b)` by `H - ell·b`. Thus
///
/// ```text
/// N_var = sum_{j=0}^B (M - D·j)(H + 1 - ell·j),
/// N_eq  = n·sum_{b=0}^{m-1} (m - b)(H + 1 - ell·b).
/// K = sum_{j=0}^B (M - D·j),  W = sum_{j=0}^B j(M - D·j),
/// R = n·m(m+1)/2,            V = n·m(m-1)(m+1)/6,
/// N_var - N_eq = (H + 1)(K - R) - ell·(W - V).
/// ```
///
/// The ceilings cannot be pulled outside `ell`. To account for their
/// residual, let `u = ceil(s) - s` and first use `M = Ds`, giving `K0,W0`.
/// Direct expansion yields
///
/// ```text
/// K0 - R = D·(s + u(1-u))/2 + n/8 > 0,
/// ((s²/3)(K0-R) - W0 + V)/D
///   = s/6 + s⁴/(24t²) + u(1-u)(s²-3s-2u+1)/6 + V/D > 0.
/// ```
///
/// Every summand is nonnegative: `s >= 7/2` and `0 <= u < 1` give
/// `s²-3s-2u+1 >= 3/4`. Rounding `M` upward increases the second expression
/// because `s²/3 > j`; rounding `H+1` upward increases the surplus because
/// `K-R > 0`. Hence `N_var > N_eq`, even with both rounding residuals.
/// The specialization has degree `< Ds <= m·A`, so multiplicity `m` at
/// `A = ceil(alpha·n)` agreements forces the required identity.
///
/// Apply Lemma 5.3, as stated in §7.2 Equation (88)'s order-zero case.
/// This is characteristic-free, unlike that section's positive-order
/// corollary. Since `H/ell < s²/3`, Appendix B.2's termwise estimate has
/// the same slack after dividing by `ell`, giving `E < ell·C`. This does
/// not multiply an already-rounded finite line count.
///
/// Theorem 5.12 requires positive degree, inverse rate, and `m >= 3`. The
/// constant-code case instead uses the conservative `binom(n, 2)` count
/// from Lemma 3.2, independent of `m`. This can be substantially tighter;
/// it is a separate bound for future callers admitting dimension one,
/// not a continuation of the positive-degree formula. Inputs outside
/// those supported cases return `+∞` so callers fail closed.
pub(crate) fn johnson_exceptional_line_count_log2(
    log_degree: usize,
    log_inv_rate: usize,
    m: usize,
) -> f64 {
    if m < 3 || log_inv_rate == 0 {
        return f64::INFINITY;
    }

    if log_degree == 0 {
        // log₂(n(n − 1)/2), written without constructing n.
        let log_n_minus_one = log_inv_rate as f64 + log2(1.0 - pow(2.0, -(log_inv_rate as f64)));
        return log_inv_rate as f64 + log_n_minus_one - 1.0;
    }

    let log_n = log_degree as f64 + log_inv_rate as f64;
    let log_rho_minus = log2(1.0 - pow(2.0, -(log_degree as f64))) - log_inv_rate as f64;
    3.0 + log_n + 3.0 * log2(m as f64 + 0.5) - log2(3.0) - log_rho_minus
}

/// UDR agreement parameter α = (1 + ρ⁺)/2, where ρ⁺ accounts for the
/// trace-side expansion from out-of-domain openings.
pub fn alpha_udr(log_trace_length: usize, log_blowup: usize, max_combo: usize) -> f64 {
    let k = (1u64 << log_trace_length) as f64;
    let n = (1u64 << (log_trace_length + log_blowup)) as f64;
    let rho_plus = (k + max_combo as f64) / n;
    (1.0 + rho_plus) * 0.5
}

/// LDR agreement parameter α = (1 + 1/(2m))·√ρ. BCHKS25 §4.2.
pub fn alpha_ldr_m(log_blowup: usize, m: usize) -> f64 {
    let rho = pow(2.0, -(log_blowup as f64));
    (1.0 + 0.5 / m as f64) * sqrt(rho)
}

/// LDR proximity parameter γ = 1 − √ρ·(1 + 1/(2m)). BCHKS25 §4.2.
pub fn gamma_ldr_m(log_blowup: usize, m: usize) -> f64 {
    let rho = pow(2.0, -(log_blowup as f64));
    1.0 - sqrt(rho) * (1.0 + 0.5 / m as f64)
}

/// UDR list size: L⁺ = 1.
pub const fn list_size_udr() -> f64 {
    1.0
}

/// LDR list size: L⁺ = (m + 1/2)/√ρ. Matches `soundcalc`
/// `johnson_bound::get_max_list_size` (explicit-m branch).
///
/// Uses the tighter [2025/2055] BCHKS25 Theorem 4.2 list size at the caller's
/// explicit `m`. This is the FRI list-size bound at that decoding radius;
/// it is not the classical fixed-safety-margin Johnson bound.
pub fn list_size_ldr_m(log_blowup: usize, m: usize) -> f64 {
    let rho = pow(2.0, -(log_blowup as f64));
    (m as f64 + 0.5) / sqrt(rho)
}

/// Largest proximity parameter `m` such that the η > 0 precondition of
/// Theorem 1 in [2021/582] holds. Caller applies [`LDR_M_CAP`].
///
/// `max_combo` accounts for the trace-side expansion from out-of-domain
/// openings, matching [`alpha_udr`]'s `rho_plus`. The precondition is the
/// strict inequality `m < X` where `X = 1 / (2 * (sqrt((h + max_combo) / h) - 1))`,
/// so the admissible maximum is `floor(X)`, or `X - 1` on the non-generic
/// chance that `X` is itself an integer.
pub fn compute_upper_m(trace_length: usize, max_combo: usize) -> usize {
    if trace_length == 0 {
        return 0;
    }
    let h = trace_length as f64;
    let ratio = (h + max_combo as f64) / h;
    let x = 1.0 / (2.0 * (sqrt(ratio) - 1.0));
    let m = floor(x);
    if m == x { (m - 1.0) as usize } else { m as usize }
}

/// Opening-batching proximity error in the unique-decoding regime.
///
/// The batching polynomial has degree `num_functions - 1`; a caller must pass at least two
/// functions. This is the unique-decoding branch of upstream `prox_gaps_error_at_log_eta`.
pub fn batching_error_udr(
    log_degree: usize,
    log_inv_rate: usize,
    field_size_bits: usize,
    num_functions: usize,
) -> f64 {
    assert!(num_functions >= 2, "num_functions must be >= 2 to compute proximity gaps error");
    let error = (log_degree + log_inv_rate) as f64;
    let num_functions_1_log = libm::log2(num_functions as f64 - 1.);
    field_size_bits as f64 - (error + num_functions_1_log)
}

/// Opening-batching proximity error at the same explicit Johnson parameter as the FRI bound.
///
/// DKT26 Theorem 5.12 and Appendix B.1–B.2 bound the exceptional line count. A polynomial
/// curve of degree `num_functions - 1` contributes that factor. The caller must use agreement
/// at least `(1 + 1/(2m)) * sqrt(k/n)` and pass at least two functions; choosing a smaller `m`
/// than the decoding radius permits would be unsound. Unsupported `m` or inverse rate fails
/// closed through the exceptional-line helper's infinite bound.
pub fn batching_error_ldr_m(
    log_degree: usize,
    log_inv_rate: usize,
    field_size_bits: usize,
    num_functions: usize,
    m: usize,
) -> f64 {
    assert!(num_functions >= 2, "num_functions must be >= 2 to compute proximity gaps error");
    let error = johnson_exceptional_line_count_log2(log_degree, log_inv_rate, m);
    let num_functions_1_log = libm::log2(num_functions as f64 - 1.);
    field_size_bits as f64 - (error + num_functions_1_log)
}

#[cfg(test)]
mod tests {
    use super::batching_error_ldr_m;
    use super::johnson_exceptional_line_count_log2;

    struct CurveCertificate {
        challenge_degree: u128,
        variables: u128,
        equations: u128,
        exceptional_count: f64,
    }

    /// Reconstruct Proposition B.1's scaled support and Equation (88), using
    /// exact integer cutoffs rather than the implementation's closed constant.
    fn finite_curve_certificate(d: usize, r: usize, m: usize, ell: usize) -> CurveCertificate {
        let ceil_sqrt_ratio = |num: u128, den: u128| {
            let root = (num / den).isqrt();
            root + u128::from(root * root * den < num)
        };
        let k = 1u128 << d;
        let n = k << r;
        let degree = k - 1;
        let m = m as u128;
        let ell = ell as u128;
        let four_t_squared = (2 * m + 1).pow(2);
        let spectral_cutoff = ceil_sqrt_ratio(four_t_squared * degree * n, 4);
        let jet_degree = ceil_sqrt_ratio(four_t_squared * n, 4 * degree) - 1;
        // ceil(x/y) - 1 = (x - 1)/y for positive integers x,y.
        let challenge_degree = (ell * four_t_squared * n - 1) / (12 * degree);
        let agreements = ceil_sqrt_ratio(four_t_squared * k * n, 4 * m * m);
        assert!(agreements > k && agreements <= n);
        assert!(jet_degree >= m && challenge_degree >= ell * jet_degree);

        let variables = (0..=jet_degree)
            .map(|j| (spectral_cutoff - degree * j) * (challenge_degree + 1 - ell * j))
            .sum();
        let equations =
            n * (0..m).map(|b| (m - b) * (challenge_degree + 1 - ell * b)).sum::<u128>();
        let psi = 1
            + (2 * degree - 1) * (2 * jet_degree - 1)
            + 2 * jet_degree.saturating_sub(2 * degree + 1);
        let denominator = agreements - degree;
        let numerator = ((2 * jet_degree - 1) * challenge_degree
            + ell * (n - degree - 1) * jet_degree)
            * denominator
            + (n - degree) * (ell * jet_degree + challenge_degree * psi);
        CurveCertificate {
            challenge_degree,
            variables,
            equations,
            exceptional_count: numerator as f64 / denominator as f64,
        }
    }

    #[test]
    fn curve_interpolation_keeps_the_rounding_residuals() {
        // The ell=3 support has H=97, exceeding 3 times the line's H=32.
        // Exact-cutoff cases also catch replacing ceil(x)-1 by floor(x).
        for (d, r, m, ell, h, variables, equations) in [
            (1, 1, 3, 3, 48, 1204, 1128),
            (1, 2, 3, 1, 32, 1650, 1552),
            (1, 2, 3, 3, 97, 4895, 4608),
            (2, 2, 4, 1, 35, 6127, 5600),
        ] {
            let certificate = finite_curve_certificate(d, r, m, ell);
            assert_eq!(certificate.challenge_degree, h);
            assert_eq!(certificate.variables, variables);
            assert_eq!(certificate.equations, equations);
        }
        let line = finite_curve_certificate(1, 2, 3, 1);
        let curve = finite_curve_certificate(1, 2, 3, 3);
        assert_eq!(line.exceptional_count, 2293.75);
        assert_eq!(curve.exceptional_count, 6950.75);
        assert!(curve.exceptional_count > 3.0 * line.exceptional_count);
    }

    #[test]
    fn johnson_curve_bound_covers_finite_interpolation_certificates() {
        for d in [1, 2, 3, 5, 8, 12, 20] {
            for r in [1, 2, 3, 4, 8] {
                for m in [3, 4, 10, 31, 100, 1000] {
                    for ell in [1, 2, 3, 7, 31, 257, 1_572_866] {
                        let certificate = finite_curve_certificate(d, r, m, ell);
                        assert!(certificate.variables > certificate.equations);
                        let closed_log2 = 256.0 - batching_error_ldr_m(d, r, 256, ell + 1, m);
                        assert!(
                            libm::log2(certificate.exceptional_count) < closed_log2,
                            "d={d}, r={r}, m={m}, ell={ell}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn johnson_line_count_matches_dkt26_vectors() {
        for (log_degree, log_inv_rate, m, expected) in [
            (1, 1, 3, 10.837102265451657_f64),
            (2, 1, 3, 11.2521397647305),
            (20, 2, 3, 30.83710364131352),
            (20, 2, 10, 35.59199114347699),
        ] {
            let actual = johnson_exceptional_line_count_log2(log_degree, log_inv_rate, m);
            assert!((actual - expected).abs() < 1e-12, "got {actual}, expected {expected}");
        }
    }

    #[test]
    fn johnson_line_count_handles_constant_and_invalid_inputs() {
        for (r, pairs) in [(1, 1.0), (2, 6.0), (3, 28.0)] {
            for m in [3, 10, 1000] {
                let constant = johnson_exceptional_line_count_log2(0, r, m);
                assert!((constant - libm::log2(pairs)).abs() < 1e-12);
            }
        }
        assert!(johnson_exceptional_line_count_log2(1, 0, 3).is_infinite());
        assert!(johnson_exceptional_line_count_log2(1, 1, 2).is_infinite());
        assert!(johnson_exceptional_line_count_log2(usize::MAX, usize::MAX, 3).is_finite());
    }
}
