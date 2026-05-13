//! Lifted coset domain abstraction with selector and vanishing computation.
//!
//! This module provides [`LiftedCoset`](crate::coset::LiftedCoset), the central abstraction for
//! domain operations in lifted STARKs where traces of different heights share a common evaluation
//! domain.

use alloc::vec::Vec;

use miden_stark_transcript::Channel;
use p3_field::{ExtensionField, TwoAdicField, batch_multiplicative_inverse};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use crate::{pcs::params::MAX_LOG_DOMAIN_SIZE, selectors::Selectors};

// ============================================================================
// LiftedCoset
// ============================================================================

/// Lifted coset for polynomial evaluation.
///
/// Represents a coset (gK)ʳ where:
/// - K is the evaluation domain of size 2^log_lde_height
/// - r = 2^log_lift_ratio is the lift factor (row repetition)
/// - The shift is gʳ where g = F::GENERATOR
///
/// Key relationships:
/// - log_blowup = log_lde_height - log_trace_height
/// - log_lift_ratio = log_max_lde_height - log_lde_height
/// - lde_shift = gʳ = F::GENERATOR.exp_power_of_2(log_lift_ratio)
///
/// # Invariants
///
/// - `log_lde_height = log_trace_height + log_blowup`
/// - `log_lde_height <= log_max_lde_height`
/// - All heights are powers of two (stored as log values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiftedCoset {
    /// Log₂ of the original trace height.
    pub log_trace_height: u8,
    /// Log₂ of this matrix's LDE height.
    pub log_lde_height: u8,
    /// Log₂ of the maximum LDE height in the commitment.
    pub log_max_lde_height: u8,
}

impl LiftedCoset {
    /// Create a new `LiftedCoset`.
    ///
    /// Both `log_lde_height` and `log_max_lde_height` are derived by adding
    /// `log_blowup` to the respective trace heights.
    ///
    /// # Panics
    ///
    /// Panics if `log_trace_height > log_max_trace_height` or if
    /// `log_max_trace_height + log_blowup > MAX_LOG_DOMAIN_SIZE`.
    #[inline]
    pub fn new(log_trace_height: u8, log_blowup: u8, log_max_trace_height: u8) -> Self {
        assert!(
            log_trace_height <= log_max_trace_height,
            "trace height cannot exceed max trace height"
        );
        let log_lde_height = log_trace_height as u16 + log_blowup as u16;
        let log_max_lde_height = log_max_trace_height as u16 + log_blowup as u16;
        assert!(
            log_max_lde_height <= MAX_LOG_DOMAIN_SIZE as u16,
            "LDE height 2^{log_max_lde_height} exceeds maximum 2^{MAX_LOG_DOMAIN_SIZE}",
        );
        Self {
            log_trace_height,
            log_lde_height: log_lde_height as u8,
            log_max_lde_height: log_max_lde_height as u8,
        }
    }

    /// Create a `LiftedCoset` at max height (no lifting).
    ///
    /// Convenience for the common single-trace case where the LDE height
    /// equals the max LDE height.
    #[inline]
    pub fn unlifted(log_trace_height: u8, log_blowup: u8) -> Self {
        let log_lde_height = log_trace_height as u16 + log_blowup as u16;
        assert!(
            log_lde_height <= MAX_LOG_DOMAIN_SIZE as u16,
            "LDE height 2^{log_lde_height} exceeds maximum 2^{MAX_LOG_DOMAIN_SIZE}",
        );
        Self {
            log_trace_height,
            log_lde_height: log_lde_height as u8,
            log_max_lde_height: log_lde_height as u8,
        }
    }

    // ============ Existing methods ============

    /// Log₂ of the blowup factor for this matrix.
    ///
    /// Returns `log_lde_height - log_trace_height`.
    #[inline]
    pub fn log_blowup(&self) -> usize {
        (self.log_lde_height - self.log_trace_height) as usize
    }

    /// Log₂ of the lift ratio for this matrix.
    ///
    /// The lift ratio is how many times this matrix's rows are virtually repeated
    /// to match the max LDE height: `max_lde_height / lde_height`.
    ///
    /// Returns `log_max_lde_height - log_lde_height`.
    #[inline]
    pub fn log_lift_ratio(&self) -> usize {
        (self.log_max_lde_height - self.log_lde_height) as usize
    }

    /// Whether this matrix is lifted (its LDE height is less than the max).
    #[inline]
    pub fn is_lifted(&self) -> bool {
        self.log_lde_height < self.log_max_lde_height
    }

    /// Compute the coset shift for this matrix's LDE domain.
    ///
    /// For a matrix with lift ratio `r = 2^log_lift_ratio`, the coset shift is gʳ
    /// where g is the field generator.
    ///
    /// Why gʳ: lifting embeds a smaller-domain polynomial into the max domain by
    /// composition `p_lift(X) = p(Xʳ)`. Evaluating `p_lift` on the max coset `g·K_max`
    /// corresponds to evaluating `p` on the nested coset `gʳ·K`, because
    /// `(g·ω)ʳ = gʳ·ωʳ` and ωʳ ranges over K when ω ranges over `K_max`.
    #[inline]
    pub fn lde_shift<F: TwoAdicField>(&self) -> F {
        F::GENERATOR.exp_power_of_2(self.log_lift_ratio())
    }

    /// The trace height (number of constraint rows).
    #[inline]
    pub fn trace_height(&self) -> usize {
        1 << self.log_trace_height as usize
    }

    /// The LDE height for this matrix.
    #[inline]
    pub fn lde_height(&self) -> usize {
        1 << self.log_lde_height as usize
    }

    /// The maximum LDE height across all matrices.
    #[inline]
    pub fn max_lde_height(&self) -> usize {
        1 << self.log_max_lde_height as usize
    }

    /// The blowup factor for this matrix.
    #[inline]
    pub fn blowup(&self) -> usize {
        1 << self.log_blowup()
    }

    // ============ Domain derivation ============

    /// Derive the quotient domain coset from this LDE coset.
    ///
    /// For constraint evaluation, we need a coset of size `trace_height * constraint_degree`.
    /// This transforms (gK)ʳ into (gJ)ʳ while preserving the lift ratio.
    ///
    /// # Panics
    /// Panics if log_constraint_degree > log_blowup.
    ///
    /// The quotient domain is a strict subset of the committed LDE domain.
    ///
    /// If the constraint degree is `D`, the resulting quotient polynomial has degree
    /// `< N * (D - 1)`, so `N * D` evaluation points suffice for commitment and for the
    /// verifier's reconstruction. The PCS uses a larger blowup `B`, so the committed
    /// LDE domain `gK` has `N * B` points, but constraint evaluation only needs the
    /// sub-coset `gJ` of size `N * D` (with `D <= B`).
    pub fn quotient_domain(&self, log_constraint_degree: u8) -> Self {
        let log_blowup = self.log_lde_height - self.log_trace_height;
        assert!(log_constraint_degree <= log_blowup, "constraint degree cannot exceed blowup");
        let log_max_trace_height = self.log_max_lde_height - log_blowup;
        Self {
            log_trace_height: self.log_trace_height,
            log_lde_height: self.log_trace_height + log_constraint_degree,
            log_max_lde_height: log_max_trace_height + log_constraint_degree,
        }
    }

    // ============ Selector computation ============

    /// Compute selectors for evaluation over this coset in natural order.
    ///
    /// Returns is_first_row, is_last_row, is_transition for each point in the coset
    /// (gK)ʳ. The trace domain H has size `2^log_trace_height`.
    ///
    /// Selectors use unnormalized Lagrange basis polynomials. The is_first_row selector
    /// is `L₀(x) = Z_H(x) / (x − 1)`, which equals 0 on all of H except the first row.
    /// When multiplied by a constraint C(x), it enforces C only at the first row:
    /// `L₀(x)·C(x)` vanishes on H iff `C(1) = 0`. Similarly,
    /// `is_last_row = Z_H(x) / (x − ω⁻¹)`.
    ///
    /// The is_transition selector is `(x − ω⁻¹)`, which is nonzero everywhere except the
    /// last row, enforcing transition constraints on all consecutive row pairs.
    /// These are "unnormalized" because we omit the constant factor 1/N that would make
    /// them evaluate to exactly 1 at their target row. This is fine because both prover
    /// and verifier evaluate the same unnormalized form: multiplying all boundary constraints
    /// by a common nonzero constant does not affect whether the quotient is a polynomial.
    pub fn selectors<F: TwoAdicField>(&self) -> Selectors<Vec<F>> {
        let shift: F = self.lde_shift();
        let coset_size = self.lde_height();
        let log_blowup = self.log_blowup();

        // Z_H(x) = xⁿ − 1 evaluated at coset points.
        // Periodic with 2^log_blowup distinct values; expand to full coset size for zip.
        let s_pow_n = shift.exp_power_of_2(self.log_trace_height as usize);
        let z_h_periodic: Vec<F> = F::two_adic_generator(log_blowup)
            .shifted_powers(s_pow_n)
            .take(1 << log_blowup)
            .map(|x| x - F::ONE)
            .collect();
        let period = z_h_periodic.len();

        // Coset points in natural order: shift·ω_Jⁱ
        let omega_j = F::two_adic_generator(self.log_lde_height as usize);
        let xs: Vec<F> = omega_j.shifted_powers(shift).collect_n(coset_size);

        let omega_h_inv = F::two_adic_generator(self.log_trace_height as usize).inverse();

        // Unnormalized Lagrange selector: selᵢ = Z_H(xᵢ) / (xᵢ − basis_point)
        // Uses modular indexing into z_h_periodic to avoid a full-size allocation.
        let single_point_selector = |basis_point: F| -> Vec<F> {
            let denoms: Vec<F> = xs.par_iter().map(|&x| x - basis_point).collect();
            let invs = batch_multiplicative_inverse(&denoms);
            (0..coset_size)
                .into_par_iter()
                .map(|i| z_h_periodic[i % period] * invs[i])
                .collect()
        };

        Selectors {
            is_first_row: single_point_selector(F::ONE),
            is_last_row: single_point_selector(omega_h_inv),
            is_transition: xs.into_par_iter().map(|x| x - omega_h_inv).collect(),
        }
    }

    /// Lifted selectors at the OOD point (verifier).
    ///
    /// For a selector `s(x)` defined over the original trace domain of size `n_j`,
    /// lifting evaluates `s(z_lift)` where `z_lift = z^r` and
    /// `r = 2^log_lift_ratio = max_n / n_j`. This maps the OOD point `z`
    /// (sampled in the max-trace domain) into the per-instance trace domain.
    ///
    /// # Formulas (unnormalized)
    /// - `is_first_row = Z_H(z_lift) / (z_lift − 1)`
    /// - `is_last_row  = Z_H(z_lift) / (z_lift − ω_{n_j}⁻¹)`
    /// - `is_transition = z_lift − ω_{n_j}⁻¹`
    ///
    /// where `Z_H(z_lift) = z_lift^{n_j} − 1 = z^{max_n} − 1`.
    pub fn selectors_at<F, EF>(&self, z: EF) -> Selectors<EF>
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        let z_lift = z.exp_power_of_2(self.log_lift_ratio());
        let vanishing = self.vanishing_at::<F, _>(z_lift);
        let omega_inv = F::two_adic_generator(self.log_trace_height as usize).inverse();

        Selectors {
            is_first_row: vanishing / (z_lift - F::ONE),
            is_last_row: vanishing / (z_lift - omega_inv),
            is_transition: z_lift - omega_inv,
        }
    }

    // ============ Vanishing polynomial ============

    /// Vanishing polynomial at an out-of-domain point.
    ///
    /// Returns `Z_H(z) = zⁿ − 1` using `exp_power_of_2` (log-many squarings).
    pub fn vanishing_at<F, EF>(&self, z: EF) -> EF
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        z.exp_power_of_2(self.log_trace_height as usize) - EF::ONE
    }

    // ============ Quotient reconstruction ============

    /// Reconstruct `Q(z)` from `D` quotient chunk evaluations.
    ///
    /// The quotient `Q` is committed as `D` chunk polynomials qₜ of degree `< N`, one for
    /// each `H`-coset inside `J`:
    ///
    /// qₜ agrees with `Q` on the coset `g·ω_Jᵗ·H`.
    ///
    /// During verification we open all qₜ(z) at the same OOD point `z` and need to
    /// recombine them into `Q(z)`.
    ///
    /// The key observation is that the map `x → xᴺ` collapses each coset
    /// `g·ω_Jᵗ·H` to a single `D`-th root of unity. Let
    /// - ωₛ = ω_Jᴺ (a `D`-th root of unity),
    /// - u = (z/s)ᴺ where s = `self.lde_shift()`.
    ///
    /// Then `Q(z)` is the barycentric interpolation of the values qₜ(z) at the points
    /// ωₛᵗ:
    ///
    /// ```text
    /// wₜ = ωₛᵗ / (u − ωₛᵗ)
    /// Q(z) = (Σₜ wₜ·qₜ(z)) / (Σₜ wₜ)
    /// ```
    pub fn reconstruct_quotient<F, EF>(&self, z: EF, chunks: &[EF]) -> EF
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        let log_d = log2_strict_usize(chunks.len());
        let shift: F = self.lde_shift();
        let omega_s = F::two_adic_generator(log_d);

        // u = (z/s)ᴺ where s = lde_shift
        let u = (z * shift.inverse()).exp_power_of_2(self.log_trace_height as usize);

        // Compute weighted sum: Σₜ wₜ·qₜ(z) and Σₜ wₜ
        let mut numerator = EF::ZERO;
        let mut denominator = EF::ZERO;
        let mut omega_s_t = F::ONE; // ωₛᵗ

        for &q_t in chunks.iter() {
            let a_t = u - omega_s_t; // aₜ = u − ωₛᵗ
            let w_t = a_t.inverse() * omega_s_t; // wₜ = ωₛᵗ / aₜ

            numerator += w_t * q_t;
            denominator += w_t;

            omega_s_t *= omega_s;
        }

        numerator * denominator.inverse()
    }

    // ============ Domain membership ============

    /// Check if a point is in the trace domain H.
    ///
    /// Returns true if `z^N == 1` where N is the trace height.
    /// Points in H cause division by zero in vanishing polynomial inversion.
    #[inline]
    pub fn is_in_trace_domain<F, EF>(&self, z: EF) -> bool
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        z.exp_power_of_2(self.log_trace_height as usize) == EF::ONE
    }

    /// Check if a point is in the LDE coset gK.
    ///
    /// Returns true if `(z/g)^|K| == 1` where g is the generator shift
    /// and K is the LDE domain. Points in gK cause division by zero in DEEP quotients.
    #[inline]
    pub fn is_in_lde_coset<F, EF>(&self, z: EF) -> bool
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        let shift: F = self.lde_shift();
        let z_over_shift = z * shift.inverse();
        z_over_shift.exp_power_of_2(self.log_lde_height as usize) == EF::ONE
    }

    // ============ OOD point sampling ============

    /// Sample an OOD evaluation point from the channel that lies outside both the
    /// trace-domain subgroup `H` and the LDE evaluation coset `gK`.
    ///
    /// Repeatedly draws `sample_algebra_element` candidates until one satisfies
    /// both exclusion tests. This terminates with overwhelming probability because
    /// `|H ∪ gK|` is negligible relative to the extension field size.
    pub fn sample_ood_point<F, EF>(&self, channel: &mut impl Channel<F = F>) -> EF
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        loop {
            let candidate: EF = channel.sample_algebra_element();
            if !self.is_in_trace_domain::<F, _>(candidate)
                && !self.is_in_lde_coset::<F, _>(candidate)
            {
                break candidate;
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use p3_field::{Field, PrimeCharacteristicRing};

    use super::*;
    use crate::testing::configs::goldilocks_poseidon2::Felt;

    #[test]
    fn domain_info_basic() {
        // Trace height 2^10, blowup 2^3, max trace 2^12
        let info = LiftedCoset::new(10, 3, 12);

        assert_eq!(info.log_trace_height, 10);
        assert_eq!(info.log_lde_height, 13);
        assert_eq!(info.log_max_lde_height, 15);

        assert_eq!(info.log_blowup(), 3);
        assert_eq!(info.log_lift_ratio(), 2);
        assert!(info.is_lifted());

        assert_eq!(info.trace_height(), 1024);
        assert_eq!(info.lde_height(), 8192);
        assert_eq!(info.max_lde_height(), 32768);
        assert_eq!(info.blowup(), 8);
    }

    #[test]
    fn domain_info_no_lift() {
        // Matrix at max height (no lifting needed)
        let info = LiftedCoset::unlifted(10, 3);

        assert_eq!(info.log_lift_ratio(), 0);
        assert!(!info.is_lifted());
    }

    #[test]
    fn domain_info_lde_shift() {
        // Trace height 2^10, blowup 2^3, max trace 2^12
        let info = LiftedCoset::new(10, 3, 12);
        let shift: Felt = info.lde_shift();

        // shift = g^(2^2) = g^4
        let expected = Felt::GENERATOR.exp_power_of_2(2);
        assert_eq!(shift, expected);
    }

    #[test]
    fn domain_info_no_lift_shift() {
        // When not lifted, shift should be g^1 = g
        let info = LiftedCoset::unlifted(10, 3);
        let shift: Felt = info.lde_shift();

        // shift = g^(2^0) = g
        assert_eq!(shift, Felt::GENERATOR);
    }

    #[test]
    fn quotient_domain_preserves_lift_ratio_and_updates_blowup() {
        // Trace height 2^10, blowup 2^3 (B=8), max trace 2^12.
        let lde = LiftedCoset::new(10, 3, 12);

        // Constraint degree D = 4 (log D = 2), so quotient domain size is N*D.
        let q = lde.quotient_domain(2);

        // Trace height is unchanged; the evaluation domain becomes N*D.
        assert_eq!(q.log_trace_height, 10);
        assert_eq!(q.log_blowup(), 2);
        assert_eq!(q.log_lde_height, 12);

        // Max evaluation domain becomes N_max*D.
        assert_eq!(q.log_max_lde_height, 14);

        // Lift ratio is preserved.
        assert_eq!(q.log_lift_ratio(), lde.log_lift_ratio());
    }
}
