//! # FRI Protocol Implementation
//!
//! Fast Reed-Solomon Interactive Oracle Proof for low-degree testing.
//! Proves that a committed polynomial has degree below a target bound.
//!
//! ## Domain Convention
//!
//! This FRI implementation treats inputs as evaluations over the unshifted two-adic
//! subgroup. If the PCS evaluates over a coset `gK`, the shift is absorbed into
//! the polynomial: `Q'(X) = Q(g·X)`. The low-degree test is run on `Q'` using
//! subgroup points.
//!
//! ## Type vocabulary
//!
//! FRI takes its initial domain as a [`LiftedDomain<F>`](crate::domain::LiftedDomain) —
//! the protocol-level LDE object carrying both the LDE subgroup size and the blowup
//! ratio relative to the trace. The unshifted subgroup view is reached via
//! `domain.lde_coset().subgroup()`. Each fold round shrinks the working subgroup by the
//! folding arity, derived via [`TwoAdicSubgroup::shrink`](crate::domain::TwoAdicSubgroup::shrink)
//! (or per-round generator squaring inside the round loop, which is equivalent and avoids
//! re-querying `F::two_adic_generator`). Internal `arity`-th roots of unity used by the fold
//! operations come from `TwoAdicSubgroup::<F>::new(log_arity).generator()`. Routing every
//! two-adic root and every multiplicative coset shift through these encapsulation types keeps
//! `F::two_adic_generator` and `F::GENERATOR` confined to their single canonical sites.

pub mod fold;
pub mod proof;
pub mod prover;
pub mod verifier;

use fold::FriFold;
use p3_field::TwoAdicField;

use crate::domain::LiftedDomain;

/// FRI protocol parameters.
///
/// Controls the trade-off between proof size, prover time, and verifier time.
///
/// Higher arity reduces the number of FRI rounds (fewer Merkle tree commitments) but increases
/// per-query proof size (each opening reveals `arity` siblings). `log_final_degree` reduces the
/// number of rounds and therefore the number of Merkle commitments; if too large, the final
/// polynomial's coefficients dominate the proof size.
///
/// The LDE blowup factor is **not** stored here — it is a structural property of the codeword
/// being tested and is read from the [`LiftedDomain`](crate::domain::LiftedDomain) passed to
/// [`num_rounds`](Self::num_rounds), [`final_poly_degree`](Self::final_poly_degree),
/// [`FriPolys::new`](prover::FriPolys::new), and
/// [`FriOracle::new`](verifier::FriOracle::new).
#[derive(Clone, Copy, Debug)]
pub struct FriParams {
    /// The FRI folding strategy.
    ///
    /// Determines the folding arity (2, 4, or 8).
    pub(crate) fold: FriFold,

    /// Log₂ of the final polynomial degree.
    ///
    /// Folding stops when degree reaches `2^log_final_degree`.
    /// Final polynomial coefficients are sent in descending degree order
    /// `[cₙ, ..., c₁, c₀]` for direct Horner evaluation by the verifier.
    pub(crate) log_final_degree: u8,

    /// Grinding bits before each folding challenge.
    pub(crate) folding_pow_bits: usize,
}

impl FriParams {
    /// Compute the number of folding rounds for an LDE codeword evaluated on `domain`.
    ///
    /// Each round reduces the domain by `2^log_folding_factor`. We fold until the domain
    /// size reaches `2^(log_final_degree + log_blowup)`, at which point the polynomial
    /// degree is at most `2^log_final_degree`.
    ///
    /// Uses `div_ceil` to round up, ensuring we always reach the target degree even if
    /// the domain size doesn't divide evenly by the folding factor.
    #[inline]
    pub fn num_rounds<F: TwoAdicField>(&self, domain: &LiftedDomain<F>) -> usize {
        let log_max_final_size = self.log_final_degree + domain.log_blowup();
        domain
            .log_lde_height()
            .saturating_sub(log_max_final_size)
            .div_ceil(self.fold.log_arity()) as usize
    }

    /// Compute the final polynomial degree after folding the codeword evaluated on `domain`.
    ///
    /// After `num_rounds` folding rounds, the LDE domain shrinks from
    /// `2^domain.log_lde_height()` to `2^(log_lde_height − num_rounds × log_folding_factor)`.
    /// The polynomial degree is then `domain_size / blowup`.
    ///
    /// Due to `div_ceil` in `num_rounds`, the actual final degree may be smaller than
    /// `2^log_final_degree` when the folding doesn't divide evenly.
    #[inline]
    pub fn final_poly_degree<F: TwoAdicField>(&self, domain: &LiftedDomain<F>) -> usize {
        let num_rounds = self.num_rounds(domain);
        let log_final_size =
            domain.log_lde_height() as usize - num_rounds * self.fold.log_arity() as usize;
        1 << log_final_size.saturating_sub(domain.log_blowup() as usize)
    }
}

#[cfg(test)]
mod tests;
