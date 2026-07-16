//! Arity-2 FRI folding using even-odd decomposition.
//!
//! Any polynomial `f(X)` can be uniquely decomposed into even and odd parts:
//!
//! ```text
//! f(X) = fₑ(X²) + X · fₒ(X²)
//! ```
//!
//! where `fₑ` contains the even-degree coefficients and `fₒ` the odd-degree coefficients.
//!
//! ## Key Identity
//!
//! From evaluations at `s` and `−s`, we can recover `fₑ(s²)` and `fₒ(s²)`:
//!
//! ```text
//! f(s)  = fₑ(s²) + s · fₒ(s²)
//! f(−s) = fₑ(s²) − s · fₒ(s²)
//! ```
//!
//! Solving:
//!
//! ```text
//! fₑ(s²) = (f(s) + f(−s)) / 2
//! fₒ(s²) = (f(s) − f(−s)) / (2s)
//! ```
//!
//! ## FRI Folding
//!
//! Given a challenge `β`, FRI defines the folded polynomial:
//!
//! ```text
//! g(X) = fₑ(X) + β · fₒ(X)
//! ```
//!
//! For a coset `{s, −s}`, we compute the folded value `g(s²)` by interpolating
//! `fₑ(s²)` and `fₒ(s²)` from the two evaluations (and when `deg f < 2`, `g(s²)=f(β)`).

use p3_field::{Algebra, TwoAdicField};

/// Arity-2 FRI folding using even-odd decomposition.
///
/// Folds pairs of evaluations using the even-odd decomposition:
/// `f(β) = (f(s) + f(-s))/2 + β/s · (f(s) - f(-s))/2`
///
/// ## Inputs
///
/// - `evals`: slice of 2 evaluations `[f(s), f(−s)]` in bit-reversed order.
/// - `s_inv`: the inverse of the coset generator `s`.
/// - `beta`: the FRI folding challenge `β`.
///
/// ## Algorithm
///
/// Using the even-odd decomposition `f(X) = fₑ(X²) + X · fₒ(X²)`:
///
/// 1. Compute `fₑ(s²) = (f(s) + f(−s)) / 2`
/// 2. Compute `fₒ(s²) = (f(s) − f(−s)) / (2s)`
/// 3. Return `g(s²) = fₑ(s²) + β · fₒ(s²)` (equals `f(β)` when `deg f < 2`)
#[inline(always)]
pub fn fold_evals<F, PF, PEF>(evals: &[PEF], s_inv: PF, beta: PEF) -> PEF
where
    F: TwoAdicField,
    PF: Algebra<F> + Algebra<PF>,
    PEF: Algebra<PF>,
{
    debug_assert_eq!(evals.len(), 2, "evals must have 2 elements");
    // y₀ = f(s), y₁ = f(−s)
    let [y0, y1] = [evals[0].clone(), evals[1].clone()];

    // f(β) = fₑ(s²) + β · fₒ(s²)
    // Even part: fₑ(s²) = (f(s) + f(−s)) / 2
    // Odd part: fₒ(s²) = (f(s) − f(−s)) / (2s)
    // Combined: ((y0 + y1) + (y0 - y1) * beta * s_inv) / 2
    let sum = y0.clone() + y1.clone();
    let diff = y0 - y1;
    let result = sum + diff * beta * s_inv;

    // Divide by 2
    result.div_2exp_u64(1)
}
