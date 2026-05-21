//! Horner-style polynomial evaluation helpers.

use core::ops::{Add, Mul};

/// Horner fold with an explicit accumulator.
///
/// Computes `acc·xⁿ + v₀·xⁿ⁻¹ + v₁·xⁿ⁻² + ... + vₙ₋₁·x⁰` where n = len(vals).
/// Equivalently: `((acc·x + v₀)·x + v₁)·x + ... + vₙ₋₁`.
/// The first element gets the highest power of `x`.
///
/// For polynomial evaluation `p(x) = Σᵢ cᵢ·xⁱ`, pass coefficients in
/// descending degree order `[cₙ, ..., c₁, c₀]`.
#[inline]
pub(crate) fn horner_acc<Acc, Val, X, I>(acc: Acc, x: X, vals: I) -> Acc
where
    I: IntoIterator<Item = Val>,
    Acc: Mul<X, Output = Acc> + Add<Val, Output = Acc>,
    X: Clone,
{
    vals.into_iter().fold(acc, |acc, val| acc * x.clone() + val)
}

/// Horner fold starting from zero.
///
/// See [`horner_acc`] for the evaluation convention.
#[inline]
pub(crate) fn horner<Acc, Val, X, I>(x: X, vals: I) -> Acc
where
    I: IntoIterator<Item = Val>,
    Acc: Default + Mul<X, Output = Acc> + Add<Val, Output = Acc>,
    X: Clone,
{
    horner_acc(Acc::default(), x, vals)
}
