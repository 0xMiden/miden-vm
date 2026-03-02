//! Quadratic extension field arithmetic for constraint expressions.
//!
//! Provides [`QuadFeltExpr`], a lightweight wrapper that pairs two base-field expressions
//! into an element of the Goldilocks quadratic extension field GF(p², u² = 7) where
//! p = 2⁶⁴ − 2³² + 1. This mirrors the arithmetic of [`BinomialExtensionField<Felt, 2>`]
//! from plonky3 (see `p3_goldilocks::extension`) but operates on symbolic constraint
//! expressions rather than concrete field elements, giving readable extension arithmetic
//! without requiring additional trait bounds on `AB::ExprEF`.

use core::ops::{Add, Mul, Sub};

use miden_core::field::PrimeCharacteristicRing;

/// Residue of the irreducible polynomial `x² − W` defining the Goldilocks quadratic extension.
/// This must match `p3_goldilocks::extension::W`.
const W: u16 = 7;

// QUADRATIC EXTENSION EXPRESSION
// ================================================================================================

/// Symbolic Goldilocks quadratic extension element `c0 + c1 · u` where `u² = 7`.
///
/// This is the expression-level analogue of [`QuadFelt`](miden_core::QuadFelt)
/// (= `BinomialExtensionField<Felt, 2>` from plonky3). The constant `W = 7` matches
/// the irreducible polynomial `x² − 7` used by plonky3's Goldilocks extension
/// (see `p3_goldilocks::extension::W`).
#[derive(Clone)]
pub struct QuadFeltExpr<E>(E, E);

impl<E> QuadFeltExpr<E> {
    /// Constructs a new extension element from two base-field values.
    pub fn new<V: Clone + Into<E>>(c0: &V, c1: &V) -> Self {
        Self(c0.clone().into(), c1.clone().into())
    }

    /// Decomposes into base-field components `[c0, c1]`.
    pub fn into_parts(self) -> [E; 2] {
        [self.0, self.1]
    }
}

impl<E: PrimeCharacteristicRing> QuadFeltExpr<E> {
    /// Squares this extension element, producing a smaller expression tree than generic `Mul`
    /// by exploiting `a·b + b·a = 2·(a·b)` for the cross term.
    pub fn square(self) -> Self {
        // (a0 + a1·u)² = (a0² + 7·a1²) + 2·a0·a1·u
        let w = E::from_u16(W);
        let a0_sq = self.0.clone() * self.0.clone();
        let a1_sq = self.1.clone() * self.1.clone();
        let c0 = a0_sq + w * a1_sq;
        let c1 = (self.0 * self.1).double();
        Self(c0, c1)
    }
}

impl<E: PrimeCharacteristicRing> Add for QuadFeltExpr<E> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<E: PrimeCharacteristicRing> Add<E> for QuadFeltExpr<E> {
    type Output = Self;
    fn add(self, rhs: E) -> Self {
        Self(self.0 + rhs, self.1)
    }
}

impl<E: PrimeCharacteristicRing> Sub for QuadFeltExpr<E> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<E: PrimeCharacteristicRing> Mul for QuadFeltExpr<E> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        // (a0 + a1·u)(b0 + b1·u) = (a0·b0 + 7·a1·b1) + (a0·b1 + a1·b0)·u
        let w = E::from_u16(W);
        let c0 = self.0.clone() * rhs.0.clone() + w * self.1.clone() * rhs.1.clone();
        let c1 = self.0 * rhs.1 + self.1 * rhs.0;
        Self(c0, c1)
    }
}

impl<E: PrimeCharacteristicRing> Mul<E> for QuadFeltExpr<E> {
    type Output = Self;
    fn mul(self, rhs: E) -> Self {
        Self(self.0 * rhs.clone(), self.1 * rhs)
    }
}
