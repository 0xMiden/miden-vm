//! Quadratic extension expression helpers (F_p[u] / u^2 - 7).
//!
//! This keeps constraint code readable when manipulating extension elements in terms of
//! base-field expressions. All arithmetic requires `E: PrimeCharacteristicRing`.

use core::ops::{Add, Mul, Sub};

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

// Quadratic non-residue for the extension: u^2 = 7.
const W: u16 = 7;

/// Quadratic extension element represented as (c0 + c1 * u).
///
/// `#[repr(C)]` guarantees layout-compatible with `[E; 2]`, so this can be used
/// inside `#[repr(C)]` column structs in place of `[T; 2]`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct QuadFeltExpr<E>(pub E, pub E);

// CONSTRUCTORS AND CONVERSIONS
// ================================================================================================

impl<E> QuadFeltExpr<E> {
    /// Constructs a new extension element from two base-field components.
    ///
    /// Accepts any type convertible to `E`, e.g. `Var` when `E = Expr`.
    pub fn new(c0: impl Into<E>, c1: impl Into<E>) -> Self {
        Self(c0.into(), c1.into())
    }

    /// Returns the base-field components `[c0, c1]`.
    pub fn into_parts(self) -> [E; 2] {
        [self.0, self.1]
    }

    /// Converts `QuadFeltExpr<V>` into `QuadFeltExpr<O>` (e.g. Var -> Expr).
    ///
    /// A blanket `From` impl is not possible because `From<QuadFeltExpr<V>> for QuadFeltExpr<E>`
    /// conflicts with std's `impl<T> From<T> for T` when `V == E`.
    pub fn into_expr<O>(self) -> QuadFeltExpr<O>
    where
        E: Into<O>,
    {
        QuadFeltExpr(self.0.into(), self.1.into())
    }
}

// EXTENSION FIELD ARITHMETIC
// ================================================================================================

impl<E: PrimeCharacteristicRing> QuadFeltExpr<E> {
    /// Returns `self * self`.
    pub fn square(self) -> Self {
        let w = E::from_u16(W);
        // (a0 + a1·u)^2 = (a0^2 + 7·a1^2) + (2·a0·a1)·u
        let a0_sq = self.0.clone() * self.0.clone();
        let a1_sq = self.1.clone() * self.1.clone();
        let a0_a1 = self.0 * self.1;
        let c0 = a0_sq + w * a1_sq;
        let c1 = a0_a1.clone() + a0_a1;
        Self(c0, c1)
    }

    /// Extension multiplication: (a0 + a1·u)(b0 + b1·u) in F_p[u]/(u² - 7).
    fn ext_mul(self, rhs: Self) -> Self {
        let w = E::from_u16(W);
        let c0 = self.0.clone() * rhs.0.clone() + w * (self.1.clone() * rhs.1.clone());
        let c1 = self.0 * rhs.1 + self.1 * rhs.0;
        Self(c0, c1)
    }
}

// QFE-QFE ARITHMETIC TRAIT IMPLS
// ================================================================================================

impl<E> Add for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<E> Sub for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<E> Mul for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.ext_mul(rhs)
    }
}

// SCALAR ARITHMETIC
// ================================================================================================

impl<E> Add<E> for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn add(self, rhs: E) -> Self {
        Self(self.0 + rhs, self.1)
    }
}

impl<E> Sub<E> for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn sub(self, rhs: E) -> Self {
        Self(self.0 - rhs, self.1)
    }
}

impl<E> Mul<E> for QuadFeltExpr<E>
where
    E: PrimeCharacteristicRing,
{
    type Output = Self;

    fn mul(self, rhs: E) -> Self {
        Self(self.0 * rhs.clone(), self.1 * rhs)
    }
}

// QUAD FELT AIR BUILDER EXTENSION
// ================================================================================================

/// Extension trait for asserting equality of quadratic extension field expressions.
pub trait QuadFeltAirBuilder: AirBuilder {
    /// Asserts `lhs == rhs` component-wise for quadratic extension field elements.
    fn assert_eq_quad(&mut self, lhs: QuadFeltExpr<Self::Expr>, rhs: QuadFeltExpr<Self::Expr>) {
        self.assert_eq(lhs.0, rhs.0);
        self.assert_eq(lhs.1, rhs.1);
    }
}

impl<AB: AirBuilder> QuadFeltAirBuilder for AB {}
