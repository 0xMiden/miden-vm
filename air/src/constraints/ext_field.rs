//! Quadratic extension expression helpers (F_p[u] / u^2 - 7).
//!
//! This keeps constraint code readable when manipulating extension elements in terms of
//! base-field expressions.

use core::ops::{Add, Mul, Sub};

use miden_core::field::PrimeCharacteristicRing;

// Quadratic non-residue for the extension: u^2 = 7.
const W: u16 = 7;

/// Quadratic extension element represented as (c0 + c1 * u).
#[derive(Clone, Debug)]
pub struct QuadFeltExpr<E>(pub E, pub E);

impl<E> QuadFeltExpr<E> {
    /// Constructs a new extension element from two base-field values.
    pub fn new<V: Clone + Into<E>>(c0: &V, c1: &V) -> Self {
        Self(c0.clone().into(), c1.clone().into())
    }

    /// Returns the base-field components `[c0, c1]`.
    pub fn into_parts(self) -> [E; 2] {
        [self.0, self.1]
    }
}

impl<E> QuadFeltExpr<E>
where
    E: Clone + Add<Output = E> + Mul<Output = E> + PrimeCharacteristicRing,
{
    /// Returns `self * other`.
    pub fn mul(self, rhs: Self) -> Self {
        let w = E::from_u16(W);
        // (a0 + a1·u)(b0 + b1·u) = (a0·b0 + 7·a1·b1) + (a0·b1 + a1·b0)·u
        let c0 = self.0.clone() * rhs.0.clone() + w * (self.1.clone() * rhs.1.clone());
        let c1 = self.0 * rhs.1 + self.1 * rhs.0;
        Self(c0, c1)
    }

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
}

impl<E> Add for QuadFeltExpr<E>
where
    E: Add<Output = E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<E> Sub for QuadFeltExpr<E>
where
    E: Sub<Output = E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<E> Add<E> for QuadFeltExpr<E>
where
    E: Add<Output = E>,
{
    type Output = Self;

    fn add(self, rhs: E) -> Self {
        Self(self.0 + rhs, self.1)
    }
}

impl<E> Sub<E> for QuadFeltExpr<E>
where
    E: Sub<Output = E>,
{
    type Output = Self;

    fn sub(self, rhs: E) -> Self {
        Self(self.0 - rhs, self.1)
    }
}

impl<E> Mul for QuadFeltExpr<E>
where
    E: Clone + Add<Output = E> + Mul<Output = E> + PrimeCharacteristicRing,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        QuadFeltExpr::mul(self, rhs)
    }
}

impl<E> Mul<E> for QuadFeltExpr<E>
where
    E: Clone + Mul<Output = E>,
{
    type Output = Self;

    fn mul(self, rhs: E) -> Self {
        Self(self.0 * rhs.clone(), self.1 * rhs)
    }
}
