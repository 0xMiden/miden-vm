// Derived from p3-air 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Modified for Miden native expression inputs; provenance and changes are recorded in README.md.

//! Shared Arc-backed arithmetic, adapted from the pinned upstream generic expression tree.

use alloc::sync::Arc;
use core::{
    iter::{Product, Sum},
    ops,
};

use p3_field::{Dup, Field, PrimeCharacteristicRing};

/// Properties that leaf nodes must provide for the generic expression tree.
///
/// Both [`super::BaseLeaf`] (base-field) and
/// [`super::ExtLeaf`] (extension-field) implement this trait,
/// enabling [`SymbolicExpr`] to handle constant folding, degree tracking, and
/// arithmetic generically.
pub trait SymLeaf: Clone + core::fmt::Debug {
    /// The base field type used for constant folding.
    type F: Field;

    const ZERO: Self;
    const ONE: Self;
    const TWO: Self;
    const NEG_ONE: Self;

    /// Returns the degree multiple of this leaf.
    fn degree_multiple(&self) -> usize;

    /// Try to view this leaf as a base-field constant.
    fn as_const(&self) -> Option<&Self::F>;

    /// Create a leaf from a base-field constant.
    fn from_const(c: Self::F) -> Self;
}

/// A symbolic expression tree, generic over its leaf type `A`.
///
/// This enum captures the shared tree structure — Add/Sub/Neg/Mul nodes with
/// `Arc`-wrapped children and cached degree multiples — used by both base-field
/// and extension-field symbolic expressions.
///
/// The native base and extension aliases use different leaves but the same arithmetic rules.
#[derive(Clone, Debug)]
pub enum SymbolicExpr<A> {
    /// A leaf node (variable, constant, selector, or lifted sub-expression).
    Leaf(A),

    /// Addition of two sub-expressions.
    Add {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },

    /// Subtraction of two sub-expressions.
    Sub {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },

    /// Negation of a sub-expression.
    Neg { x: Arc<Self>, degree_multiple: usize },

    /// Multiplication of two sub-expressions.
    Mul {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
}

impl<A: SymLeaf> SymbolicExpr<A> {
    /// Return the cached, trace-size-independent degree multiple.
    ///
    /// This is a diagnostic inherited from trusted symbolic construction, not an actual-height
    /// capacity check. Arithmetic on cached degrees is not checked for overflow. Untrusted
    /// serialized caches must not be used to establish quotient soundness.
    pub fn degree_multiple(&self) -> usize {
        match self {
            Self::Leaf(a) => a.degree_multiple(),
            Self::Add { degree_multiple, .. }
            | Self::Sub { degree_multiple, .. }
            | Self::Neg { degree_multiple, .. }
            | Self::Mul { degree_multiple, .. } => *degree_multiple,
        }
    }

    /// Try to view this expression as a base-field constant.
    fn as_const(&self) -> Option<&A::F> {
        match self {
            Self::Leaf(a) => a.as_const(),
            _ => None,
        }
    }

    /// Addition with constant folding and zero-identity elimination.
    fn sym_add(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a + b));
        }
        if self.as_const().is_some_and(|c| c.is_zero()) {
            return rhs;
        }
        if rhs.as_const().is_some_and(|c| c.is_zero()) {
            return self;
        }
        let dm = self.degree_multiple().max(rhs.degree_multiple());
        Self::Add {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }

    /// Subtraction with constant folding and zero-identity elimination.
    fn sym_sub(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a - b));
        }
        if self.as_const().is_some_and(|c| c.is_zero()) {
            return rhs.sym_neg();
        }
        if rhs.as_const().is_some_and(|c| c.is_zero()) {
            return self;
        }
        let dm = self.degree_multiple().max(rhs.degree_multiple());
        Self::Sub {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }

    /// Negation with constant folding.
    fn sym_neg(self) -> Self {
        if let Some(&c) = self.as_const() {
            return Self::Leaf(A::from_const(-c));
        }
        let dm = self.degree_multiple();
        Self::Neg { x: Arc::new(self), degree_multiple: dm }
    }

    /// Multiplication with constant folding, zero-annihilation, and one-identity.
    fn sym_mul(self, rhs: Self) -> Self {
        if let (Some(&a), Some(&b)) = (self.as_const(), rhs.as_const()) {
            return Self::Leaf(A::from_const(a * b));
        }
        if self.as_const().is_some_and(|c| c.is_zero())
            || rhs.as_const().is_some_and(|c| c.is_zero())
        {
            return Self::Leaf(A::from_const(A::F::ZERO));
        }
        if self.as_const().is_some_and(|c| c.is_one()) {
            return rhs;
        }
        if rhs.as_const().is_some_and(|c| c.is_one()) {
            return self;
        }
        let dm = self.degree_multiple() + rhs.degree_multiple();
        Self::Mul {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple: dm,
        }
    }
}

impl<A: SymLeaf> PrimeCharacteristicRing for SymbolicExpr<A> {
    type PrimeSubfield = <A::F as PrimeCharacteristicRing>::PrimeSubfield;

    const ZERO: Self = Self::Leaf(A::ZERO);
    const ONE: Self = Self::Leaf(A::ONE);
    const TWO: Self = Self::Leaf(A::TWO);
    const NEG_ONE: Self = Self::Leaf(A::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::Leaf(A::from_const(A::F::from_prime_subfield(f)))
    }
}

impl<A: SymLeaf> Dup for SymbolicExpr<A> {
    #[inline(always)]
    fn dup(&self) -> Self {
        self.clone()
    }
}

impl<A: SymLeaf> Default for SymbolicExpr<A> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Add<T> for SymbolicExpr<A> {
    type Output = Self;
    fn add(self, rhs: T) -> Self {
        self.sym_add(rhs.into())
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Sub<T> for SymbolicExpr<A> {
    type Output = Self;
    fn sub(self, rhs: T) -> Self {
        self.sym_sub(rhs.into())
    }
}

impl<A: SymLeaf> ops::Neg for SymbolicExpr<A> {
    type Output = Self;
    fn neg(self) -> Self {
        self.sym_neg()
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::Mul<T> for SymbolicExpr<A> {
    type Output = Self;
    fn mul(self, rhs: T) -> Self {
        self.sym_mul(rhs.into())
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::AddAssign<T> for SymbolicExpr<A> {
    fn add_assign(&mut self, rhs: T) {
        *self = self.dup() + rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::SubAssign<T> for SymbolicExpr<A> {
    fn sub_assign(&mut self, rhs: T) {
        *self = self.dup() - rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> ops::MulAssign<T> for SymbolicExpr<A> {
    fn mul_assign(&mut self, rhs: T) {
        *self = self.dup() * rhs.into();
    }
}

impl<A: SymLeaf, T: Into<Self>> Sum<T> for SymbolicExpr<A> {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into).reduce(|a, b| a + b).unwrap_or(Self::ZERO)
    }
}

impl<A: SymLeaf, T: Into<Self>> Product<T> for SymbolicExpr<A> {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into).reduce(|a, b| a * b).unwrap_or(Self::ONE)
    }
}
