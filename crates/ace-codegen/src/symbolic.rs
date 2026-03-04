//! EF-only symbolic types for ACE constraint recording.
//!
//! All expressions live in the extension field (`EF`), eliminating the need
//! for base-to-extension conversions.

use core::{
    fmt::Debug,
    iter::{Product, Sum},
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use std::sync::Arc;

use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};

// ================================================================================================
// Entry
// ================================================================================================

/// Identifies which section of the trace a symbolic variable refers to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    Preprocessed { offset: usize },
    Main { offset: usize },
    Permutation { offset: usize },
    Aux { offset: usize },
    Periodic,
    AuxBusBoundary,
    Public,
    Challenge,
}

// ================================================================================================
// SymVar
// ================================================================================================

/// A symbolic variable referencing an entry and column index in the trace.
#[derive(Copy, Clone, Debug)]
pub struct SymVar<EF> {
    pub entry: Entry,
    pub index: usize,
    _phantom: PhantomData<EF>,
}

impl<EF> SymVar<EF> {
    pub const fn new(entry: Entry, index: usize) -> Self {
        Self { entry, index, _phantom: PhantomData }
    }
}

// --- SymVar arithmetic (delegates to SymExpr) ---

impl<EF: Field, T: Into<SymExpr<EF>>> Add<T> for SymVar<EF> {
    type Output = SymExpr<EF>;

    fn add(self, rhs: T) -> SymExpr<EF> {
        SymExpr::from(self) + rhs.into()
    }
}

impl<EF: Field, T: Into<SymExpr<EF>>> Sub<T> for SymVar<EF> {
    type Output = SymExpr<EF>;

    fn sub(self, rhs: T) -> SymExpr<EF> {
        SymExpr::from(self) - rhs.into()
    }
}

impl<EF: Field, T: Into<SymExpr<EF>>> Mul<T> for SymVar<EF> {
    type Output = SymExpr<EF>;

    fn mul(self, rhs: T) -> SymExpr<EF> {
        SymExpr::from(self) * rhs.into()
    }
}

// ================================================================================================
// SymExpr
// ================================================================================================

/// Simplified symbolic expression tree over the extension field.
///
/// Unlike the upstream `SymbolicExpression<F>`, this is always EF-typed and
/// drops the cached `degree_multiple` on arithmetic nodes.
#[derive(Clone, Debug)]
pub enum SymExpr<EF> {
    Variable(SymVar<EF>),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Constant(EF),
    Add(Arc<Self>, Arc<Self>),
    Sub(Arc<Self>, Arc<Self>),
    Neg(Arc<Self>),
    Mul(Arc<Self>, Arc<Self>),
}

// --- Default ---

impl<EF: Field> Default for SymExpr<EF> {
    fn default() -> Self {
        Self::Constant(EF::ZERO)
    }
}

// --- From conversions ---

impl<EF> From<SymVar<EF>> for SymExpr<EF> {
    fn from(var: SymVar<EF>) -> Self {
        Self::Variable(var)
    }
}

impl<F: Field, EF: ExtensionField<F>> From<F> for SymExpr<EF> {
    fn from(f: F) -> Self {
        Self::Constant(EF::from(f))
    }
}

// --- PrimeCharacteristicRing ---

impl<EF: Field> PrimeCharacteristicRing for SymExpr<EF> {
    type PrimeSubfield = EF::PrimeSubfield;

    const ZERO: Self = Self::Constant(EF::ZERO);
    const ONE: Self = Self::Constant(EF::ONE);
    const TWO: Self = Self::Constant(EF::TWO);
    const NEG_ONE: Self = Self::Constant(EF::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::Constant(EF::from_prime_subfield(f))
    }
}

// --- Algebra marker impls ---

impl<F: Field, EF: ExtensionField<F>> Algebra<F> for SymExpr<EF> {}

impl<EF: Field> Algebra<SymVar<EF>> for SymExpr<EF> {}

// --- Add ---

impl<EF: Field, T: Into<Self>> Add<T> for SymExpr<EF> {
    type Output = Self;

    fn add(self, rhs: T) -> Self {
        match (self, rhs.into()) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a + b),
            (Self::Constant(z), rhs) if z == EF::ZERO => rhs,
            (lhs, Self::Constant(z)) if z == EF::ZERO => lhs,
            (lhs, rhs) => Self::Add(Arc::new(lhs), Arc::new(rhs)),
        }
    }
}

impl<EF: Field, T: Into<Self>> AddAssign<T> for SymExpr<EF> {
    fn add_assign(&mut self, rhs: T) {
        *self = self.clone() + rhs.into();
    }
}

impl<EF: Field, T: Into<Self>> Sum<T> for SymExpr<EF> {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into).reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}

// --- Sub ---

impl<EF: Field, T: Into<Self>> Sub<T> for SymExpr<EF> {
    type Output = Self;

    fn sub(self, rhs: T) -> Self {
        match (self, rhs.into()) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a - b),
            (lhs, Self::Constant(z)) if z == EF::ZERO => lhs,
            (lhs, rhs) => Self::Sub(Arc::new(lhs), Arc::new(rhs)),
        }
    }
}

impl<EF: Field, T: Into<Self>> SubAssign<T> for SymExpr<EF> {
    fn sub_assign(&mut self, rhs: T) {
        *self = self.clone() - rhs.into();
    }
}

// --- Neg ---

impl<EF: Field> Neg for SymExpr<EF> {
    type Output = Self;

    fn neg(self) -> Self {
        match self {
            Self::Constant(c) => Self::Constant(-c),
            Self::Neg(inner) => Arc::unwrap_or_clone(inner),
            expr => Self::Neg(Arc::new(expr)),
        }
    }
}

// --- Mul ---

impl<EF: Field, T: Into<Self>> Mul<T> for SymExpr<EF> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self {
        match (self, rhs.into()) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a * b),
            (Self::Constant(z), _) | (_, Self::Constant(z)) if z == EF::ZERO => {
                Self::Constant(EF::ZERO)
            },
            (Self::Constant(o), rhs) if o == EF::ONE => rhs,
            (lhs, Self::Constant(o)) if o == EF::ONE => lhs,
            (lhs, rhs) => Self::Mul(Arc::new(lhs), Arc::new(rhs)),
        }
    }
}

impl<EF: Field, T: Into<Self>> MulAssign<T> for SymExpr<EF> {
    fn mul_assign(&mut self, rhs: T) {
        *self = self.clone() * rhs.into();
    }
}

impl<EF: Field, T: Into<Self>> Product<T> for SymExpr<EF> {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.map(Into::into).reduce(|x, y| x * y).unwrap_or(Self::ONE)
    }
}
