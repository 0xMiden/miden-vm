// Derived from p3-air 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Modified for Miden: field-independent addresses replace upstream variable/window interfaces.

use p3_field::{Algebra, ExtensionField, Field, InjectiveMonomial};
use serde::{Deserialize, Serialize};

use super::{SymLeaf, SymbolicExpr};

/// The two rows available to an authored relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RowOffset {
    Current,
    Next,
}

impl RowOffset {
    pub const fn index(self) -> usize {
        match self {
            Self::Current => 0,
            Self::Next => 1,
        }
    }
}

/// Field-independent addresses in the base-expression namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BaseInput {
    Main { offset: RowOffset, index: usize },
    Preprocessed { offset: RowOffset, index: usize },
    Public(usize),
    Periodic(usize),
}

impl BaseInput {
    pub(crate) const fn degree_multiple(self) -> usize {
        match self {
            Self::Main { .. } | Self::Preprocessed { .. } | Self::Periodic(_) => 1,
            Self::Public(_) => 0,
        }
    }
}

/// Atomic base-expression inputs, selector polynomials and field constants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BaseLeaf<F> {
    Input(BaseInput),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Constant(F),
}

pub type SymbolicExpression<F> = SymbolicExpr<BaseLeaf<F>>;

impl<F: Field> SymLeaf for BaseLeaf<F> {
    type F = F;

    const ZERO: Self = Self::Constant(F::ZERO);
    const ONE: Self = Self::Constant(F::ONE);
    const TWO: Self = Self::Constant(F::TWO);
    const NEG_ONE: Self = Self::Constant(F::NEG_ONE);

    fn degree_multiple(&self) -> usize {
        match self {
            Self::Input(input) => input.degree_multiple(),
            Self::IsFirstRow | Self::IsLastRow => 1,
            Self::IsTransition | Self::Constant(_) => 0,
        }
    }

    fn as_const(&self) -> Option<&F> {
        match self {
            Self::Constant(value) => Some(value),
            _ => None,
        }
    }

    fn from_const(value: F) -> Self {
        Self::Constant(value)
    }
}

impl<F: Field> SymbolicExpression<F> {
    pub fn input(address: BaseInput) -> Self {
        Self::Leaf(BaseLeaf::Input(address))
    }
}

impl<F: Field, EF: ExtensionField<F>> From<F> for SymbolicExpression<EF> {
    fn from(value: F) -> Self {
        Self::Leaf(BaseLeaf::Constant(value.into()))
    }
}

impl<F: Field> Algebra<F> for SymbolicExpression<F> {}

// This is injective on values, but not a permutation of expression trees because degree caches
// are construction history. Keep the narrower upstream capability.
impl<F: Field + InjectiveMonomial<N>, const N: u64> InjectiveMonomial<N> for SymbolicExpression<F> {}
