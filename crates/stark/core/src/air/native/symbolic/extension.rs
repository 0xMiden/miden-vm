// Derived from p3-air 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Modified for Miden: auxiliary addresses replace upstream variable wrappers; resolution and
// unchecked degree/lowering traversals are omitted. Concrete field conversions retain upstream
// coherence boundaries.

use p3_field::extension::{
    BinomialExtensionField, Complex, CubicTrinomialExtensionField, QuinticTrinomialExtensionField,
};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

use super::{BaseLeaf, RowOffset, SymLeaf, SymbolicExpr, SymbolicExpression};

/// Field-independent addresses in the extension-expression namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuxInput {
    Trace { offset: RowOffset, index: usize },
    Challenge(usize),
    Export(usize),
}

impl AuxInput {
    pub(crate) const fn degree_multiple(self) -> usize {
        match self {
            Self::Trace { .. } => 1,
            Self::Challenge(_) | Self::Export(_) => 0,
        }
    }
}

/// Extension expressions retain lifted base subtrees instead of erasing their input namespaces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExtLeaf<F, EF> {
    Base(SymbolicExpression<F>),
    Input(AuxInput),
    ExtConstant(EF),
}

pub type SymbolicExpressionExt<F, EF> = SymbolicExpr<ExtLeaf<F, EF>>;

impl<F: Field, EF: ExtensionField<F>> SymLeaf for ExtLeaf<F, EF> {
    type F = F;

    const ZERO: Self = Self::Base(SymbolicExpression::ZERO);
    const ONE: Self = Self::Base(SymbolicExpression::ONE);
    const TWO: Self = Self::Base(SymbolicExpression::TWO);
    const NEG_ONE: Self = Self::Base(SymbolicExpression::NEG_ONE);

    fn degree_multiple(&self) -> usize {
        match self {
            Self::Base(value) => value.degree_multiple(),
            Self::Input(input) => input.degree_multiple(),
            Self::ExtConstant(_) => 0,
        }
    }

    fn as_const(&self) -> Option<&F> {
        match self {
            Self::Base(SymbolicExpression::Leaf(BaseLeaf::Constant(value))) => Some(value),
            Self::ExtConstant(value) if value.is_in_basefield() => {
                Some(&value.as_basis_coefficients_slice()[0])
            },
            _ => None,
        }
    }

    fn from_const(value: F) -> Self {
        Self::Base(SymbolicExpression::from(value))
    }
}

impl<F: Field, EF: ExtensionField<F>> SymbolicExpressionExt<F, EF> {
    pub fn input(address: AuxInput) -> Self {
        Self::Leaf(ExtLeaf::Input(address))
    }
}

impl<F: Field, EF> From<SymbolicExpression<F>> for SymbolicExpressionExt<F, EF> {
    fn from(value: SymbolicExpression<F>) -> Self {
        Self::Leaf(ExtLeaf::Base(value))
    }
}

impl<F: Field, EF> From<F> for SymbolicExpressionExt<F, EF> {
    fn from(value: F) -> Self {
        Self::Leaf(ExtLeaf::Base(SymbolicExpression::from(value)))
    }
}

impl<F: Field, EF: ExtensionField<F>> Algebra<F> for SymbolicExpressionExt<F, EF> {}

impl<F: Field, EF: ExtensionField<F>> Algebra<SymbolicExpression<F>>
    for SymbolicExpressionExt<F, EF>
{
}

// A generic From<EF>/Algebra<EF> would overlap the base-F implementations when EF = F.
// The concrete extension constructors below are distinct types and retain upstream coherence.
impl<F: Field, const D: usize> From<BinomialExtensionField<F, D>>
    for SymbolicExpressionExt<F, BinomialExtensionField<F, D>>
where
    BinomialExtensionField<F, D>: ExtensionField<F>,
{
    fn from(value: BinomialExtensionField<F, D>) -> Self {
        Self::Leaf(ExtLeaf::ExtConstant(value))
    }
}

impl<F: Field, const D: usize> Algebra<BinomialExtensionField<F, D>>
    for SymbolicExpressionExt<F, BinomialExtensionField<F, D>>
where
    BinomialExtensionField<F, D>: ExtensionField<F>,
{
}

impl<F: Field> From<CubicTrinomialExtensionField<F>>
    for SymbolicExpressionExt<F, CubicTrinomialExtensionField<F>>
where
    CubicTrinomialExtensionField<F>: ExtensionField<F>,
{
    fn from(value: CubicTrinomialExtensionField<F>) -> Self {
        Self::Leaf(ExtLeaf::ExtConstant(value))
    }
}

impl<F: Field> Algebra<CubicTrinomialExtensionField<F>>
    for SymbolicExpressionExt<F, CubicTrinomialExtensionField<F>>
where
    CubicTrinomialExtensionField<F>: ExtensionField<F>,
{
}

impl<F: Field> From<QuinticTrinomialExtensionField<F>>
    for SymbolicExpressionExt<F, QuinticTrinomialExtensionField<F>>
where
    QuinticTrinomialExtensionField<F>: ExtensionField<F>,
{
    fn from(value: QuinticTrinomialExtensionField<F>) -> Self {
        Self::Leaf(ExtLeaf::ExtConstant(value))
    }
}

impl<F: Field> Algebra<QuinticTrinomialExtensionField<F>>
    for SymbolicExpressionExt<F, QuinticTrinomialExtensionField<F>>
where
    QuinticTrinomialExtensionField<F>: ExtensionField<F>,
{
}

// A complex tower's immediate base is Complex<F>, so the generic binomial implementation does
// not supply conversion from this extension when the symbolic base remains F.
impl<F: Field> From<BinomialExtensionField<Complex<F>, 2>>
    for SymbolicExpressionExt<F, BinomialExtensionField<Complex<F>, 2>>
where
    BinomialExtensionField<Complex<F>, 2>: ExtensionField<F>,
{
    fn from(value: BinomialExtensionField<Complex<F>, 2>) -> Self {
        Self::Leaf(ExtLeaf::ExtConstant(value))
    }
}

impl<F: Field> Algebra<BinomialExtensionField<Complex<F>, 2>>
    for SymbolicExpressionExt<F, BinomialExtensionField<Complex<F>, 2>>
where
    BinomialExtensionField<Complex<F>, 2>: ExtensionField<F>,
{
}
