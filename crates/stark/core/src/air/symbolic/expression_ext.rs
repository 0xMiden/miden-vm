// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from p3-air 0.8.0; see mod.rs documentation for provenance.

use p3_field::{
    Algebra, ExtensionField, Field,
    extension::{
        BinomialExtensionField, Complex, CubicTrinomialExtensionField,
        QuinticTrinomialExtensionField,
    },
};

use super::{AuxInput, Base, Expr, ExpressionDomain, Extension, RawExpr};

/// Extension-field symbolic value sharing the base expression's representation.
pub type SymbolicExpressionExt<F, EF> = Expr<F, EF, Extension>;

impl<F: Field, EF: ExtensionField<F>> Expr<F, EF, Extension> {
    /// Construct an immutable extension-domain input address.
    pub fn input(input: AuxInput) -> Self {
        input.into()
    }

    /// Construct an extension constant. A named constructor avoids overlap between
    /// generic `From<F>` and `From<EF>` when the extension is the base field itself.
    pub fn extension_constant(value: EF) -> Self {
        Self::from_raw(RawExpr::from_constant(ExpressionDomain::Extension, value))
    }
    /// Recover a base expression only when the tree contains no extension-only leaves.
    pub fn to_base(&self) -> Option<Expr<F, EF, Base>> {
        super::traversal::to_base(&self.raw).map(Expr::from_raw)
    }
}

// Distinct extension constructors avoid a generic From<EF>/From<F> coherence overlap.
macro_rules! extension_algebra {
    ([$($generic:tt)*] $extension:ty) => {
        impl<$($generic)*> From<$extension> for Expr<F, $extension, Extension>
        where F: Field, $extension: ExtensionField<F> {
            fn from(value: $extension) -> Self { Self::extension_constant(value) }
        }
        impl<$($generic)*> Algebra<$extension> for Expr<F, $extension, Extension>
        where F: Field, $extension: ExtensionField<F> {
            fn mixed_dot_product<const N: usize>(values: &[Self; N], coefficients: &[$extension; N]) -> Self {
                Self::linear_combination(values.iter().map(|v| v.raw.clone()).collect(), coefficients.iter().map(|v| Self::extension_constant(*v).raw).collect())
            }
            fn batched_linear_combination(values: &[Self], coefficients: &[$extension]) -> Self {
                Self::linear_combination(values.iter().map(|v| v.raw.clone()).collect(), coefficients.iter().map(|v| Self::extension_constant(*v).raw).collect())
            }
        }
    };
}
extension_algebra!([F, const DIM: usize] BinomialExtensionField<F, DIM>);
extension_algebra!([F] CubicTrinomialExtensionField<F>);
extension_algebra!([F] QuinticTrinomialExtensionField<F>);
extension_algebra!([F] BinomialExtensionField<Complex<F>, 2>);
