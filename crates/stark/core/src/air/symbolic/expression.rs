// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Derived from p3-air 0.8.0; see README.md for provenance and local changes.

use super::{Base, BaseInput, Expr};
use p3_field::{ExtensionField, Field};

/// Base-field symbolic value, parameterized by the extension used by its capture session.
pub type SymbolicExpression<F, EF = F> = Expr<F, EF, Base>;

impl<F: Field, EF: ExtensionField<F>> Expr<F, EF, Base> {
    /// Construct an immutable base-domain input address.
    pub fn input(input: BaseInput) -> Self {
        input.into()
    }

    /// Construct a base-field constant without depending on a conversion trait.
    pub fn constant(value: F) -> Self {
        Self::from(value)
    }
}
