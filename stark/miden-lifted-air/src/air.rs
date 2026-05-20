//! The `LiftedAir` super-trait for AIR definitions in the lifted STARK system.
//!
//! # Panic safety of `eval()`
//!
//! [`LiftedAir::eval`] is generic over `AB: LiftedAirBuilder`, so it cannot branch
//! on the concrete builder type. All builders expose data through the same trait
//! methods — [`main()`](crate::AirBuilder::main),
//! [`permutation()`](crate::PermutationAirBuilder::permutation),
//! [`public_values()`](crate::AirBuilder::public_values),
//! [`permutation_randomness()`](crate::PermutationAirBuilder::permutation_randomness),
//! [`permutation_values()`](crate::PermutationAirBuilder::permutation_values), and
//! [`periodic_values()`](crate::PeriodicAirBuilder::periodic_values) — which return
//! matrices or slices.
//!
//! If the symbolic evaluation in [`LiftedAir::constraint_degree`] succeeds (i.e.
//! does not panic), it proves that the AIR's `eval()` only accesses indices within
//! the declared dimensions. Any concrete builder constructed with matching dimensions
//! is therefore safe from out-of-bounds panics.
//!
//! Use [`crate::debug::check_builder_shape`] to verify a concrete builder's
//! dimensions match the AIR before calling `eval()`.

use alloc::vec::Vec;

use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    LiftedAirBuilder,
    symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt},
};

/// Super-trait for AIR definitions used by the lifted STARK prover/verifier.
///
/// Inherits from upstream traits for width and public values.
/// Adds Miden-specific auxiliary trace support and periodic column data.
/// Every `LiftedAir` must provide an auxiliary trace (even if it is a minimal
/// 1-column dummy).
///
/// # Type Parameters
/// - `F`: Base field
/// - `EF`: Extension field (for aux trace challenges and aux values)
pub trait LiftedAir<F: Field, EF>: Sync + BaseAir<F> {
    /// Return the periodic table data: a list of columns, each a `Vec<F>` of evaluations.
    ///
    /// Each inner `Vec<F>` represents one periodic column. Its length is the period of
    /// that column, and the entries are the evaluations over a subgroup of that order.
    ///
    /// Default: no periodic columns.
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        Vec::new()
    }

    /// Return a matrix with all periodic columns extended to a common height.
    ///
    /// Columns with smaller periods are repeated cyclically to fill the extended domain.
    /// Returns `None` if there are no periodic columns.
    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<F>> {
        let cols = self.periodic_columns();
        if cols.is_empty() {
            return None;
        }

        let max_period = cols.iter().map(Vec::len).max()?;
        let num_cols = cols.len();

        let mut values = Vec::with_capacity(max_period * num_cols);
        for row in 0..max_period {
            for col in &cols {
                let period = col.len();
                values.push(col[row % period]);
            }
        }

        Some(RowMajorMatrix::new(values, num_cols))
    }

    /// Number of extension-field challenges required for the auxiliary trace.
    fn num_randomness(&self) -> usize;

    /// Number of extension-field columns in the auxiliary trace.
    fn aux_width(&self) -> usize;

    /// Number of extension-field aux values committed to the Fiat-Shamir transcript.
    ///
    /// These are the values returned by
    /// [`ProverInstance::build_aux_traces`](crate::ProverInstance::build_aux_traces)
    /// alongside the aux trace matrix. Their count may differ from
    /// [`aux_width`](Self::aux_width) (the number of aux trace columns).
    ///
    /// These values are exposed to AIR constraints as *permutation values* via
    /// [`PermutationAirBuilder::permutation_values`](crate::PermutationAirBuilder::permutation_values).
    fn num_aux_values(&self) -> usize;

    /// Return the [`AirLayout`] describing this AIR's dimensions.
    ///
    /// This is the single source of truth for building symbolic or layout builders.
    /// `preprocessed_width` is always 0 because lifted AIRs forbid preprocessed traces.
    fn air_layout(&self) -> AirLayout {
        AirLayout {
            preprocessed_width: 0,
            main_width: self.width(),
            num_public_values: self.num_public_values(),
            permutation_width: self.aux_width(),
            num_permutation_challenges: self.num_randomness(),
            num_permutation_values: self.num_aux_values(),
            num_periodic_columns: self.periodic_columns().len(),
        }
    }

    /// Evaluate all AIR constraints using the provided builder.
    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB);

    /// Symbolic constraint degree multiples, split into base-field and
    /// extension-field maxima (see [`ConstraintDegrees`]).
    ///
    /// The default evaluates the AIR on a
    /// [`SymbolicAirBuilder`](crate::symbolic::SymbolicAirBuilder) — using
    /// `SymbolicAirBuilder<F>` (i.e. `EF = F`), sufficient for degree computation
    /// since extension-field operations have the same degree structure. Override
    /// this when the split is known statically so a per-AIR bound can be sharp
    /// without redoing the symbolic pass.
    ///
    /// These are the raw symbolic degree multiples — no minimum is imposed and
    /// no clamping is applied. A degenerate AIR whose constraints all vanish
    /// under `Z_H` (combined degree `< 2`) is the prover/verifier's concern,
    /// not an air-crate structural check.
    fn constraint_degree(&self) -> ConstraintDegrees
    where
        Self: Sized,
    {
        raw_constraint_degree::<F, EF, Self>(self)
    }
}

/// Symbolic constraint degree multiples, split by constraint kind.
///
/// `base` is the maximum degree multiple over the base-field constraints and
/// `ext` over the extension-field constraints (each `0` if the AIR has none of
/// that kind). Consumers that need a single value take `base.max(ext)`; the
/// split is exposed via [`LiftedAir::constraint_degree`] so a per-AIR override
/// can be sharp without redoing the symbolic pass.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConstraintDegrees {
    /// Max degree multiple over base-field constraints (`0` if there are none).
    pub base: usize,
    /// Max degree multiple over extension-field constraints (`0` if there are none).
    pub ext: usize,
}

/// Raw constraint degree multiples from symbolic evaluation, before any
/// clamping. A combined value `< 2` (`base.max(ext) < 2`) means every
/// constraint is constant or linear in the trace variables, which forces the
/// constraint polynomial to zero after division by `Z_H` — i.e. the AIR
/// encodes no information about the trace.
fn raw_constraint_degree<F, EF, A>(air: &A) -> ConstraintDegrees
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    let mut builder = SymbolicAirBuilder::<F>::new(air.air_layout());
    air.eval(&mut builder);

    let base = builder
        .base_constraints()
        .iter()
        .map(SymbolicExpression::degree_multiple)
        .max()
        .unwrap_or(0);
    let ext = builder
        .extension_constraints()
        .iter()
        .map(SymbolicExpressionExt::degree_multiple)
        .max()
        .unwrap_or(0);
    ConstraintDegrees { base, ext }
}
