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
//! If the symbolic evaluation in [`LiftedAir::log_quotient_degree`] succeeds (i.e.
//! does not panic), it proves that the AIR's `eval()` only accesses indices within
//! the declared dimensions. Any concrete builder constructed with matching dimensions
//! is therefore safe from out-of-bounds panics.
//!
//! Use [`LiftedAir::is_valid_builder`] to verify that a concrete builder's
//! dimensions match the AIR before calling `eval()`.

use alloc::vec::Vec;

use p3_air::{BaseAir, WindowAccess};
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_util::log2_ceil_usize;
use thiserror::Error;

use crate::{
    LiftedAirBuilder,
    auxiliary::{ReducedAuxValues, ReductionError, VarLenPublicInputs},
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
    /// [`AuxBuilder::build_aux_trace`](crate::AuxBuilder::build_aux_trace) alongside the aux
    /// trace matrix. Their count may differ from [`aux_width`](Self::aux_width) (the number of
    /// aux trace columns).
    ///
    /// These values are exposed to AIR constraints as *permutation values* via
    /// [`PermutationAirBuilder::permutation_values`](crate::PermutationAirBuilder::permutation_values).
    fn num_aux_values(&self) -> usize;

    /// Number of variable-length public inputs this AIR expects.
    ///
    /// Each input is a slice of base-field elements that
    /// [`reduced_aux_values`](Self::reduced_aux_values) reduces to a single value.
    /// The prover validates that witnesses provide exactly this many slices.
    ///
    /// Implementors of [`reduced_aux_values`](Self::reduced_aux_values) should verify
    /// that `var_len_public_inputs` contains exactly this many slices, returning
    /// [`ReductionError`] otherwise.
    fn num_var_len_public_inputs(&self) -> usize;

    /// Reduce this AIR's aux values to a [`ReducedAuxValues`] contribution.
    ///
    /// Called by the verifier (with concrete field values, not symbolic expressions)
    /// to compute each AIR's contribution to the global cross-AIR bus identity check.
    /// The verifier accumulates contributions across all AIRs and checks that the
    /// combined result is identity (prod=1, sum=0).
    ///
    /// # Arguments
    /// - `aux_values`: prover-supplied aux values (from the proof)
    /// - `challenges`: extension-field challenges (same as used for aux trace building)
    /// - `public_values`: this AIR's public values (base field)
    /// - `var_len_public_inputs`: reducible inputs for the cross-AIR identity check
    ///
    /// # Errors
    ///
    /// The verifier validates instance dimensions (public values length,
    /// var-len public inputs count) before calling this method, so
    /// implementations can assume correct input counts. However, the
    /// *length of each individual var-len slice* is not validated upfront —
    /// implementations that index into these slices must check lengths
    /// themselves or use the `Result` return type to report errors.
    ///
    /// Default: returns identity (correct for AIRs without buses).
    fn reduced_aux_values(
        &self,
        _aux_values: &[EF],
        _challenges: &[EF],
        _public_values: &[F],
        _var_len_public_inputs: VarLenPublicInputs<'_, F>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError>
    where
        EF: ExtensionField<F>,
    {
        Ok(ReducedAuxValues::identity())
    }

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

    /// Validate that this AIR satisfies the [`LiftedAir`] contract.
    ///
    /// The lifted STARK protocol relies on several structural properties of the AIR
    /// that can be checked statically (i.e. without a witness). This method verifies
    /// the subset that is machine-checkable; the full list of trust assumptions is
    /// documented in the module docs of `miden-lifted-stark`. Both the prover and
    /// verifier call this before proceeding, so a malformed AIR is caught early.
    ///
    /// # Checked properties
    ///
    /// - **No preprocessed trace** — the lifted STARK protocol does not support preprocessed
    ///   (fixed) columns; their presence is an error.
    /// - **Positive auxiliary width** — every lifted AIR must declare at least one auxiliary column
    ///   (`aux_width() > 0`).
    /// - **Well-formed periodic columns** — each periodic column must be non-empty and have a
    ///   power-of-two length.
    fn validate(&self) -> Result<(), AirStructureError> {
        if self.preprocessed_trace().is_some() {
            return Err(AirStructureError::PreprocessedTrace);
        }
        if self.aux_width() == 0 {
            return Err(AirStructureError::ZeroAuxWidth);
        }
        for (i, col) in self.periodic_columns().iter().enumerate() {
            if col.is_empty() || !col.len().is_power_of_two() {
                return Err(AirStructureError::InvalidPeriodicColumn {
                    index: i,
                    length: col.len(),
                });
            }
        }
        Ok(())
    }

    /// Evaluate all AIR constraints using the provided builder.
    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB);

    /// Log₂ of the number of quotient chunks, inferred from symbolic constraint analysis.
    ///
    /// Evaluates the AIR on a [`SymbolicAirBuilder`](crate::symbolic::SymbolicAirBuilder) to
    /// determine the maximum constraint degree M, then returns `log2_ceil(M - 1)` (padded so M
    /// ≥ 2).
    ///
    /// Uses `SymbolicAirBuilder<F>` (i.e. `EF = F`) which is sufficient for degree
    /// computation since extension-field operations have the same degree structure.
    ///
    /// # Why `M − 1` chunks?
    ///
    /// Let N be the trace height (so trace columns are polynomials of degree < N).
    /// Symbolic evaluation assigns each constraint a *degree multiple* M, meaning the
    /// resulting numerator polynomial C(X) has degree bounded by roughly M·(N − 1).
    ///
    /// In a STARK, the constraint numerator is divisible by the trace vanishing
    /// polynomial `Z_H(X) = Xᴺ − 1`, so the quotient polynomial
    /// `Q(X) = C(X) / Z_H(X)` has
    ///
    /// `deg(Q) ≤ deg(C) − N ≤ M·(N − 1) − N < (M − 1)·N`.
    ///
    /// We commit to Q(X) by splitting it into D chunks of degree < N. The bound above
    /// shows that D = M − 1 chunks suffice; we then round D up to a power of two and
    /// return `log2(D)`.
    ///
    /// We clamp M ≥ 2 so that D ≥ 1. If M = 1 then `deg(C) < N`, and divisibility by
    /// `Z_H` would force C(X) to be the zero polynomial (i.e. the constraint carries no
    /// information about the trace).
    fn log_quotient_degree(&self) -> usize
    where
        Self: Sized,
    {
        let mut builder = SymbolicAirBuilder::<F>::new(self.air_layout());
        self.eval(&mut builder);

        let base_degree_multiple =
            |constraint: &SymbolicExpression<F>| constraint.degree_multiple();
        let ext_degree_multiple =
            |constraint: &SymbolicExpressionExt<F, F>| constraint.degree_multiple();

        let base_degree =
            builder.base_constraints().iter().map(base_degree_multiple).max().unwrap_or(0);
        let ext_degree = builder
            .extension_constraints()
            .iter()
            .map(ext_degree_multiple)
            .max()
            .unwrap_or(0);
        let constraint_degree = base_degree.max(ext_degree).max(2);

        log2_ceil_usize(constraint_degree - 1)
    }

    /// Number of quotient chunks: `2^log_quotient_degree()`.
    fn constraint_degree(&self) -> usize
    where
        Self: Sized,
    {
        1 << self.log_quotient_degree()
    }

    /// Check that a builder's dimensions match this AIR.
    ///
    /// Verifies every data-carrying accessor on [`LiftedAirBuilder`]: main trace,
    /// preprocessed trace, aux trace, public values, randomness, aux values, and
    /// periodic values.
    ///
    /// This guards the invariant that makes [`eval`](Self::eval) panic-free: if
    /// the symbolic evaluation in [`log_quotient_degree`](Self::log_quotient_degree)
    /// succeeds and this check passes, then `eval()` cannot panic from
    /// out-of-bounds access on the builder's accessors.
    fn is_valid_builder<AB: LiftedAirBuilder<F = F>>(
        &self,
        builder: &AB,
    ) -> Result<(), AirStructureError> {
        let check =
            |part: TracePart, expected: usize, actual: usize| -> Result<(), AirStructureError> {
                if actual != expected {
                    return Err(AirStructureError::BuilderMismatch { part, expected, actual });
                }
                Ok(())
            };

        let main = builder.main();
        // Check current and next slices of the main trace.
        check(TracePart::Main, self.width(), main.current_slice().len())?;
        check(TracePart::Main, self.width(), main.next_slice().len())?;

        // Check current and next slices of the aux trace.
        let perm = builder.permutation();
        check(TracePart::Aux, self.aux_width(), perm.current_slice().len())?;
        check(TracePart::Aux, self.aux_width(), perm.next_slice().len())?;

        check(TracePart::PublicValues, self.num_public_values(), builder.public_values().len())?;
        check(
            TracePart::Randomness,
            self.num_randomness(),
            builder.permutation_randomness().len(),
        )?;
        check(TracePart::AuxValues, self.num_aux_values(), builder.permutation_values().len())?;
        check(
            TracePart::PeriodicValues,
            self.periodic_columns().len(),
            builder.periodic_values().len(),
        )?;

        Ok(())
    }
}

/// Which part of the trace a builder mismatch refers to.
#[derive(Copy, Clone, Debug)]
pub enum TracePart {
    Main,
    Aux,
    PublicValues,
    Randomness,
    AuxValues,
    PeriodicValues,
}

/// Errors intrinsic to a single AIR definition, independent of any instance
/// data. Returned by [`LiftedAir::validate`] and [`LiftedAir::is_valid_builder`].
#[derive(Debug, Error)]
pub enum AirStructureError {
    #[error("periodic column {index}: length must be positive power of two, got {length}")]
    InvalidPeriodicColumn { index: usize, length: usize },
    #[error("preprocessed traces are not supported")]
    PreprocessedTrace,
    #[error("{part:?} dimension mismatch: expected {expected}, got {actual}")]
    BuilderMismatch {
        part: TracePart,
        expected: usize,
        actual: usize,
    },
    #[error("aux width must be positive")]
    ZeroAuxWidth,
}
