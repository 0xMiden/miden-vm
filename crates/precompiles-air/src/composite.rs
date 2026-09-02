//! Utilities for composing independently defined AIRs into disjoint column bands.

use alloc::vec::Vec;
use core::ops::Range;

use miden_core::utils::RowMajorMatrix;
use miden_lifted_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, WindowAccess};

/// A two-row window restricted to one contiguous column band.
#[derive(Clone)]
pub struct SlicedWindow<W> {
    inner: W,
    columns: Range<usize>,
}

impl<W> SlicedWindow<W> {
    fn new(inner: W, columns: Range<usize>) -> Self {
        Self { inner, columns }
    }
}

impl<T, W> WindowAccess<T> for SlicedWindow<W>
where
    W: WindowAccess<T>,
{
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.columns.clone()]
    }

    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.columns.clone()]
    }
}

/// Constraint-builder view for one AIR embedded in a larger composite AIR.
///
/// Public inputs and shared lookup challenges are forwarded unchanged. Main, preprocessed,
/// permutation-trace, permutation-value, and periodic-column views are restricted to the embedded
/// AIR's bands.
pub struct SubAirBuilder<'a, AB>
where
    AB: AirBuilder,
{
    inner: &'a mut AB,
    main_columns: Range<usize>,
    preprocessed: SlicedWindow<AB::PreprocessedWindow>,
    permutation_columns: Range<usize>,
    permutation_values: Range<usize>,
    periodic_columns: Range<usize>,
}

impl<'a, AB> SubAirBuilder<'a, AB>
where
    AB: AirBuilder,
{
    pub fn new(
        inner: &'a mut AB,
        main_columns: Range<usize>,
        preprocessed_columns: Range<usize>,
        permutation_columns: Range<usize>,
        permutation_values: Range<usize>,
        periodic_columns: Range<usize>,
    ) -> Self {
        let preprocessed = SlicedWindow::new(inner.preprocessed().clone(), preprocessed_columns);
        Self {
            inner,
            main_columns,
            preprocessed,
            permutation_columns,
            permutation_values,
            periodic_columns,
        }
    }
}

impl<AB> AirBuilder for SubAirBuilder<'_, AB>
where
    AB: AirBuilder,
{
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = SlicedWindow<AB::PreprocessedWindow>;
    type MainWindow = SlicedWindow<AB::MainWindow>;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;

    fn main(&self) -> Self::MainWindow {
        SlicedWindow::new(self.inner.main(), self.main_columns.clone())
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.inner.assert_zero(value);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.inner.periodic_values()[self.periodic_columns.clone()]
    }
}

impl<AB> ExtensionBuilder for SubAirBuilder<'_, AB>
where
    AB: ExtensionBuilder,
{
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;

    fn assert_zero_ext<I>(&mut self, value: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.inner.assert_zero_ext(value);
    }
}

impl<AB> PermutationAirBuilder for SubAirBuilder<'_, AB>
where
    AB: PermutationAirBuilder,
{
    type MP = SlicedWindow<AB::MP>;
    type RandomVar = AB::RandomVar;
    type PermutationVar = AB::PermutationVar;

    fn permutation(&self) -> Self::MP {
        SlicedWindow::new(self.inner.permutation(), self.permutation_columns.clone())
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.inner.permutation_values()[self.permutation_values.clone()]
    }
}

/// Extract one contiguous column band from every row of a matrix.
pub fn extract_band<T: Clone + Send + Sync>(
    matrix: &RowMajorMatrix<T>,
    columns: Range<usize>,
) -> RowMajorMatrix<T> {
    assert!(columns.start <= columns.end && columns.end <= matrix.width);
    let width = columns.len();
    let height = matrix.values.len() / matrix.width;
    let mut values = Vec::with_capacity(height * width);
    for row in matrix.values.chunks_exact(matrix.width) {
        values.extend_from_slice(&row[columns.clone()]);
    }
    RowMajorMatrix::new(values, width)
}

/// Concatenate same-height matrices row by row.
pub fn concatenate_bands<T: Clone + Send + Sync>(
    left: &RowMajorMatrix<T>,
    right: &RowMajorMatrix<T>,
) -> RowMajorMatrix<T> {
    let left_height = left.values.len() / left.width;
    let right_height = right.values.len() / right.width;
    assert_eq!(left_height, right_height, "column bands must have the same height");

    let width = left.width + right.width;
    let mut values = Vec::with_capacity(left_height * width);
    for row in 0..left_height {
        values.extend_from_slice(&left.values[row * left.width..(row + 1) * left.width]);
        values.extend_from_slice(&right.values[row * right.width..(row + 1) * right.width]);
    }
    RowMajorMatrix::new(values, width)
}
