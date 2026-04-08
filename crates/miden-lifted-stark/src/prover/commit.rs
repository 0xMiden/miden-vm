//! Trace commitment (LDE + LMCS).
//!
//! This module provides types and functions for committing traces with lifting support:
//!
//! - [`commit_traces`]: Commit traces with lifting support (LDE → LMCS)
//! - [`Committed`]: Wrapper around LMCS tree with domain metadata

use alloc::vec::Vec;

use miden_lifted_air::log2_strict_u8;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{
    Matrix,
    bitrev::{BitReversedMatrixView, BitReversibleMatrix},
    dense::{RowMajorMatrix, RowMajorMatrixView},
};
use tracing::info_span;

use crate::{
    StarkConfig,
    coset::LiftedCoset,
    lmcs::{Lmcs, LmcsTree, bitrev::materialize_bitrev},
};

// ============================================================================
// Committed
// ============================================================================

/// Committed polynomial evaluations with domain metadata.
///
/// Wraps an LMCS tree and stores the blowup used for the LDE.
///
/// We keep `log_blowup` here (instead of threading it through every call) so we can
/// recover per-matrix domain information (trace height, lift ratio, coset shift) from
/// just the committed matrices. This is especially useful when committing multiple
/// traces of different heights into one tree.
///
/// # Type Parameters
///
/// - `F`: Scalar field element type
/// - `M`: Matrix type (e.g., `RowMajorMatrix<F>`)
/// - `L`: LMCS configuration type
///
/// # Usage
///
/// ```ignore
/// let committed = commit_traces(config, traces);
/// let root = committed.root();
/// let view = committed.evals_on_quotient_domain(0, constraint_degree);
/// ```
///
/// Storing the blowup also avoids re-deriving `trace_height = lde_height / blowup` for each
/// matrix, which is needed for quotient-domain views and lifting shifts.
pub struct Committed<F, M, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
    M: Matrix<F>,
{
    /// The underlying LMCS tree.
    tree: L::Tree<M>,
    /// Log₂ of the blowup factor used during LDE.
    log_blowup: u8,
}

impl<F, M, L> Committed<F, M, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
    M: Matrix<F>,
{
    /// Create a new `Committed` wrapper.
    ///
    /// # Arguments
    ///
    /// - `tree`: The LMCS tree containing committed LDE matrices
    /// - `log_blowup`: Log₂ of the blowup factor used during LDE
    #[inline]
    pub fn new(tree: L::Tree<M>, log_blowup: u8) -> Self {
        Self { tree, log_blowup }
    }

    /// Get the commitment root.
    #[inline]
    pub fn root(&self) -> L::Commitment {
        self.tree.root()
    }

    /// Get a reference to the underlying tree.
    #[inline]
    pub fn tree(&self) -> &L::Tree<M> {
        &self.tree
    }

    /// Get log₂ of the maximum LDE height across all matrices.
    ///
    /// This is the height of the tree (the largest matrix height).
    #[inline]
    fn log_max_lde_height(&self) -> u8 {
        log2_strict_u8(self.tree.height())
    }

    /// Returns the [`LiftedCoset`] the `m`-th matrix was committed on.
    ///
    /// # Panics
    ///
    /// Panics if `m >= num_matrices()`.
    fn lifted_coset(&self, m: usize) -> LiftedCoset {
        let matrix = &self.tree.leaves()[m];
        let log_lde_height = log2_strict_u8(matrix.height());
        let log_trace_height = log_lde_height - self.log_blowup;
        let log_max_trace_height = self.log_max_lde_height() - self.log_blowup;

        LiftedCoset::new(log_trace_height, self.log_blowup, log_max_trace_height)
    }
}

impl<F, L> Committed<F, RowMajorMatrix<F>, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Return a zero-copy view of matrix `m` on the quotient evaluation domain.
    ///
    /// This returns evaluations over the quotient coset `gJ ⊆ gK`.
    ///
    /// The tree commits to LDE evaluations on `gK` (size `N·B`). The `RowMajorMatrix`
    /// stores bit-reversed evaluations; `gJ` appears as the first `N·D` rows, so this is
    /// a zero-copy prefix view followed by `bit_reverse_rows()` to expose natural order.
    ///
    /// # Panics
    ///
    /// Panics if `m >= num_matrices()`.
    pub fn evals_on_quotient_domain(
        &self,
        m: usize,
        constraint_degree: usize,
    ) -> BitReversedMatrixView<RowMajorMatrixView<'_, F>> {
        let quotient_height = self.lifted_coset(m).trace_height() * constraint_degree;
        self.tree.leaves()[m].split_rows(quotient_height).0.bit_reverse_rows()
    }
}

// ============================================================================
// commit_traces
// ============================================================================

/// Commit multiple trace matrices with lifting: LDE → LMCS tree.
///
/// Traces must be sorted by height in ascending order. Each trace is lifted to
/// the max LDE domain using the appropriate nested coset shift.
///
/// The DFT output is wrapped in `BitReversedMatrixView` (zero-cost view) and
/// passed directly to the LMCS — no materialization needed.
///
/// Returns a [`Committed`] wrapper providing:
/// - Commitment root via [`Committed::root()`]
/// - Underlying LMCS tree via [`Committed::tree()`]
/// - Quotient domain views via [`Committed::evals_on_quotient_domain()`]
///
/// # Arguments
/// - `config`: STARK configuration containing PCS params, LMCS, and DFT
/// - `traces`: Trace matrices sorted by height (ascending)
///
/// # Panics
/// - If `traces` is empty
/// - If trace heights are not powers of two
/// - If traces are not sorted by height in ascending order
///
/// Lifting note: for a trace of height `n` embedded into a max height `n_max`, let
/// `r = n_max / n`. The commitment should behave as if it contains evaluations of the
/// lifted polynomial `f_lift(X) = f(Xʳ)` on the max LDE coset. This is achieved by
/// evaluating the original trace on a *nested* coset with shift gʳ: the map
/// `(g·ω)ʳ = gʳ·ωʳ` sends the max domain down to the smaller one.
pub fn commit_traces<F, EF, SC>(
    config: &SC,
    traces: Vec<RowMajorMatrix<F>>,
) -> Committed<F, RowMajorMatrix<F>, SC::Lmcs>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
{
    assert!(!traces.is_empty(), "at least one trace required");

    // Validate traces are sorted by height
    assert!(
        traces.windows(2).all(|w| w[0].height() <= w[1].height()),
        "traces must be sorted by height in ascending order"
    );

    let log_blowup = config.pcs().log_blowup();

    // Find max trace height
    let max_trace_height = traces.last().unwrap().height();
    let log_max_trace_height = log2_strict_u8(max_trace_height);

    let ldes: Vec<_> = traces
        .into_iter()
        .enumerate()
        .map(|(idx, trace)| {
            let trace_height = trace.height();
            let width = trace.width();

            // Validate height is power of two
            assert!(
                trace_height.is_power_of_two(),
                "trace height must be power of two (index {idx})"
            );

            let log_trace_height = log2_strict_u8(trace_height);

            // Use LiftedCoset to compute the coset shift
            let coset = LiftedCoset::new(log_trace_height, log_blowup, log_max_trace_height);
            let coset_shift = coset.lde_shift::<F>();

            info_span!("LDE", trace = idx, log_height = log_trace_height, width).in_scope(|| {
                let lde = config.dft().coset_lde_batch(trace, log_blowup.into(), coset_shift);
                materialize_bitrev(lde)
            })
        })
        .collect();

    // Build aligned LMCS tree and wrap in Committed
    let tree = config.lmcs().build_aligned_tree(ldes);
    Committed::new(tree, log_blowup)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::PrimeCharacteristicRing;
    use p3_util::reverse_bits_len;

    use super::*;
    use crate::testing::configs::goldilocks_poseidon2::Felt;

    #[test]
    fn split_rows_truncates_correctly() {
        // Create a 16x4 matrix (LDE height = 16, width = 4)
        let data: Vec<Felt> = (0u64..64).map(Felt::from_u64).collect();
        let matrix = RowMajorMatrix::new(data, 4);

        // Truncate to 8 rows via split_rows
        let truncated = matrix.split_rows(8).0;
        assert_eq!(truncated.height(), 8);
        assert_eq!(truncated.width(), 4);

        // Verify first row is unchanged
        let row: Vec<Felt> = truncated.row(0).unwrap().into_iter().collect();
        assert_eq!(
            row,
            vec![Felt::from_u64(0), Felt::from_u64(1), Felt::from_u64(2), Felt::from_u64(3)]
        );
    }

    #[test]
    fn bit_reverse_rows_gives_natural_order() {
        // Create an 8x2 matrix with values that let us verify bit-reversal
        // Row i (bit-reversed) contains [2*i, 2*i+1]
        let data: Vec<Felt> = (0u64..16).map(Felt::from_u64).collect();
        let matrix = RowMajorMatrix::new(data, 2);

        let natural = matrix.as_view().bit_reverse_rows();
        assert_eq!(natural.height(), 8);
        assert_eq!(natural.width(), 2);

        // General verification: natural row i should have values from bit-reversed row bitrev(i)
        for i in 0..8 {
            let br_i = reverse_bits_len(i, 3);
            let natural_row: Vec<Felt> = natural.row(i).unwrap().into_iter().collect();
            let expected: Vec<Felt> =
                vec![Felt::from_u64((br_i * 2) as u64), Felt::from_u64((br_i * 2 + 1) as u64)];
            assert_eq!(natural_row, expected, "mismatch at natural row {i}");
        }
    }

    #[test]
    fn truncate_then_bit_reverse() {
        // Create a 16x2 matrix
        let data: Vec<Felt> = (0u64..32).map(Felt::from_u64).collect();
        let matrix = RowMajorMatrix::new(data, 2);

        // Truncate to 8 rows and convert to natural order
        let truncated_natural = matrix.split_rows(8).0.bit_reverse_rows();
        assert_eq!(truncated_natural.height(), 8);
        assert_eq!(truncated_natural.width(), 2);

        for i in 0..8 {
            let row: Vec<Felt> = truncated_natural.row(i).unwrap().into_iter().collect();
            assert_eq!(row.len(), 2, "row {i} should have 2 elements");
        }
    }
}
