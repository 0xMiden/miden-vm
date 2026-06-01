//! Trace commitment (LDE + LMCS).
//!
//! This module provides types and functions for committing traces with lifting support:
//!
//! - [`commit_traces`]: Commit traces with lifting support (LDE → LMCS)
//! - [`Committed`]: Wrapper around LMCS tree with domain metadata

use alloc::vec::Vec;

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
    domain::{Coset, EvaluationDomain, LiftedDomain},
    lmcs::{Lmcs, LmcsTree},
    util::bitrev::materialize_bitrev,
};

// ============================================================================
// Committed
// ============================================================================

/// Committed polynomial evaluations.
///
/// Thin wrapper around an LMCS tree. Per-matrix sizing for quotient evaluation
/// flows through the [`EvaluationDomain`] passed to
/// [`evals_on_quotient_domain`](Self::evals_on_quotient_domain) — the wrapper
/// itself doesn't carry domain metadata, so accessing matrix `m`'s evaluation
/// view doesn't trigger a per-call sub-domain construction (which would compute
/// a multiplicative inverse).
///
/// # Type Parameters
///
/// - `F`: Scalar field element type
/// - `M`: Matrix type (e.g., `RowMajorMatrix<F>`)
/// - `L`: LMCS configuration type
pub struct Committed<F, M, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
    M: Matrix<F>,
{
    /// The underlying LMCS tree.
    tree: L::Tree<M>,
}

impl<F, M, L> Committed<F, M, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
    M: Matrix<F>,
{
    /// Create a new `Committed` wrapper around an LMCS tree.
    #[inline]
    pub fn new(tree: L::Tree<M>) -> Self {
        Self { tree }
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
}

impl<F, L> Committed<F, RowMajorMatrix<F>, L>
where
    F: TwoAdicField,
    L: Lmcs<F = F>,
{
    /// Return a zero-copy view of matrix `m` on the quotient evaluation domain.
    ///
    /// This returns evaluations over the quotient coset `gJ ⊆ gK` for matrix `m`,
    /// sized to the per-matrix trace height times `eval_domain.quotient_degree()`.
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
        eval_domain: &EvaluationDomain<F>,
    ) -> BitReversedMatrixView<RowMajorMatrixView<'_, F>> {
        debug_assert_eq!(
            eval_domain.lifted().lde_height(),
            self.tree.leaves()[m].height(),
            "eval_domain LDE height must match matrix m's tree height",
        );
        self.tree.leaves()[m].split_rows(eval_domain.size()).0.bit_reverse_rows()
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
/// - `domains`: One pre-validated [`LiftedDomain`] per trace, in the same order as `traces`. The
///   last entry is the batch's max-trace domain (heights are sorted ascending).
/// - `traces`: Trace matrices, in the same order as `domains`. Each must have height matching its
///   paired `domains[i].trace_height()`.
///
/// # Panics
/// - If `domains` and `traces` have different lengths
/// - If any trace's height doesn't match its paired domain's `trace_height()`
///
/// Lifting note: for a trace of height `n` embedded into a max height `n_max`, let
/// `r = n_max / n`. The commitment should behave as if it contains evaluations of the
/// lifted polynomial `f_lift(X) = f(Xʳ)` on the max LDE coset. This is achieved by
/// evaluating the original trace on a *nested* coset with shift gʳ: the map
/// `(g·ω)ʳ = gʳ·ωʳ` sends the max domain down to the smaller one.
pub(super) fn commit_traces<F, EF, SC>(
    config: &SC,
    domains: &[LiftedDomain<F>],
    traces: Vec<RowMajorMatrix<F>>,
) -> Committed<F, RowMajorMatrix<F>, SC::Lmcs>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    SC: StarkConfig<F, EF>,
{
    assert_eq!(domains.len(), traces.len(), "domains and traces must have matching lengths");
    assert!(!traces.is_empty(), "at least one trace required");

    let log_blowup = config.pcs().log_blowup();

    let ldes: Vec<_> = traces
        .into_iter()
        .zip(domains)
        .enumerate()
        .map(|(idx, (trace, domain))| {
            let width = trace.width();
            assert_eq!(
                trace.height(),
                domain.trace_height(),
                "trace {idx} height does not match its domain",
            );

            let log_trace_height = domain.log_trace_height();
            let coset_shift = domain.lde_shift();

            info_span!("LDE", trace = idx, log_height = log_trace_height, width).in_scope(|| {
                let lde = config.dft().coset_lde_batch(trace, log_blowup.into(), coset_shift);
                materialize_bitrev(lde)
            })
        })
        .collect();

    // Build aligned LMCS tree and wrap in Committed
    let tree = config.lmcs().build_aligned_tree(ldes);
    Committed::new(tree)
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
            assert_eq!(
                truncated_natural.row(i).unwrap().into_iter().count(),
                2,
                "row {i} should have 2 elements"
            );
        }
    }
}
