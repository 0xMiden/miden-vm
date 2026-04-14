//! Single flat fraction + counts buffer for the prover-side LogUp collection phase.
//!
//! [`LookupFractions`] owns one flat `Vec<(F, EF)>` and one flat `Vec<usize>`:
//!
//! - `fractions` holds every `(multiplicity, encoded_denominator)` pair every row pushes, in the
//!   exact order the builder produces them. Across one row, column 0's fractions come first, then
//!   column 1's, …, then column `num_cols - 1`'s. Across rows, row 0's block comes before row 1's.
//! - `counts` has exactly `num_rows * num_cols` entries, laid out row-major: `counts[r * num_cols +
//!   c]` is the number of fractions row `r` pushed into column `c`. Equivalently,
//!   `counts.chunks(num_cols).nth(r)` is row `r`'s per-column tally.
//!
//! Both vecs are sized up front from [`super::LookupAir::column_shape`] so the hot row
//! loop can push into `Vec::with_capacity`-backed storage without re-allocating.
//!
//! The downstream batch-inversion + partial-sum pass (not implemented here) can:
//!
//! - Batch-invert denominators over the entire flat `fractions` slice — inversion doesn't care
//!   which column each entry belongs to.
//! - Compute per-column partial sums by walking rows in order with a single cursor into `fractions`
//!   and stepping through `counts` in lockstep, maintaining a `[EF; num_cols]` running-sum
//!   register. No per-column gather, no intermediate copies.
//!
//! [`accumulate_slow`] is the reference oracle that does this computation naively
//! (one `try_inverse()` per fraction).

use alloc::{vec, vec::Vec};

use miden_core::field::{ExtensionField, Field};

use super::{LookupAir, LookupBuilder};

// LOOKUP FRACTIONS
// ================================================================================================

/// Single flat fraction + counts buffer shared between the prover collection phase and
/// the downstream accumulator.
///
/// ## Layout
///
/// ```text
///   fractions (flat, row-major by write order):
///     | row 0, col 0 |  row 0, col 1 | ... | row 0, col C-1 || row 1, col 0 | ... |
///
///   counts (flat, row-major, length = num_rows * num_cols):
///     | r0c0 | r0c1 | ... | r0,C-1 | r1c0 | r1c1 | ... | r1,C-1 | ... |
/// ```
///
/// Row `r`'s contribution to column `c` is the slice
/// `fractions[prefix .. prefix + counts[r * num_cols + c]]`, where `prefix` is the running
/// sum of earlier `counts` entries. The accumulator walks rows in order with a single
/// cursor — no separate offset array, no gather.
///
/// No padding, no fixed stride: a row that contributes zero fractions to a column writes
/// zero entries and records `counts.push(0)`.
pub struct LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Flat fraction buffer, packed in builder write order (see the module doc).
    ///
    /// Exposed to the prover builder as `pub(super)` so it can split-borrow this field
    /// disjointly from `counts` inside `LookupBuilder::column`.
    pub(super) fractions: Vec<(F, EF)>,
    /// Flat count buffer, length `num_rows * num_cols` after a complete collection pass,
    /// laid out row-major so `counts[r * num_cols + c]` is the number of fractions row
    /// `r` pushed into column `c`.
    ///
    /// Exposed to the prover builder as `pub(super)` for the same split-borrow reason.
    pub(super) counts: Vec<usize>,
    /// Per-column upper bound on fractions a single row can push. Used as the capacity
    /// hint (`num_rows * Σ shape`) when allocating `fractions`, and as the reference for
    /// the debug-mode overflow check in the prover builder.
    pub(super) shape: Vec<usize>,
    /// Number of main-trace rows this buffer is sized for.
    num_rows: usize,
    /// Cached `shape.len()` — the permutation column count.
    num_cols: usize,
}

impl<F, EF> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Allocate a fresh buffer sized to hold every fraction an AIR can emit across
    /// `num_rows` rows. The flat fraction capacity is `num_rows * Σ shape`, so the row
    /// loop does not re-allocate as long as each row stays within its declared
    /// [`LookupAir::column_shape`] bound. The flat count capacity is `num_rows * num_cols`.
    pub fn new<A, LB>(air: &A, num_rows: usize) -> Self
    where
        A: LookupAir<LB>,
        LB: LookupBuilder<F = F, EF = EF>,
    {
        let shape: Vec<usize> = air.column_shape().to_vec();
        let num_cols = air.num_columns();
        debug_assert_eq!(shape.len(), num_cols, "column_shape length must equal num_columns",);
        let total_fraction_capacity: usize = num_rows * shape.iter().sum::<usize>();
        let fractions = Vec::with_capacity(total_fraction_capacity);
        let counts = Vec::with_capacity(num_rows * num_cols);
        Self {
            fractions,
            counts,
            shape,
            num_rows,
            num_cols,
        }
    }

    /// Number of permutation columns.
    pub fn num_columns(&self) -> usize {
        self.num_cols
    }

    /// Total rows this buffer was sized for.
    pub fn num_rows(&self) -> usize {
        self.num_rows
    }

    /// Per-column upper bound on fractions per row.
    pub fn shape(&self) -> &[usize] {
        &self.shape
    }

    /// Full flat fraction buffer, packed in builder write order. Length equals
    /// `Σ counts()` — i.e. the total number of fractions actually pushed.
    pub fn fractions(&self) -> &[(F, EF)] {
        &self.fractions
    }

    /// Full flat count buffer, row-major. Length equals `num_rows * num_cols` after a
    /// complete collection pass. Chunk with `counts().chunks(num_cols)` to get per-row
    /// slices, or index directly as `counts()[r * num_cols + c]`.
    pub fn counts(&self) -> &[usize] {
        &self.counts
    }
}

// SLOW ACCUMULATOR (REFERENCE ORACLE)
// ================================================================================================

/// Naive per-fraction partial-sum accumulator, used as the correctness oracle for the
/// eventual fused batch-inversion + partial-sum pass.
///
/// Returns `aux[col]` of length `num_rows + 1`, with:
///
/// ```text
///   aux[col][0]   = EF::ZERO
///   aux[col][r+1] = aux[col][r]
///                 + Σ_{i=0..counts[r * num_cols + col]} m_i · d_i.try_inverse().unwrap()
/// ```
///
/// Walks the flat `fractions` / `counts` buffers in lockstep with one cursor, maintaining
/// a `[EF; num_cols]` per-column running-sum register. Matches the memory-access pattern
/// the fused fast path will use, just with one `try_inverse()` per fraction instead of a
/// batched Montgomery inversion.
pub fn accumulate_slow<F, EF>(fractions: &LookupFractions<F, EF>) -> Vec<Vec<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    let mut aux: Vec<Vec<EF>> = (0..num_cols).map(|_| vec![EF::ZERO; num_rows + 1]).collect();
    let mut running = vec![EF::ZERO; num_cols];

    let flat_fractions = fractions.fractions();
    let flat_counts = fractions.counts();
    debug_assert_eq!(
        flat_counts.len(),
        num_rows * num_cols,
        "counts length {} != num_rows * num_cols {}",
        flat_counts.len(),
        num_rows * num_cols,
    );

    let mut cursor = 0usize;
    for (row, row_counts) in flat_counts.chunks(num_cols).enumerate() {
        for (col, &count) in row_counts.iter().enumerate() {
            for &(m, d) in &flat_fractions[cursor..cursor + count] {
                let d_inv = d
                    .try_inverse()
                    .expect("LogUp denominator must be non-zero (bus_prefix is never zero)");
                running[col] += d_inv * m;
            }
            aux[col][row + 1] = running[col];
            cursor += count;
        }
    }
    debug_assert_eq!(
        cursor,
        flat_fractions.len(),
        "cursor {cursor} != total fractions {}",
        flat_fractions.len(),
    );

    aux
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};

    use super::*;
    use crate::{
        Felt,
        constraints::lookup::{LookupAir, LookupBuilder},
    };

    /// Minimal `LookupAir` used to drive `LookupFractions::new` without pulling in the
    /// real Miden air. Only `num_columns()` and `column_shape()` are exercised; the
    /// other methods return sentinel values and `eval` is a no-op.
    struct FakeAir {
        shape: [usize; 2],
    }

    impl<LB: LookupBuilder> LookupAir<LB> for FakeAir {
        fn num_columns(&self) -> usize {
            self.shape.len()
        }
        fn column_shape(&self) -> &[usize] {
            &self.shape
        }
        fn max_message_width(&self) -> usize {
            0
        }
        fn num_bus_ids(&self) -> usize {
            0
        }
        fn eval(&self, _builder: &mut LB) {}
    }

    /// Bypass `LookupFractions::new` so we can build a fixture against `FakeAir` without
    /// having a real `LookupBuilder` impl on hand — `new` needs `LookupBuilder<F = …, EF = …>`
    /// in its bounds and the only concrete impl today is `ProverLookupBuilder`.
    fn fixture(shape: [usize; 2], num_rows: usize) -> LookupFractions<Felt, QuadFelt> {
        let total_fraction_capacity: usize = num_rows * shape.iter().sum::<usize>();
        LookupFractions {
            fractions: Vec::with_capacity(total_fraction_capacity),
            counts: Vec::with_capacity(num_rows * shape.len()),
            shape: shape.to_vec(),
            num_rows,
            num_cols: shape.len(),
        }
    }

    /// `accumulate_slow` returns `num_rows + 1` entries per column, starting at ZERO and
    /// reflecting the running sum of `m · d⁻¹` over each row's slice.
    ///
    /// Layout fed in:
    ///
    /// ```text
    ///   row 0: col 0 pushes 2, col 1 pushes 0
    ///   row 1: col 0 pushes 1, col 1 pushes 1
    ///
    ///   fractions = [(1, d1), (2, d2), (1, d1), (2, d2)]
    ///   counts    = [2, 0, 1, 1]
    /// ```
    #[test]
    fn accumulate_slow_hand_crafted() {
        let one = Felt::new(1);
        let two = Felt::new(2);
        let d1 = QuadFelt::new([Felt::new(3), Felt::new(0)]);
        let d2 = QuadFelt::new([Felt::new(5), Felt::new(0)]);

        let mut fx = fixture([2, 1], 2);
        // Row 0
        fx.fractions.push((one, d1));
        fx.fractions.push((two, d2));
        fx.counts.push(2); // col 0
        fx.counts.push(0); // col 1
        // Row 1
        fx.fractions.push((one, d1));
        fx.counts.push(1); // col 0
        fx.fractions.push((two, d2));
        fx.counts.push(1); // col 1

        let aux = accumulate_slow(&fx);
        assert_eq!(aux.len(), 2);
        assert_eq!(aux[0].len(), 3);
        assert_eq!(aux[1].len(), 3);

        let d1_inv = d1.try_inverse().unwrap();
        let d2_inv = d2.try_inverse().unwrap();

        // Column 0: [0, 1/d1 + 2/d2, (1/d1 + 2/d2) + 1/d1] = [0, 1/d1 + 2/d2, 2/d1 + 2/d2]
        assert_eq!(aux[0][0], QuadFelt::ZERO);
        assert_eq!(aux[0][1], d1_inv + d2_inv.double());
        assert_eq!(aux[0][2], d1_inv.double() + d2_inv.double());

        // Column 1: [0, 0, 2/d2]
        assert_eq!(aux[1][0], QuadFelt::ZERO);
        assert_eq!(aux[1][1], QuadFelt::ZERO);
        assert_eq!(aux[1][2], d2_inv.double());
    }

    /// `LookupFractions::new` sizes the flat `fractions` Vec with `num_rows * Σ shape`
    /// capacity and the flat `counts` Vec with `num_rows * num_cols` capacity (so neither
    /// reallocates in the hot loop). Both start empty.
    #[test]
    fn new_reserves_capacity() {
        let air = FakeAir { shape: [3, 5] };
        type LB<'a> = super::super::ProverLookupBuilder<'a, Felt, QuadFelt>;
        let fx: LookupFractions<Felt, QuadFelt> = LookupFractions::new::<_, LB<'_>>(&air, 10);

        assert_eq!(fx.num_columns(), 2);
        assert_eq!(fx.num_rows(), 10);
        assert_eq!(fx.shape(), &[3, 5]);
        assert!(fx.fractions.capacity() >= 10 * (3 + 5));
        assert!(fx.counts.capacity() >= 10 * 2);
        assert!(fx.fractions.is_empty());
        assert!(fx.counts.is_empty());
    }
}
