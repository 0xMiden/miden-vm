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

use miden_core::{
    field::{ExtensionField, Field},
    utils::RowMajorMatrix,
};

use super::{LookupAir, LookupBuilder};

/// Row-chunk granularity for the fused accumulator. Matches
/// [`crate::trace::main_trace::ROW_MAJOR_CHUNK_SIZE`] so we stay consistent with the
/// repo's row-major tuning: ~512 rows × avg shape ~3 ≈ 1.5 K fractions per chunk and
/// ~24 KiB of chunk-local scratch, comfortably L1-resident on any modern x86/arm core.
const ACCUMULATE_ROWS_PER_CHUNK: usize = 512;

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
pub fn accumulate_slow<F, EF>(
    fractions: &LookupFractions<F, EF>,
    running_sum_cols: &[usize],
    fraction_map: &[&[usize]],
) -> Vec<Vec<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    let mut aux: Vec<Vec<EF>> = (0..num_cols).map(|_| vec![EF::ZERO; num_rows + 1]).collect();

    let is_running_sum: Vec<bool> = (0..num_cols).map(|c| running_sum_cols.contains(&c)).collect();

    let flat_fractions = fractions.fractions();
    let flat_counts = fractions.counts();
    debug_assert_eq!(
        flat_counts.len(),
        num_rows * num_cols,
        "counts length {} != num_rows * num_cols {}",
        flat_counts.len(),
        num_rows * num_cols,
    );

    let mut per_row_value = vec![EF::ZERO; num_cols];
    let mut running_sums = vec![EF::ZERO; num_cols];

    let mut cursor = 0usize;
    for (row, row_counts) in flat_counts.chunks(num_cols).enumerate() {
        // Compute per-row fraction value for each column.
        for (col, &count) in row_counts.iter().enumerate() {
            let mut sum = EF::ZERO;
            for &(m, d) in &flat_fractions[cursor..cursor + count] {
                let d_inv = d
                    .try_inverse()
                    .expect("LogUp denominator must be non-zero (bus_prefix is never zero)");
                sum += d_inv * m;
            }
            per_row_value[col] = sum;
            cursor += count;
        }

        // Write aux values: fraction columns get per-row values, running-sum columns
        // get cumulative sums that also fold in the fraction columns' per-row values.
        for col in 0..num_cols {
            if is_running_sum[col] {
                let rs_pos = running_sum_cols.iter().position(|&c| c == col).unwrap();
                let frac_cols = fraction_map[rs_pos];
                let mut delta = per_row_value[col];
                for &fc in frac_cols {
                    delta += per_row_value[fc];
                }
                running_sums[col] += delta;
                aux[col][row + 1] = running_sums[col];
            } else {
                // Fraction column: per-row value (no accumulation across rows).
                aux[col][row + 1] = per_row_value[col];
            }
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

// FUSED ACCUMULATOR (FAST PATH)
// ================================================================================================

/// Fused batch-inversion + accumulator, chunked and (with `concurrent`) parallelized by row.
///
/// Returns a [`RowMajorMatrix<EF>`] with `num_rows + 1` rows and `num_cols` columns. Row `0`
/// is the zero initial condition; row `r + 1` holds the accumulated value after row `r`'s
/// fraction contributions have been folded in (matching [`accumulate_slow`] exactly).
///
/// Columns are split into two roles based on `running_sum_cols` / `fraction_map`:
///
/// - **Running-sum columns** accumulate a cross-row partial sum of their own fractions plus the
///   associated fraction columns' per-row values.
/// - **Fraction columns** store only the per-row fraction value (no cross-row accumulation).
///
/// ## Why a matrix and not per-column `Vec`s
///
/// One contiguous heap allocation of size `(num_rows + 1) * num_cols`, row-major: within a
/// row all columns live in adjacent memory, so the per-row inner loop is a tight sequential
/// write. The previous `Vec<Vec<EF>>` layout scattered each column on the heap and forced
/// `num_cols` independent pointer chases per row.
///
/// ## Algorithm
///
/// **Prepass.** Build `row_frac_offsets: Vec<usize>` of length `num_rows + 1` so any row
/// range `[lo, hi)` can look up its flat-fraction slice in O(1). Sequential, O(num_rows ·
/// num_cols) `usize` adds.
///
/// **Phase 1 — chunked fused walk.** Split rows into groups of `ACCUMULATE_ROWS_PER_CHUNK`
/// and process each chunk independently (serial or rayon-parallel depending on the
/// `concurrent` feature):
///
/// 1. Montgomery inversion of the chunk's denominators into a chunk-local `scratch` buffer via
///    `invert_denoms_in_place`: one forward prefix-product pass, one `try_inverse`, one backward
///    sweep. Scratch fits in L1/L2 at the 512-row tuning.
/// 2. Forward walk by row over the chunk's counts slice. For each `(row, col)`:
///    - Compute the per-row fraction value `Σ m_i · d_i⁻¹`.
///    - **Fraction columns**: write the per-row value directly (no running sum).
///    - **Running-sum columns**: accumulate own fractions + associated fraction columns' per-row
///      values into a `running` register, then write `running[col]`.
/// 3. Final `running` for RS columns is copied into the chunk's slot in `chunk_totals`.
///
/// **Phase 2 — sequential scan.** Exclusive prefix scan over `chunk_totals` for RS columns
/// only — fraction columns need no cross-chunk offset.
///
/// **Phase 3 — parallel offset add.** Add per-column offset into every row of the chunk,
/// for RS columns only.
///
/// ## Panics
///
/// Panics if any stored denominator is zero (would indicate an upstream bug — real bus
/// encodings never produce zero because of the non-zero `bus_prefix[bus]` term).
pub fn accumulate<F, EF>(
    fractions: &LookupFractions<F, EF>,
    running_sum_cols: &[usize],
    fraction_map: &[&[usize]],
) -> RowMajorMatrix<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    let out_rows = num_rows + 1;

    let is_running_sum: Vec<bool> = (0..num_cols).map(|c| running_sum_cols.contains(&c)).collect();

    // Single contiguous row-major allocation: row 0 stays at ZERO, chunks write rows 1..=num_rows.
    let mut output_data = vec![EF::ZERO; out_rows * num_cols];

    let flat_fractions = fractions.fractions();
    let flat_counts = fractions.counts();
    debug_assert_eq!(
        flat_counts.len(),
        num_rows * num_cols,
        "counts length {} != num_rows * num_cols {}",
        flat_counts.len(),
        num_rows * num_cols,
    );

    // Early-out: empty trace (no rows, or rows with zero shape) — return the zero-initialized
    // matrix without touching anything. Row 0 is the only row and it's already ZERO.
    if num_rows == 0 || flat_fractions.is_empty() {
        return RowMajorMatrix::new(output_data, num_cols);
    }

    // Prepass: fraction-start offset for every row (length num_rows + 1). row_frac_offsets[r] =
    // start of row r's fractions in flat_fractions; row_frac_offsets[num_rows] = total count.
    let row_frac_offsets = compute_row_frac_offsets(flat_counts, num_rows, num_cols);
    debug_assert_eq!(row_frac_offsets.len(), num_rows + 1);
    debug_assert_eq!(row_frac_offsets[num_rows], flat_fractions.len());

    // Split row 0 off the front of the output — it stays ZERO. Chunks operate on `output_tail`,
    // which holds rows 1..=num_rows packed as `num_rows * num_cols` elements, and the row
    // `r` of `output` corresponds to index `(r - 1) * num_cols` of `output_tail`.
    let (row_zero, output_tail) = output_data.split_at_mut(num_cols);
    debug_assert!(row_zero.iter().all(|v| *v == EF::ZERO));

    let rows_per_chunk = ACCUMULATE_ROWS_PER_CHUNK;
    let num_chunks = num_rows.div_ceil(rows_per_chunk);
    let mut chunk_totals: Vec<EF> = vec![EF::ZERO; num_chunks * num_cols];

    // Phase 1: fused per-chunk inversion + local walk. Each closure invocation owns a
    // disjoint output slice + chunk_totals slot; rayon parallelizes when `concurrent` is on.
    let phase1 = |(chunk_idx, (chunk_out, totals_slot)): (usize, (&mut [EF], &mut [EF]))| {
        let row_lo = chunk_idx * rows_per_chunk;
        let row_hi = (row_lo + rows_per_chunk).min(num_rows);
        let chunk_rows = row_hi - row_lo;
        let frac_lo = row_frac_offsets[row_lo];
        let frac_hi = row_frac_offsets[row_hi];
        let chunk_fracs = &flat_fractions[frac_lo..frac_hi];
        let chunk_counts = &flat_counts[row_lo * num_cols..row_hi * num_cols];
        debug_assert_eq!(chunk_out.len(), chunk_rows * num_cols);
        debug_assert_eq!(totals_slot.len(), num_cols);

        if chunk_fracs.is_empty() {
            // Chunk has no fractions — its local prefix is identically ZERO for every row,
            // the output slice is already zero from the initial allocation, and the totals
            // slot stays at ZERO. Nothing to do.
            debug_assert!(chunk_out.iter().all(|v| *v == EF::ZERO));
            return;
        }

        // Chunk-local scratch for d_i⁻¹. Allocated once per chunk; reused across the
        // forward + backward + walk passes below. Typical size at the default tuning:
        // ~1.5 K EF elements ≈ 24 KiB, comfortably L1-resident.
        let mut scratch: Vec<EF> = vec![EF::ZERO; chunk_fracs.len()];
        invert_denoms_in_place(chunk_fracs, &mut scratch);

        // Per-column per-row fraction value scratch (reset each row).
        let mut per_row_value: Vec<EF> = vec![EF::ZERO; num_cols];
        // Running-sum register for RS columns only (local prefix, offset added in phase 3).
        let mut running: Vec<EF> = vec![EF::ZERO; num_cols];
        let mut cursor = 0usize;
        for row_in_chunk in 0..chunk_rows {
            let row_counts = &chunk_counts[row_in_chunk * num_cols..(row_in_chunk + 1) * num_cols];
            let out_row_base = row_in_chunk * num_cols;

            // First pass: compute per-row fraction value for each column.
            for (col, &count) in row_counts.iter().enumerate() {
                let mut sum = EF::ZERO;
                for i in 0..count {
                    let (m, _) = chunk_fracs[cursor + i];
                    sum += scratch[cursor + i] * m;
                }
                per_row_value[col] = sum;
                cursor += count;
            }

            // Second pass: write output values.
            for col in 0..num_cols {
                if is_running_sum[col] {
                    // RS column: accumulate own fractions + associated fraction columns.
                    let rs_pos = running_sum_cols.iter().position(|&c| c == col).unwrap();
                    let mut delta = per_row_value[col];
                    for &fc in fraction_map[rs_pos] {
                        delta += per_row_value[fc];
                    }
                    running[col] += delta;
                    chunk_out[out_row_base + col] = running[col];
                } else {
                    // Fraction column: per-row value only (no cross-row accumulation).
                    chunk_out[out_row_base + col] = per_row_value[col];
                }
            }
        }
        debug_assert_eq!(cursor, chunk_fracs.len());

        totals_slot.copy_from_slice(&running);
    };

    #[cfg(not(feature = "concurrent"))]
    {
        output_tail
            .chunks_mut(rows_per_chunk * num_cols)
            .zip(chunk_totals.chunks_mut(num_cols))
            .enumerate()
            .for_each(phase1);
    }
    #[cfg(feature = "concurrent")]
    {
        use miden_crypto::parallel::*;
        output_tail
            .par_chunks_mut(rows_per_chunk * num_cols)
            .zip(chunk_totals.par_chunks_mut(num_cols))
            .enumerate()
            .for_each(phase1);
    }

    // Phase 2: sequential exclusive prefix scan over chunk totals → chunk offsets. Only
    // running-sum columns need cross-chunk offsets; fraction columns stay at ZERO.
    let mut chunk_offsets: Vec<EF> = vec![EF::ZERO; num_chunks * num_cols];
    {
        let mut running = vec![EF::ZERO; num_cols];
        for c in 0..num_chunks {
            chunk_offsets[c * num_cols..(c + 1) * num_cols].copy_from_slice(&running);
            let totals = &chunk_totals[c * num_cols..(c + 1) * num_cols];
            for &rs_col in running_sum_cols {
                running[rs_col] += totals[rs_col];
            }
        }
    }

    // Phase 3: add each chunk's global offset into every row of its local-prefix slice.
    // Only running-sum columns need the offset; fraction columns are untouched.
    let phase3 = |(chunk_out, offset): (&mut [EF], &[EF])| {
        let has_nonzero_offset = running_sum_cols.iter().any(|&c| offset[c] != EF::ZERO);
        if !has_nonzero_offset {
            return;
        }
        for row_slice in chunk_out.chunks_exact_mut(num_cols) {
            for &rs_col in running_sum_cols {
                row_slice[rs_col] += offset[rs_col];
            }
        }
    };

    #[cfg(not(feature = "concurrent"))]
    {
        output_tail
            .chunks_mut(rows_per_chunk * num_cols)
            .zip(chunk_offsets.chunks(num_cols))
            .for_each(phase3);
    }
    #[cfg(feature = "concurrent")]
    {
        use miden_crypto::parallel::*;
        output_tail
            .par_chunks_mut(rows_per_chunk * num_cols)
            .zip(chunk_offsets.par_chunks(num_cols))
            .for_each(phase3);
    }

    RowMajorMatrix::new(output_data, num_cols)
}

/// Forward scan over the flat `counts` buffer producing per-row fraction-start offsets.
///
/// Returns a `Vec<usize>` of length `num_rows + 1` where `offsets[r]` is the starting index
/// of row `r`'s fractions in the flat `fractions.fractions()` buffer and `offsets[num_rows]`
/// equals the total fraction count. Sequential (O(num_rows · num_cols) `usize` adds).
fn compute_row_frac_offsets(flat_counts: &[usize], num_rows: usize, num_cols: usize) -> Vec<usize> {
    debug_assert_eq!(flat_counts.len(), num_rows * num_cols);
    let mut offsets = Vec::with_capacity(num_rows + 1);
    let mut acc = 0usize;
    offsets.push(0);
    for row_counts in flat_counts.chunks(num_cols) {
        for &count in row_counts {
            acc += count;
        }
        offsets.push(acc);
    }
    offsets
}

/// Montgomery's trick in place: overwrite `scratch` with the per-element inverses of
/// `chunk_fracs[i].1` using one real field inversion + O(N) multiplications.
///
/// Algorithm (classic Montgomery batch inversion):
///
/// 1. **Forward pass** — `scratch[i] = d_0 · d_1 · ... · d_i` (prefix products).
/// 2. **One inversion** — invert `scratch[last]` to obtain the running inverse of the whole
///    product.
/// 3. **Backward sweep** — walk i from `last` down to `1`, compute `scratch[i] = scratch[i-1] ·
///    running_inv` (which equals `d_i⁻¹`), then fold `d_i` back into `running_inv` so the next
///    iteration sees the inverse of `d_0 · ... · d_{i-1}`. At the end of the sweep `running_inv =
///    d_0⁻¹`, which we write into `scratch[0]`.
///
/// `scratch` must be sized to `chunk_fracs.len()` on entry; contents on entry are ignored
/// (fully overwritten).
///
/// # Panics
///
/// Panics if the product `d_0 · d_1 · ... · d_{last}` is zero. For LogUp denominators this
/// would indicate an upstream bug (individual `d_i` are never zero because of the nonzero
/// `bus_prefix[bus]` term, and the product of nonzero field elements is nonzero).
fn invert_denoms_in_place<F, EF>(chunk_fracs: &[(F, EF)], scratch: &mut [EF])
where
    F: Field,
    EF: ExtensionField<F>,
{
    debug_assert_eq!(scratch.len(), chunk_fracs.len());
    debug_assert!(!chunk_fracs.is_empty());

    // Forward pass: prefix products.
    let mut acc = chunk_fracs[0].1;
    scratch[0] = acc;
    for i in 1..chunk_fracs.len() {
        acc *= chunk_fracs[i].1;
        scratch[i] = acc;
    }

    // One field inversion — amortized over the whole chunk.
    let mut running_inv = scratch[scratch.len() - 1]
        .try_inverse()
        .expect("LogUp denominator product must be non-zero (bus_prefix is never zero)");

    // Backward sweep: in-place fill with individual inverses.
    for i in (1..chunk_fracs.len()).rev() {
        let d_i = chunk_fracs[i].1;
        scratch[i] = scratch[i - 1] * running_inv;
        running_inv *= d_i;
    }
    scratch[0] = running_inv;
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::Matrix,
    };

    use super::*;
    use crate::{
        Felt,
        lookup::{LookupAir, LookupBuilder, RunningSumLookupAir},
    };

    // Small deterministic LCG — reproducible stream for random-fixture cross-check tests.
    // We don't need cryptographic quality, just determinism.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0
        }
        fn felt(&mut self) -> Felt {
            // Take the high 32 bits to avoid the near-zero-biasing of low bits.
            Felt::new(self.next() >> 32)
        }
        fn quad(&mut self) -> QuadFelt {
            QuadFelt::new([self.felt(), self.felt()])
        }
    }

    /// Build a `LookupFractions` fixture of the given shape and row count, filled with
    /// reproducibly-random non-zero denominators and arbitrary base-field multiplicities.
    /// Shared helper for the cross-check tests.
    fn random_fixture(
        shape: &[usize],
        num_rows: usize,
        seed: u64,
    ) -> LookupFractions<Felt, QuadFelt> {
        let mut rng = Lcg(seed);
        let mut fx: LookupFractions<Felt, QuadFelt> = LookupFractions {
            fractions: Vec::with_capacity(num_rows * shape.iter().sum::<usize>()),
            counts: Vec::with_capacity(num_rows * shape.len()),
            shape: shape.to_vec(),
            num_rows,
            num_cols: shape.len(),
        };
        for _row in 0..num_rows {
            for &max_count in shape {
                let count = (rng.next() as usize) % (max_count + 1);
                for _ in 0..count {
                    let m = rng.felt();
                    // Rejection sample until we get a non-zero denominator. With a 64-bit
                    // Goldilocks field and random draws, this basically never loops.
                    let d = loop {
                        let candidate = rng.quad();
                        if candidate != QuadFelt::ZERO {
                            break candidate;
                        }
                    };
                    fx.fractions.push((m, d));
                }
                fx.counts.push(count);
            }
        }
        fx
    }

    /// Assert that `accumulate`'s row-major matrix output matches `accumulate_slow`'s per-column
    /// `Vec<Vec<EF>>` output element-by-element. Shared check used by the single-chunk and
    /// multi-chunk regression tests.
    fn assert_matrix_matches_slow(
        slow: &[Vec<QuadFelt>],
        fast: &RowMajorMatrix<QuadFelt>,
        num_cols: usize,
        num_rows: usize,
    ) {
        assert_eq!(fast.width(), num_cols, "fast.width() mismatch");
        assert_eq!(fast.height(), num_rows + 1, "fast.height() mismatch");
        assert_eq!(slow.len(), num_cols, "slow column count mismatch");
        for (col, slow_col) in slow.iter().enumerate() {
            assert_eq!(slow_col.len(), num_rows + 1, "slow col {col} row count mismatch");
            for (row, &s) in slow_col.iter().enumerate() {
                let f = fast.values[row * num_cols + col];
                assert_eq!(s, f, "row {row} col {col} differs: slow={s:?} fast={f:?}",);
            }
        }
    }

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

    impl RunningSumLookupAir for FakeAir {
        fn running_sum_columns(&self) -> &[usize] {
            &[0]
        }
        fn fraction_columns_for(&self, _running_sum_col: usize) -> &[usize] {
            &[1]
        }
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

    /// `accumulate_slow` returns `num_rows + 1` entries per column. Column 0 is a running
    /// sum that also folds in column 1's per-row values. Column 1 is a fraction column
    /// storing only per-row values (no cross-row accumulation).
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

        let rs_cols: &[usize] = &[0];
        let frac_map: &[&[usize]] = &[&[1]];
        let aux = accumulate_slow(&fx, rs_cols, frac_map);
        assert_eq!(aux.len(), 2);
        assert_eq!(aux[0].len(), 3);
        assert_eq!(aux[1].len(), 3);

        let d1_inv = d1.try_inverse().unwrap();
        let d2_inv = d2.try_inverse().unwrap();

        // Row 0: col 0 own = 1/d1 + 2/d2, col 1 own = 0
        // Row 1: col 0 own = 1/d1,         col 1 own = 2/d2
        let row0_col0 = d1_inv + d2_inv.double();
        let row1_col0 = d1_inv;
        let row1_col1 = d2_inv.double();

        // Column 0 (running sum, absorbs col 1): [0, row0_col0+0, prev + row1_col0 + row1_col1]
        assert_eq!(aux[0][0], QuadFelt::ZERO);
        assert_eq!(aux[0][1], row0_col0);
        assert_eq!(aux[0][2], row0_col0 + row1_col0 + row1_col1);

        // Column 1 (fraction): [0, 0, 2/d2]  (per-row values, no accumulation)
        assert_eq!(aux[1][0], QuadFelt::ZERO);
        assert_eq!(aux[1][1], QuadFelt::ZERO);
        assert_eq!(aux[1][2], row1_col1);
    }

    /// `LookupFractions::new` sizes the flat `fractions` Vec with `num_rows * Σ shape`
    /// capacity and the flat `counts` Vec with `num_rows * num_cols` capacity (so neither
    /// reallocates in the hot loop). Both start empty.
    #[test]
    fn new_reserves_capacity() {
        let air = FakeAir { shape: [3, 5] };
        type LB<'a> = crate::lookup::ProverLookupBuilder<'a, Felt, QuadFelt>;
        let fx: LookupFractions<Felt, QuadFelt> = LookupFractions::new::<_, LB<'_>>(&air, 10);

        assert_eq!(fx.num_columns(), 2);
        assert_eq!(fx.num_rows(), 10);
        assert_eq!(fx.shape(), &[3, 5]);
        assert!(fx.fractions.capacity() >= 10 * (3 + 5));
        assert!(fx.counts.capacity() >= 10 * 2);
        assert!(fx.fractions.is_empty());
        assert!(fx.counts.is_empty());
    }

    /// Single-chunk random cross-check: a tiny fixture (32 rows) fits inside one
    /// [`ACCUMULATE_ROWS_PER_CHUNK`] chunk, so phase 2's prefix scan and phase 3's offset
    /// add are both trivial (zero offset), and this test only exercises phase 1's fused
    /// Montgomery + walk path.
    #[test]
    fn accumulate_matches_accumulate_slow_random() {
        const SHAPE: [usize; 3] = [2, 1, 3];
        const NUM_ROWS: usize = 32;
        const _: () = assert!(
            NUM_ROWS < ACCUMULATE_ROWS_PER_CHUNK,
            "must stay in one chunk to test phase 1",
        );

        let rs_cols: &[usize] = &[0];
        let frac_map: &[&[usize]] = &[&[1, 2]];
        let fx = random_fixture(&SHAPE, NUM_ROWS, 0x00c0_ffee_beef_c0de);
        let slow = accumulate_slow(&fx, rs_cols, frac_map);
        let fast = accumulate(&fx, rs_cols, frac_map);
        assert_matrix_matches_slow(&slow, &fast, SHAPE.len(), NUM_ROWS);
    }

    /// Multi-chunk regression test: a fixture spanning multiple
    /// [`ACCUMULATE_ROWS_PER_CHUNK`]-row chunks (with a deliberately short trailing chunk)
    /// exercises phase 2's exclusive prefix scan and phase 3's per-chunk offset add — the
    /// code paths the single-chunk test can't hit. The trailing `+ 7` rows ensure the last
    /// chunk is smaller than the others and that `num_rows % rows_per_chunk != 0`, catching
    /// any off-by-one in the last-chunk bounds.
    #[test]
    fn accumulate_multi_chunk_matches_accumulate_slow() {
        const SHAPE: [usize; 4] = [1, 2, 3, 1];
        const NUM_ROWS: usize = ACCUMULATE_ROWS_PER_CHUNK * 3 + 7;

        let rs_cols: &[usize] = &[0];
        let frac_map: &[&[usize]] = &[&[1, 2, 3]];
        let fx = random_fixture(&SHAPE, NUM_ROWS, 0xdead_beef_cafe_babe);
        let slow = accumulate_slow(&fx, rs_cols, frac_map);
        let fast = accumulate(&fx, rs_cols, frac_map);
        assert_matrix_matches_slow(&slow, &fast, SHAPE.len(), NUM_ROWS);
    }

    /// Empty-trace smoke test: `num_rows = 0` must return a 1-row, `num_cols`-wide zero
    /// matrix (the initial condition) without touching the inversion path.
    #[test]
    fn accumulate_empty_trace() {
        let shape = vec![2usize, 3, 1];
        let num_cols = shape.len();
        let fx: LookupFractions<Felt, QuadFelt> = LookupFractions {
            fractions: Vec::new(),
            counts: Vec::new(),
            shape,
            num_rows: 0,
            num_cols,
        };
        let rs_cols: &[usize] = &[0];
        let frac_map: &[&[usize]] = &[&[1, 2]];
        let aux = accumulate(&fx, rs_cols, frac_map);
        assert_eq!(aux.width(), num_cols);
        assert_eq!(aux.height(), 1);
        assert!(aux.values.iter().all(|v| *v == QuadFelt::ZERO));
    }
}
