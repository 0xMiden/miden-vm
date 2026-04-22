//! Generic LogUp aux-trace construction: fraction buffer + accumulator + top-level driver.
//!
//! Prover collection writes `(multiplicity, encoded_denominator)` pairs into a
//! [`LookupFractions`] buffer (one flat `Vec<(F, EF)>` plus one flat `Vec<usize>` of per-row
//! per-column counts). The fused [`accumulate`] pass batch-inverts denominators and walks
//! rows in order with a running accumulator column, writing out the complete aux trace as a
//! [`RowMajorMatrix<EF>`]. [`accumulate_slow`] is the reference oracle that does the same
//! computation naively (one `try_inverse()` per fraction).
//!
//! [`build_logup_aux_trace`] is the top-level driver: it sources challenges /
//! periodic-column shape directly from the AIR's own trait methods, runs
//! [`build_lookup_fractions`] + [`accumulate`], and splits the matrix into an
//! `(aux_trace, committed_final)` pair. Any `LiftedAir + LookupAir` implementor can
//! delegate its `AuxBuilder::build_aux_trace` to it with a one-line body. Callers whose
//! verifier expects a different committed-finals width (e.g. the Miden MASM verifier,
//! which currently absorbs two values) pad the returned `Vec<EF>` themselves.
//!
//! ## Aux trace shape
//!
//! [`accumulate`] returns a [`RowMajorMatrix`] with `num_rows + 1` rows:
//!
//! - row 0 is the all-`ZERO` initial accumulator
//! - row `r` (for `1..=num_rows`) holds the running sum **after** row `r − 1`'s fraction
//!   contributions have been folded in
//! - row `num_rows` is therefore the global running sum across the entire trace
//!
//! The return value of [`build_logup_aux_trace`] splits that matrix in two:
//!
//! - `aux_trace` is the first `num_rows` rows of the accumulator — it starts at `ZERO` and ends at
//!   the running sum **before** the last row's contribution. The last row's fraction contribution
//!   does **not** appear in the aux trace.
//! - `committed_finals` is `[acc_final]`: the single accumulator terminal read out of row
//!   `num_rows`. Verifiers that want a wider absorbed-values vector (e.g. the Miden MASM verifier,
//!   which absorbs two, the second always `ZERO`) pad this themselves.
//!
//! ## Fraction buffer layout
//!
//! - `fractions` holds every `(multiplicity, encoded_denominator)` pair every row pushes, in the
//!   exact order the builder produces them. Across one row, column 0's fractions come first, then
//!   column 1's, …, then column `num_cols - 1`'s. Across rows, row 0's block comes before row 1's.
//! - `counts` has exactly `num_rows * num_cols` entries, laid out row-major: `counts[r * num_cols +
//!   c]` is the number of fractions row `r` pushed into column `c`. Equivalently,
//!   `counts.chunks(num_cols).nth(r)` is row `r`'s per-column tally.
//!
//! Both vecs are sized up front from [`LookupAir::column_shape`] so the hot row loop can
//! push into `Vec::with_capacity`-backed storage without re-allocating.

use alloc::{vec, vec::Vec};

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::LiftedAir;

use super::{
    Challenges, LookupAir, ProverLookupBuilder, prover::build_lookup_fractions,
};

/// Row-chunk granularity for the fused accumulator. Matches
/// [`crate::trace::main_trace::ROW_MAJOR_CHUNK_SIZE`] so we stay consistent with the
/// repo's row-major tuning: ~512 rows × avg shape ~3 ≈ 1.5 K fractions per chunk and
/// ~24 KiB of chunk-local scratch, comfortably L1-resident on any modern x86/arm core.
const ACCUMULATE_ROWS_PER_CHUNK: usize = 512;

// TOP-LEVEL DRIVER
// ================================================================================================

/// Generic `AuxBuilder::build_aux_trace` body for any `LiftedAir + LookupAir` AIR.
///
/// Sources `α`, `β`, `max_message_width`, `num_bus_ids`, and the periodic columns directly
/// from the AIR's trait methods, runs the collection + accumulation phases, and returns
/// `(aux_trace, vec![acc_final])`. AIRs wire this in with a near one-line body on their
/// `AuxBuilder` impl; verifiers that expect extra absorbed values (e.g. the Miden MASM
/// verifier, which absorbs two) extend the returned `Vec<EF>` themselves.
///
/// The challenges ordering (`challenges[0] = α`, `challenges[1] = β`) mirrors the
/// constraint-path adapter's `ConstraintLookupBuilder::new` so prover- and constraint-path
/// challenges line up.
pub fn build_logup_aux_trace<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    challenges: &[EF],
) -> (RowMajorMatrix<EF>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let _span = tracing::info_span!("build_aux_trace_logup").entered();

    let alpha = challenges[0];
    let beta = challenges[1];
    let lookup_challenges =
        Challenges::<EF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());
    let periodic = air.periodic_columns();

    let fractions = build_lookup_fractions(air, main, &periodic, &lookup_challenges);

    let full = accumulate(&fractions);
    let num_cols = full.width;
    let num_rows = main.height();
    debug_assert_eq!(
        full.values.len(),
        (num_rows + 1) * num_cols,
        "accumulate output buffer is sized for num_rows + 1 rows",
    );

    let mut data = full.values;
    let last_row: Vec<EF> = data.split_off(num_rows * num_cols);
    debug_assert_eq!(last_row.len(), num_cols);

    let aux_trace = RowMajorMatrix::new(data, num_cols);
    (aux_trace, vec![last_row[0]])
}

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
    /// `num_rows` rows. The flat fraction capacity is `num_rows * Σ shape`, so the row loop
    /// does not re-allocate as long as each row stays within its declared bound. The flat
    /// count capacity is `num_rows * shape.len()`.
    ///
    /// Takes `shape` by value so the caller owns the allocation (typically
    /// `air.column_shape().to_vec()`).
    pub fn from_shape(shape: Vec<usize>, num_rows: usize) -> Self {
        let num_cols = shape.len();
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
/// fused batch-inversion + partial-sum pass.
///
/// Column 0 is the sole running-sum accumulator; columns 1+ are fraction columns that
/// store per-row values directly.
///
/// Returns `aux[col]` of length `num_rows + 1`:
/// - `aux[0][0] = ZERO`, `aux[0][r+1] = aux[0][r] + Σ_col per_row_value[col]`
/// - `aux[i>0][r] = per_row_value[i]` for main row `r`
pub fn accumulate_slow<F, EF>(fractions: &LookupFractions<F, EF>) -> Vec<Vec<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    let mut aux: Vec<Vec<EF>> = (0..num_cols).map(|_| vec![EF::ZERO; num_rows + 1]).collect();

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
    let mut running_sum = EF::ZERO;

    let mut cursor = 0usize;
    for (row, row_counts) in flat_counts.chunks(num_cols).enumerate() {
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

        // Fraction columns: store per-row value at aux[col][row] (aux_curr convention).
        for col in 1..num_cols {
            aux[col][row] = per_row_value[col];
        }

        // Accumulator (col 0): running sum of ALL columns' per-row values.
        let row_total: EF = per_row_value.iter().copied().sum();
        running_sum += row_total;
        aux[0][row + 1] = running_sum;
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

/// Materialise the LogUp auxiliary trace from collected fractions.
///
/// Takes the flat `(multiplicity, denominator)` buffer produced by the prover collection
/// phase and returns the complete aux trace as a row-major matrix. Column 0 is the
/// running-sum accumulator; columns 1+ store per-row fraction sums directly.
///
/// ## Output layout
///
/// Returns a [`RowMajorMatrix<EF>`] with `num_rows + 1` rows and `num_cols` columns.
/// Let `fᵢ(r) = Σⱼ mⱼ · dⱼ⁻¹` be the sum of fractions assigned to column `i` on row `r`:
///
/// - Fraction columns (i > 0): `output[r][i] = fᵢ(r)`
/// - Accumulator (col 0): `output[0][0] = 0`, `output[r+1][0] = output[r][0] + Σᵢ fᵢ(r)`
///
/// ## Algorithm
///
/// **Prepass.** Build `row_frac_offsets` for O(1) row-range lookup into the flat buffer.
///
/// **Phase 1 (parallel).** Split rows into fixed-size chunks.
/// Each chunk independently: batch-inverts its denominators (Montgomery trick), computes
/// `fᵢ(r)` for every `(row, col)`, writes fraction columns into the output matrix, and
/// records the row total `t(r) = Σᵢ fᵢ(r)` into a side buffer.
///
/// **Phase 2 (sequential).** Prefix-sum over `t(r)` to fill the accumulator column:
/// `acc(r+1) = acc(r) + t(r)`. This step is inherently sequential (cross-row dependency)
/// but touches only one scalar per row.
pub fn accumulate<F, EF>(fractions: &LookupFractions<F, EF>) -> RowMajorMatrix<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    let out_rows = num_rows + 1;

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

    if num_rows == 0 || flat_fractions.is_empty() {
        return RowMajorMatrix::new(output_data, num_cols);
    }

    // Prepass: fraction-start offset for every row (length num_rows + 1). row_frac_offsets[r] =
    // start of row r's fractions in flat_fractions; row_frac_offsets[num_rows] = total count.
    let row_frac_offsets = compute_row_frac_offsets(flat_counts, num_rows, num_cols);
    debug_assert_eq!(row_frac_offsets.len(), num_rows + 1);
    debug_assert_eq!(row_frac_offsets[num_rows], flat_fractions.len());

    // Phase 1 operates on rows 0..num_rows of the output buffer. It writes fraction
    // columns (i > 0) and leaves col 0 untouched (still zero). The side buffer
    // row_totals collects t(r) = Σᵢ fᵢ(r) for phase 2's prefix sum.
    let frac_region = &mut output_data[..num_rows * num_cols];
    let mut row_totals: Vec<EF> = vec![EF::ZERO; num_rows];

    let rows_per_chunk = ACCUMULATE_ROWS_PER_CHUNK;

    let phase1 = |(chunk_idx, (chunk_out, totals_slice)): (usize, (&mut [EF], &mut [EF]))| {
        let row_lo = chunk_idx * rows_per_chunk;
        let row_hi = (row_lo + rows_per_chunk).min(num_rows);
        let chunk_rows = row_hi - row_lo;
        let frac_lo = row_frac_offsets[row_lo];
        let frac_hi = row_frac_offsets[row_hi];
        let chunk_fracs = &flat_fractions[frac_lo..frac_hi];
        let chunk_counts = &flat_counts[row_lo * num_cols..row_hi * num_cols];
        debug_assert_eq!(chunk_out.len(), chunk_rows * num_cols);
        debug_assert_eq!(totals_slice.len(), chunk_rows);

        if chunk_fracs.is_empty() {
            return;
        }

        // Batch-invert and scale: scratch[j] = mⱼ · dⱼ⁻¹ (ready to sum).
        // Allocated once per chunk (~1.5 K elements ≈ 24 KiB, L1-resident).
        let mut scratch: Vec<EF> = vec![EF::ZERO; chunk_fracs.len()];
        invert_and_scale(chunk_fracs, &mut scratch);

        let mut per_row_value: Vec<EF> = vec![EF::ZERO; num_cols];
        let mut cursor = 0usize;
        for row_in_chunk in 0..chunk_rows {
            let row_counts = &chunk_counts[row_in_chunk * num_cols..(row_in_chunk + 1) * num_cols];
            let out_row_base = row_in_chunk * num_cols;

            // fᵢ(r) = Σⱼ scratch[j]  (scratch already holds mⱼ · dⱼ⁻¹).
            for (col, &count) in row_counts.iter().enumerate() {
                let mut sum = EF::ZERO;
                for i in 0..count {
                    sum += scratch[cursor + i];
                }
                per_row_value[col] = sum;
                cursor += count;
            }

            // output[r][i] = fᵢ(r) for fraction columns i > 0.
            let out_row = &mut chunk_out[out_row_base..out_row_base + num_cols];
            out_row[1..].copy_from_slice(&per_row_value[1..]);

            // t(r) = Σᵢ fᵢ(r), consumed by phase 2.
            totals_slice[row_in_chunk] = per_row_value.iter().copied().sum();
        }
        debug_assert_eq!(cursor, chunk_fracs.len());
    };

    #[cfg(not(feature = "concurrent"))]
    {
        frac_region
            .chunks_mut(rows_per_chunk * num_cols)
            .zip(row_totals.chunks_mut(rows_per_chunk))
            .enumerate()
            .for_each(phase1);
    }
    #[cfg(feature = "concurrent")]
    {
        use miden_crypto::parallel::*;
        frac_region
            .par_chunks_mut(rows_per_chunk * num_cols)
            .zip(row_totals.par_chunks_mut(rows_per_chunk))
            .enumerate()
            .for_each(phase1);
    }

    // Phase 2: acc(0) = 0, acc(r+1) = acc(r) + t(r).
    // Writes col 0 of rows 1..=num_rows; row 0 col 0 stays at zero from the allocation.
    let mut acc = EF::ZERO;
    for r in 0..num_rows {
        acc += row_totals[r];
        output_data[(r + 1) * num_cols] = acc;
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

/// Montgomery batch inversion fused with multiplicity scaling: writes `scratch[j] = mⱼ · dⱼ⁻¹`
/// using one field inversion + O(N) multiplications.
///
/// The backward sweep multiplies each inverse by `mⱼ` (an `EF × F` mul, cheaper than
/// `EF × EF`) so the caller gets ready-to-sum fraction values without a second pass.
///
/// # Panics
///
/// Panics if the denominator product is zero (would indicate an upstream bug — individual
/// `dⱼ` are never zero because of the nonzero `bus_prefix[bus]` term).
fn invert_and_scale<F, EF>(chunk_fracs: &[(F, EF)], scratch: &mut [EF])
where
    F: Field,
    EF: ExtensionField<F>,
{
    debug_assert_eq!(scratch.len(), chunk_fracs.len());
    debug_assert!(!chunk_fracs.is_empty());

    // Forward pass: scratch[i] = d₀ · d₁ · … · dᵢ (prefix products of denominators).
    let mut acc = chunk_fracs[0].1;
    scratch[0] = acc;
    for i in 1..chunk_fracs.len() {
        acc *= chunk_fracs[i].1;
        scratch[i] = acc;
    }

    // One field inversion — amortised over the whole chunk.
    let mut running_inv = scratch[scratch.len() - 1]
        .try_inverse()
        .expect("LogUp denominator product must be non-zero (bus_prefix is never zero)");

    // Backward sweep: scratch[i] = mᵢ · dᵢ⁻¹.
    // At each step, running_inv = (dᵢ · dᵢ₊₁ · … · dₙ₋₁)⁻¹.
    // dᵢ⁻¹ = scratch[i-1] · running_inv (prefix product up to i-1 cancels all but dᵢ),
    // then we scale by mᵢ (EF × F) and fold dᵢ back into running_inv.
    for i in (1..chunk_fracs.len()).rev() {
        let (m_i, d_i) = chunk_fracs[i];
        scratch[i] = scratch[i - 1] * running_inv * m_i;
        running_inv *= d_i;
    }
    // i = 0: running_inv = d₀⁻¹.
    scratch[0] = running_inv * chunk_fracs[0].0;
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
        lookup::{LookupAir, LookupBuilder},
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
            Felt::new_unchecked(self.next() >> 32)
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

    fn fixture(shape: [usize; 2], num_rows: usize) -> LookupFractions<Felt, QuadFelt> {
        LookupFractions::from_shape(shape.to_vec(), num_rows)
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
        let one = Felt::new_unchecked(1);
        let two = Felt::new_unchecked(2);
        let d1 = QuadFelt::new([Felt::new_unchecked(3), Felt::new_unchecked(0)]);
        let d2 = QuadFelt::new([Felt::new_unchecked(5), Felt::new_unchecked(0)]);

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

        // Row 0: col 0 own = 1/d1 + 2/d2, col 1 own = 0
        // Row 1: col 0 own = 1/d1,         col 1 own = 2/d2
        let row0_col0 = d1_inv + d2_inv.double();
        let row1_col0 = d1_inv;
        let row1_col1 = d2_inv.double();

        // Column 0 (accumulator): [0, row0_col0+0, prev + row1_col0 + row1_col1]
        assert_eq!(aux[0][0], QuadFelt::ZERO);
        assert_eq!(aux[0][1], row0_col0);
        assert_eq!(aux[0][2], row0_col0 + row1_col0 + row1_col1);

        // Column 1 (fraction, aux_curr): [0, 2/d2, 0]
        // Row 0: col 1 has no fractions → aux[1][0] = 0
        // Row 1: col 1 has 2/d2 → aux[1][1] = 2/d2
        // Row 2 (extra row): don't care (committed final)
        assert_eq!(aux[1][0], QuadFelt::ZERO);
        assert_eq!(aux[1][1], row1_col1);
    }

    /// `LookupFractions::new` sizes the flat `fractions` Vec with `num_rows * Σ shape`
    /// capacity and the flat `counts` Vec with `num_rows * num_cols` capacity (so neither
    /// reallocates in the hot loop). Both start empty.
    #[test]
    fn new_reserves_capacity() {
        let air = FakeAir { shape: [3, 5] };
        let fx: LookupFractions<Felt, QuadFelt> =
            LookupFractions::from_shape(air.shape.to_vec(), 10);

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

        let fx = random_fixture(&SHAPE, NUM_ROWS, 0x00c0_ffee_beef_c0de);
        let slow = accumulate_slow(&fx);
        let fast = accumulate(&fx);
        assert_matrix_matches_slow(&slow, &fast, SHAPE.len(), NUM_ROWS);
    }

    /// Multi-chunk regression test: a fixture spanning multiple
    /// [`ACCUMULATE_ROWS_PER_CHUNK`]-row chunks (with a deliberately short trailing chunk)
    /// exercises phase 2's prefix-sum path. The trailing `+ 7` rows ensure the last
    /// chunk is smaller than the others and that `num_rows % rows_per_chunk != 0`, catching
    /// any off-by-one in the last-chunk bounds.
    #[test]
    fn accumulate_multi_chunk_matches_accumulate_slow() {
        const SHAPE: [usize; 4] = [1, 2, 3, 1];
        const NUM_ROWS: usize = ACCUMULATE_ROWS_PER_CHUNK * 3 + 7;

        let fx = random_fixture(&SHAPE, NUM_ROWS, 0xdead_beef_cafe_babe);
        let slow = accumulate_slow(&fx);
        let fast = accumulate(&fx);
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
        let aux = accumulate(&fx);
        assert_eq!(aux.width(), num_cols);
        assert_eq!(aux.height(), 1);
        assert!(aux.values.iter().all(|v| *v == QuadFelt::ZERO));
    }
}
