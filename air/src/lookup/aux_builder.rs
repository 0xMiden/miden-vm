//! Generic LogUp aux-trace construction.
//!
//! [`build_logup_aux_trace`] builds lookup fractions for an AIR and returns an `n`-row cyclic
//! auxiliary trace together with the normalized global sum `sigma_prime = sigma / n`.
//!
//! ## Aux trace shape
//!
//! Let `t(r)` be the total lookup contribution on row `r`, and let
//! `sigma = sum_r t(r)`. [`accumulate`] returns exactly `num_rows` rows:
//!
//! - row 0 has accumulator value `a(0) = 0`
//! - fraction columns store their per-row values on every row, including the last row
//! - column 0 satisfies `a(r + 1) = a(r) - sigma_prime + t(r)` cyclically, so the next row of the
//!   last row is row 0
//!
//! Summing the cyclic recurrence gives `num_rows * sigma_prime = sigma`. The single committed
//! auxiliary value is therefore `sigma_prime`, not a terminal accumulator row.
use alloc::{vec, vec::Vec};

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::LiftedAir;

use super::{Challenges, LookupAir, ProverLookupBuilder, prover::build_lookup_fractions};

/// Row-chunk granularity for the fused accumulator. Matches
/// [`crate::trace::main_trace::ROW_MAJOR_CHUNK_SIZE`] so we stay consistent with the
/// repo's row-major tuning: ~512 rows × avg shape ~3 ≈ 1.5 K fractions per chunk and
/// ~24 KiB of chunk-local scratch, comfortably L1-resident on any modern x86/arm core.
pub(crate) const ACCUMULATE_ROWS_PER_CHUNK: usize = 512;

// TOP-LEVEL DRIVER
// ================================================================================================

/// Generic `LiftedAir::build_aux_trace` body for any `LiftedAir + LookupAir` AIR.
///
/// Sources `alpha`, `beta`, `max_message_width`, `num_bus_ids`, and periodic columns from the AIR,
/// runs collection + normalized cyclic accumulation, and returns
/// `(aux_trace, vec![sigma_prime])`, where `sigma_prime = sigma / num_rows`.
///
/// The challenges ordering (`challenges[0] = alpha`, `challenges[1] = beta`) mirrors the
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

    debug_assert!(
        challenges.len() >= 2,
        "build_logup_aux_trace expects at least 2 challenges (alpha, beta), got {}",
        challenges.len(),
    );
    assert!(main.height() > 0, "LogUp normalization requires a non-empty trace");

    let alpha = challenges[0];
    let beta = challenges[1];
    let lookup_challenges =
        Challenges::<EF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());
    let periodic = air.periodic_columns();

    let fractions = build_lookup_fractions(air, main, &periodic, &lookup_challenges);

    let (aux_trace, sigma_prime) = accumulate(&fractions);
    debug_assert_eq!(aux_trace.height(), main.height());

    (aux_trace, vec![sigma_prime])
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
///     | r0,c0 | r0,c1 | ... | r0,C-1 || r1,c0 | ... |
///
///   counts (flat, row-major, length = num_rows * num_cols):
///     | r0,c0 | r0,c1 | ... | r0,C-1 | r1,c0 | r1,c1 | ... | r1,C-1 | ... |
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
    /// Flat fraction buffer in builder write order.
    pub(super) fractions: Vec<(F, EF)>,
    /// Per-row, per-column fraction counts in row-major order.
    pub(super) counts: Vec<usize>,
    /// Per-column upper bound on fractions emitted by one row.
    pub(super) shape: Vec<usize>,
    /// Number of main-trace rows.
    num_rows: usize,
    /// Number of lookup columns.
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

    #[cfg(feature = "concurrent")]
    /// Build a `LookupFractions` from already-populated `fractions` and `counts` buffers.
    pub(super) fn from_parts(
        shape: Vec<usize>,
        num_rows: usize,
        fractions: Vec<(F, EF)>,
        counts: Vec<usize>,
    ) -> Self {
        let num_cols = shape.len();
        debug_assert_eq!(counts.len(), num_rows * num_cols);

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

/// Naive per-fraction normalized cyclic accumulator, used as the correctness oracle for the
/// fused batch-inversion + partial-sum pass.
///
/// Returns `(aux, sigma_prime)`, where every auxiliary column has exactly `num_rows` entries.
/// Column 0 starts at zero and follows the normalized cyclic recurrence; columns 1+ store their
/// per-row values directly.
pub fn accumulate_slow<F, EF>(fractions: &LookupFractions<F, EF>) -> (Vec<Vec<EF>>, EF)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    assert!(num_rows > 0, "LogUp normalization requires a non-empty trace");
    assert!(num_cols > 0, "LogUp requires at least one accumulator column");
    let mut aux: Vec<Vec<EF>> = (0..num_cols).map(|_| vec![EF::ZERO; num_rows]).collect();

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
    let mut row_totals = vec![EF::ZERO; num_rows];

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

        row_totals[row] = per_row_value.iter().copied().sum();
    }
    debug_assert_eq!(
        cursor,
        flat_fractions.len(),
        "cursor {cursor} != total fractions {}",
        flat_fractions.len(),
    );

    let sigma: EF = row_totals.iter().copied().sum();
    let n_inv = EF::from_usize(num_rows)
        .try_inverse()
        .expect("LogUp trace length must be non-zero in the field");
    let sigma_prime = sigma * n_inv;

    let mut acc = EF::ZERO;
    for (row, &row_total) in row_totals.iter().enumerate() {
        aux[0][row] = acc;
        acc += row_total - sigma_prime;
    }
    debug_assert_eq!(acc, EF::ZERO, "normalized LogUp accumulator must close cyclically");

    (aux, sigma_prime)
}

// FUSED ACCUMULATOR (FAST PATH)
// ================================================================================================

/// Materialise the normalized cyclic LogUp auxiliary trace from collected fractions.
///
/// Returns `(aux_trace, sigma_prime)`, where the matrix has exactly `num_rows` rows. Let
/// `fᵢ(r) = Σⱼ mⱼ · dⱼ⁻¹`, `t(r) = Σᵢ fᵢ(r)`, and `sigma_prime = Σᵣ t(r) / num_rows`:
///
/// - Fraction columns (i > 0): `output[r][i] = fᵢ(r)`
/// - Accumulator (col 0): `output[0][0] = 0` and `output[(r+1) mod n][0] = output[r][0] -
///   sigma_prime + t(r)`
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
/// **Phase 2 (sequential).** Compute `sigma_prime`, then scan `t(r) - sigma_prime` to fill the
/// accumulator column. This step is inherently sequential but touches only one scalar per row.
pub fn accumulate<F, EF>(fractions: &LookupFractions<F, EF>) -> (RowMajorMatrix<EF>, EF)
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_cols = fractions.num_columns();
    let num_rows = fractions.num_rows();
    assert!(num_rows > 0, "LogUp normalization requires a non-empty trace");
    assert!(num_cols > 0, "LogUp requires at least one accumulator column");

    let mut output_data = vec![EF::ZERO; num_rows * num_cols];

    let flat_fractions = fractions.fractions();
    let flat_counts = fractions.counts();
    debug_assert_eq!(
        flat_counts.len(),
        num_rows * num_cols,
        "counts length {} != num_rows * num_cols {}",
        flat_counts.len(),
        num_rows * num_cols,
    );

    // Prepass: fraction-start offset for every row (length num_rows + 1). row_frac_offsets[r] =
    // start of row r's fractions in flat_fractions; row_frac_offsets[num_rows] = total count.
    let row_frac_offsets = compute_row_frac_offsets(flat_counts, num_rows, num_cols);
    debug_assert_eq!(row_frac_offsets.len(), num_rows + 1);
    debug_assert_eq!(row_frac_offsets[num_rows], flat_fractions.len());

    // Phase 1 operates on rows 0..num_rows of the output buffer. It writes fraction
    // columns (i > 0) and leaves col 0 untouched (still zero). The side buffer
    // row_totals collects t(r) = Σᵢ fᵢ(r) for phase 2's normalization and centered scan.
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

            // f_i(r) = sum_j scratch[j] (scratch already holds m_j * d_j^-1).
            for (col, &count) in row_counts.iter().enumerate() {
                let end = cursor + count;
                let sum = scratch[cursor..end].iter().copied().sum();
                per_row_value[col] = sum;
                cursor = end;
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

    // Phase 2: reduce the global sum, then scan the centered row totals. The parallel-iterator
    // shim uses Rayon when concurrency is enabled and executes sequentially otherwise. The
    // accumulator scan remains sequential because each row depends on its predecessor.
    use miden_crypto::parallel::*;
    let sigma: EF = row_totals.par_iter().copied().sum();
    let n_inv = EF::from_usize(num_rows)
        .try_inverse()
        .expect("LogUp trace length must be non-zero in the field");
    let sigma_prime = sigma * n_inv;

    // Writing the current accumulator before updating gives a(0) = 0 and leaves the final update
    // as the cyclic last-to-first edge.
    let mut acc = EF::ZERO;
    for r in 0..num_rows {
        output_data[r * num_cols] = acc;
        acc += row_totals[r] - sigma_prime;
    }
    debug_assert_eq!(acc, EF::ZERO, "normalized LogUp accumulator must close cyclically");

    (RowMajorMatrix::new(output_data, num_cols), sigma_prime)
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
    //
    // Loop invariant (entering iteration i, for i = n-1 down to 1):
    //     running_inv = (dᵢ · dᵢ₊₁ · … · dₙ₋₁)⁻¹
    //     scratch[i-1] = d₀ · d₁ · … · dᵢ₋₁  (left over from the forward pass)
    //
    // Then:
    //     dᵢ⁻¹ = scratch[i-1] · running_inv
    //     (prefix-product cancels every factor except dᵢ⁻¹ inside running_inv).
    // We scale by mᵢ (EF × F, cheaper than EF × EF) to yield the fraction directly, then
    // fold dᵢ into running_inv so the invariant holds for iteration i-1.
    // After the loop: running_inv = d₀⁻¹, ready for the i = 0 case below.
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
        slow_sigma_prime: QuadFelt,
        fast: &RowMajorMatrix<QuadFelt>,
        fast_sigma_prime: QuadFelt,
        num_cols: usize,
        num_rows: usize,
    ) {
        assert_eq!(fast.width(), num_cols, "fast.width() mismatch");
        assert_eq!(fast.height(), num_rows, "fast.height() mismatch");
        assert_eq!(slow_sigma_prime, fast_sigma_prime, "sigma_prime mismatch");
        assert_eq!(slow.len(), num_cols, "slow column count mismatch");
        for (col, slow_col) in slow.iter().enumerate() {
            assert_eq!(slow_col.len(), num_rows, "slow col {col} row count mismatch");
            for (row, &s) in slow_col.iter().enumerate() {
                let f = fast.get(row, col).expect("Accessed element is in bounds");
                assert_eq!(s, f, "row {row} col {col} differs: slow={s:?} fast={f:?}",);
            }
        }
    }

    /// Minimal `LookupAir` used to drive `LookupFractions::from_shape` without pulling in the
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

    /// `accumulate_slow` returns `num_rows` entries per column plus the normalized global sum.
    /// Column 0 is the centered cyclic accumulator; column 1 stores per-row values directly.
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

        let (aux, sigma_prime) = accumulate_slow(&fx);
        assert_eq!(aux.len(), 2);
        assert_eq!(aux[0].len(), 2);
        assert_eq!(aux[1].len(), 2);

        let d1_inv = d1.try_inverse().unwrap();
        let d2_inv = d2.try_inverse().unwrap();

        // Row 0: col 0 own = 1/d1 + 2/d2, col 1 own = 0
        // Row 1: col 0 own = 1/d1,         col 1 own = 2/d2
        let row0_col0 = d1_inv + d2_inv.double();
        let row1_col0 = d1_inv;
        let row1_col1 = d2_inv.double();

        let row0_total = row0_col0;
        let row1_total = row1_col0 + row1_col1;
        assert_eq!(sigma_prime.double(), row0_total + row1_total);

        // Column 0 stores a(0), a(1); the second row closes cyclically back to a(0).
        assert_eq!(aux[0][0], QuadFelt::ZERO);
        assert_eq!(aux[0][1], row0_total - sigma_prime);
        assert_eq!(aux[0][0], aux[0][1] + row1_total - sigma_prime);

        assert_eq!(aux[1][0], QuadFelt::ZERO);
        assert_eq!(aux[1][1], row1_col1);
    }

    /// `LookupFractions::from_shape` sizes the flat `fractions` Vec with `num_rows * Σ shape`
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

    /// Single-chunk random cross-check: a tiny fixture (32 rows) exercises one phase-1 fused
    /// Montgomery/walk chunk followed by the global normalization and centered scan.
    #[test]
    fn accumulate_matches_accumulate_slow_random() {
        const SHAPE: [usize; 3] = [2, 1, 3];
        const NUM_ROWS: usize = 32;
        const _: () = assert!(
            NUM_ROWS < ACCUMULATE_ROWS_PER_CHUNK,
            "must stay in one chunk to test phase 1",
        );

        let fx = random_fixture(&SHAPE, NUM_ROWS, 0x00c0_ffee_beef_c0de);
        let (slow, slow_sigma_prime) = accumulate_slow(&fx);
        let (fast, fast_sigma_prime) = accumulate(&fx);
        assert_matrix_matches_slow(
            &slow,
            slow_sigma_prime,
            &fast,
            fast_sigma_prime,
            SHAPE.len(),
            NUM_ROWS,
        );
    }

    /// Multi-chunk regression test: a fixture spanning multiple
    /// [`ACCUMULATE_ROWS_PER_CHUNK`]-row chunks exercises parallel row-total computation followed
    /// by global normalization and the centered scan. The trailing `+ 7` rows make the last chunk
    /// shorter and catch off-by-one errors in the chunk bounds.
    #[test]
    fn accumulate_multi_chunk_matches_accumulate_slow() {
        const SHAPE: [usize; 4] = [1, 2, 3, 1];
        const NUM_ROWS: usize = ACCUMULATE_ROWS_PER_CHUNK * 3 + 7;

        let fx = random_fixture(&SHAPE, NUM_ROWS, 0xdead_beef_cafe_babe);
        let (slow, slow_sigma_prime) = accumulate_slow(&fx);
        let (fast, fast_sigma_prime) = accumulate(&fx);
        assert_matrix_matches_slow(
            &slow,
            slow_sigma_prime,
            &fast,
            fast_sigma_prime,
            SHAPE.len(),
            NUM_ROWS,
        );
    }

    /// Normalization is undefined for an empty trace.
    #[test]
    #[should_panic(expected = "LogUp normalization requires a non-empty trace")]
    fn accumulate_rejects_empty_trace() {
        let shape = vec![2usize, 3, 1];
        let num_cols = shape.len();
        let fx: LookupFractions<Felt, QuadFelt> = LookupFractions {
            fractions: Vec::new(),
            counts: Vec::new(),
            shape,
            num_rows: 0,
            num_cols,
        };
        let _ = num_cols;
        let _ = accumulate(&fx);
    }

    #[test]
    fn accumulate_no_interactions_is_zero() {
        const NUM_ROWS: usize = 4;
        let mut fx = fixture([1, 1], NUM_ROWS);
        fx.counts.resize(NUM_ROWS * 2, 0);

        let (aux, sigma_prime) = accumulate(&fx);
        assert_eq!(aux.height(), NUM_ROWS);
        assert_eq!(sigma_prime, QuadFelt::ZERO);
        assert!(aux.values.iter().all(|&value| value == QuadFelt::ZERO));
    }

    #[test]
    fn accumulate_last_row_only_closes_cyclically() {
        const NUM_ROWS: usize = 4;
        let denominator = QuadFelt::from_u32(7);
        let contribution = denominator.try_inverse().unwrap();
        let mut fx = fixture([1, 1], NUM_ROWS);
        for row in 0..NUM_ROWS {
            if row == NUM_ROWS - 1 {
                fx.fractions.push((Felt::ONE, denominator));
                fx.counts.extend([1, 0]);
            } else {
                fx.counts.extend([0, 0]);
            }
        }

        let (aux, sigma_prime) = accumulate(&fx);
        assert_eq!(QuadFelt::from_usize(NUM_ROWS) * sigma_prime, contribution);
        let last_acc = aux.get(NUM_ROWS - 1, 0).unwrap();
        assert_eq!(QuadFelt::ZERO, last_acc + contribution - sigma_prime);
    }

    #[test]
    fn accumulate_single_row_commits_its_row_total() {
        let denominator = QuadFelt::from_u32(11);
        let contribution = denominator.try_inverse().unwrap().double();
        let mut fx = fixture([1, 1], 1);
        fx.fractions.push((Felt::from_u32(2), denominator));
        fx.counts.extend([1, 0]);

        let (aux, sigma_prime) = accumulate(&fx);
        assert_eq!(aux.height(), 1);
        assert_eq!(aux.get(0, 0).unwrap(), QuadFelt::ZERO);
        assert_eq!(sigma_prime, contribution);
    }
}
