//! [`LookupBuilder`] adapter for concrete prover rows.
//!
//! The prover path evaluates an AIR against base-field row values and appends one
//! `(multiplicity, encoded_denominator)` entry for each active lookup interaction with nonzero
//! multiplicity to
//! [`LookupFractions`].

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, ops::Range};

use miden_crypto::field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupFractions,
    LookupGroup, LookupMessage,
};
use crate::air::RowWindow;

// PROVER LOOKUP BUILDER
// ================================================================================================

/// [`LookupBuilder`] over one concrete current/next-row window.
///
/// All expression-like associated types collapse to concrete field values on this path.
pub struct ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    periodic_values: &'a [F],
    challenges: &'a Challenges<EF>,
    /// Flat fractions and per-column counts shared across the collected rows.
    fractions: &'a mut LookupFractions<F, EF>,
    column_idx: usize,
    num_columns: usize,
}

impl<'a, F, EF> ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a prover-path adapter for one row pair.
    ///
    /// - `main`: two-row window over the current and next base-field rows.
    /// - `periodic_values`: periodic columns at the current row.
    /// - `challenges`: precomputed LogUp challenges (shared across every row; the caller builds
    ///   this once outside the row loop and passes a shared reference here).
    /// - `air`: the lookup shape (used only to validate the fraction-buffer width; the builder
    ///   never calls `air.eval` itself).
    /// - `fractions`: fraction and count buffers, sized via [`LookupFractions::from_shape`] and
    ///   reused across the collected rows.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the fraction-buffer width differs from `air.column_shape().len()`.
    pub fn new<A>(
        main: RowWindow<'a, F>,
        preprocessed: RowWindow<'a, F>,
        periodic_values: &'a [F],
        challenges: &'a Challenges<EF>,
        air: &A,
        fractions: &'a mut LookupFractions<F, EF>,
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        Self::from_shape(
            main,
            preprocessed,
            periodic_values,
            challenges,
            air.column_shape(),
            fractions,
        )
    }

    /// Shared constructor for legacy and native declarations. Shape is read without evaluating
    /// a relation, so the native collection path has no legacy `LookupAir` bound.
    pub(super) fn from_shape(
        main: RowWindow<'a, F>,
        preprocessed: RowWindow<'a, F>,
        periodic_values: &'a [F],
        challenges: &'a Challenges<EF>,
        shape: &[usize],
        fractions: &'a mut LookupFractions<F, EF>,
    ) -> Self {
        let num_columns = shape.len();
        debug_assert_eq!(fractions.num_columns(), num_columns, "fraction-buffer width mismatch");
        Self {
            main,
            preprocessed,
            periodic_values,
            challenges,
            fractions,
            column_idx: 0,
            num_columns,
        }
    }

    /// Validate that one concrete row emitted the declared number of columns.
    fn finish(self) {
        debug_assert_eq!(
            self.column_idx, self.num_columns,
            "LookupAir::eval emitted {} columns, but column_shape declares {}",
            self.column_idx, self.num_columns,
        );
    }
}

// BUILD LOOKUP FRACTIONS DRIVER
// ================================================================================================

/// Walk a complete main trace through [`ProverLookupBuilder`] and return its packed fractions
/// and per-column counts.
///
/// Generic over the base field `F` and extension field `EF`. The caller supplies the
/// main trace and periodic columns. This function does row slicing, periodic-column
/// indexing, and fraction collection. Concrete AIRs wrap this with their own
/// periodic-column layout.
///
/// # Arguments
///
/// - `air`: the [`LookupAir`] to evaluate.
/// - `main_trace`: row-major main execution trace. Row access is zero-copy via
///   `main_trace.values.borrow()`.
/// - `preprocessed_trace`: verifier-known trace for AIRs that declare preprocessed columns. Its
///   height must match `main_trace`; pass `None` when the AIR has no preprocessed columns.
/// - `periodic_columns`: one `Vec<F>` per periodic column, each with its own period.
/// - `challenges`: precomputed LogUp challenges (shared across every row).
///
/// # Panics
///
/// Panics in debug builds if any row pushes more fractions into a column than that
/// column's declared [`LookupAir::column_shape`] bound. This indicates the emitter's
/// `MAX_INTERACTIONS_PER_ROW` const is too low and needs to be bumped.
pub fn build_lookup_fractions<A, F, EF>(
    air: &A,
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    periodic_columns: &[Vec<F>],
    challenges: &Challenges<EF>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    A: Sync,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let num_rows = main_trace.height();
    let process_chunk = |rows| {
        build_lookup_fraction_chunk(
            air,
            main_trace,
            preprocessed_trace,
            periodic_columns,
            challenges,
            rows,
        )
    };

    collect_lookup_chunks(air.column_shape(), num_rows, process_chunk)
}

/// Shared chunk scheduling and ordered concatenation, independent of declaration syntax.
pub(super) fn collect_lookup_chunks<F, EF>(
    shape: &[usize],
    num_rows: usize,
    process_chunk: impl Fn(Range<usize>) -> LookupFractions<F, EF> + Sync,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    #[cfg(not(feature = "concurrent"))]
    let fractions = process_chunk(0..num_rows);

    // Concatenation after parallel processing preserves global row order because chunks
    // tile `0..num_rows` contiguously and each chunk's `fractions` / `counts` are
    // row-major within the chunk.
    #[cfg(feature = "concurrent")]
    let fractions = {
        use miden_crypto::parallel::*;

        let shape = shape.to_vec();
        let num_cols = shape.len();
        let rows_per_chunk = crate::lookup::aux_builder::ACCUMULATE_ROWS_PER_CHUNK;
        let num_chunks = num_rows.div_ceil(rows_per_chunk);

        let chunks: Vec<LookupFractions<F, EF>> = (0..num_chunks)
            .into_par_iter()
            .map(|chunk_idx| {
                let row_lo = chunk_idx * rows_per_chunk;
                let row_hi = (row_lo + rows_per_chunk).min(num_rows);
                process_chunk(row_lo..row_hi)
            })
            .collect();

        let total_fractions: usize = chunks.iter().map(|c| c.fractions.len()).sum();
        let (fractions_vec, counts_vec) = if current_num_threads() == 1 {
            let mut fractions_vec = Vec::with_capacity(total_fractions);
            let mut counts_vec = Vec::with_capacity(num_rows * num_cols);
            for chunk in chunks {
                fractions_vec.extend(chunk.fractions);
                counts_vec.extend(chunk.counts);
            }
            (fractions_vec, counts_vec)
        } else {
            let (fraction_chunks, count_chunks): (Vec<_>, Vec<_>) =
                chunks.into_iter().map(|chunk| (chunk.fractions, chunk.counts)).unzip();

            // Initialize the contiguous destinations in parallel, then copy each ordered chunk
            // into its disjoint destination slice. This keeps the public flat layout while
            // avoiding a single-threaded first-touch and copy of the complete lookup buffer.
            let mut fractions_vec: Vec<(F, EF)> =
                (0..total_fractions).into_par_iter().map(|_| (F::ZERO, EF::ZERO)).collect();
            let mut counts_vec: Vec<usize> =
                (0..num_rows * num_cols).into_par_iter().map(|_| 0).collect();

            let fraction_outputs =
                split_by_lengths_mut(&mut fractions_vec, fraction_chunks.iter().map(Vec::len));
            let count_outputs =
                split_by_lengths_mut(&mut counts_vec, count_chunks.iter().map(Vec::len));

            fraction_outputs
                .into_par_iter()
                .zip(fraction_chunks.into_par_iter())
                .for_each(|(output, chunk)| output.copy_from_slice(&chunk));
            count_outputs
                .into_par_iter()
                .zip(count_chunks.into_par_iter())
                .for_each(|(output, chunk)| output.copy_from_slice(&chunk));

            (fractions_vec, counts_vec)
        };

        LookupFractions::from_parts(shape, num_rows, fractions_vec, counts_vec)
    };

    debug_assert_eq!(
        fractions.counts().len(),
        num_rows * fractions.num_columns(),
        "counts buffer should have exactly num_rows * num_cols entries after collection",
    );
    debug_assert_eq!(fractions.shape(), shape, "collected lookup shape");
    fractions
}

#[cfg(feature = "concurrent")]
fn split_by_lengths_mut<T>(
    output: &mut [T],
    lengths: impl IntoIterator<Item = usize>,
) -> Vec<&mut [T]> {
    let lengths = lengths.into_iter();
    let mut remaining = output;
    let mut parts = Vec::with_capacity(lengths.size_hint().0);
    for len in lengths {
        let (part, tail) = core::mem::take(&mut remaining).split_at_mut(len);
        parts.push(part);
        remaining = tail;
    }
    assert!(remaining.is_empty(), "chunk lengths must cover the complete output buffer");
    parts
}

/// Collect a row range using global periodic offsets and cyclic next-row windows.
///
/// `preprocessed_trace`, when present, must have the main trace's height; its rows are exposed to
/// the lookup builder as a separate window (they are not prepended to `main`).
pub(super) fn build_lookup_fraction_chunk<A, F, EF>(
    air: &A,
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    periodic_columns: &[Vec<F>],
    challenges: &Challenges<EF>,
    rows: Range<usize>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    build_lookup_fraction_chunk_with(
        main_trace,
        preprocessed_trace,
        periodic_columns,
        challenges,
        air.column_shape(),
        rows,
        |_, builder| air.eval(builder),
    )
}

/// The sole row/periodic reader for both declaration interfaces.
pub(super) fn build_lookup_fraction_chunk_with<F, EF>(
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    periodic_columns: &[Vec<F>],
    challenges: &Challenges<EF>,
    shape: &[usize],
    rows: Range<usize>,
    eval: impl Fn(&super::native::LookupFrame<'_, F>, &mut ProverLookupBuilder<'_, F, EF>),
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[F] = main_trace.values.borrow();
    let (preprocessed_width, preprocessed_flat): (usize, &[F]) =
        preprocessed_trace.map_or((0, &[][..]), |trace| {
            assert_eq!(
                trace.height(),
                num_rows,
                "lookup-fraction collection expects preprocessed and main traces to have equal height"
            );
            (trace.width(), trace.values.borrow())
        });
    let empty_row: &[F] = &[];
    let mut chunk = LookupFractions::from_shape(shape.to_vec(), rows.len());
    let mut periodic_row = vec![F::ZERO; periodic_columns.len()];
    for r in rows {
        let curr = &flat[r * width..(r + 1) * width];
        let nxt_idx = (r + 1) % num_rows;
        let next = &flat[nxt_idx * width..(nxt_idx + 1) * width];
        let window = RowWindow::from_two_rows(curr, next);
        let (preprocessed_current, preprocessed_next) = if preprocessed_width == 0 {
            (empty_row, empty_row)
        } else {
            let curr = &preprocessed_flat[r * preprocessed_width..(r + 1) * preprocessed_width];
            let next = &preprocessed_flat
                [nxt_idx * preprocessed_width..(nxt_idx + 1) * preprocessed_width];
            (curr, next)
        };
        let preprocessed_window = RowWindow::from_two_rows(preprocessed_current, preprocessed_next);
        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }
        let frame = super::native::LookupFrame {
            main: crate::air::native::Rows { current: curr, next },
            preprocessed: crate::air::native::Rows {
                current: preprocessed_current,
                next: preprocessed_next,
            },
            periodic: &periodic_row,
        };
        let mut lb = ProverLookupBuilder::from_shape(
            window,
            preprocessed_window,
            &periodic_row,
            challenges,
            shape,
            &mut chunk,
        );
        eval(&frame, &mut lb);
        lb.finish();
    }
    chunk
}

impl<F: Field, EF: ExtensionField<F>> super::native::LookupBuilder
    for ProverLookupBuilder<'_, F, EF>
{
    type F = F;
    type Expr = F;
    type ExprEF = EF;
    type Column<'a>
        = <Self as LookupBuilder>::Column<'a>
    where
        Self: 'a;

    fn next_column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R, deg: Deg) -> R {
        LookupBuilder::next_column(self, f, deg)
    }
}

impl<'a, F, EF> LookupBuilder for ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = F;
    type Var = F;

    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    type PeriodicVar = F;

    type MainWindow = RowWindow<'a, F>;
    type PreprocessedWindow = RowWindow<'a, F>;

    type Column<'c>
        = ProverColumn<'c, F, EF>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
        _deg: Deg,
    ) -> R {
        let idx = self.column_idx;
        debug_assert!(
            idx < self.num_columns,
            "LookupAir::eval emitted more columns than column_shape declares ({})",
            self.num_columns,
        );
        let vec = &mut self.fractions.fractions;
        let counts = &mut self.fractions.counts;
        let shape_col = self.fractions.shape[idx];
        let start_len = vec.len();

        let (result, pushed) = {
            let mut col = ProverColumn {
                challenges: self.challenges,
                fractions: vec,
            };
            let result = f(&mut col);
            (result, col.fractions.len() - start_len)
        };
        debug_assert!(
            pushed <= shape_col,
            "column {idx} exceeded its shape bound: pushed {pushed}, shape says {shape_col}",
        );
        counts.push(pushed);
        self.column_idx += 1;
        result
    }
}

// PROVER COLUMN
// ================================================================================================

/// Per-column handle scoped to one [`LookupBuilder::next_column`] invocation.
pub struct ProverColumn<'c, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'c Challenges<EF>,
    fractions: &'c mut Vec<(F, EF)>,
}

impl<'c, F, EF> LookupColumn for ProverColumn<'c, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Expr = F;
    type ExprEF = EF;

    type Group<'g>
        = ProverGroup<'g, F, EF>
    where
        Self: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = ProverGroup {
            challenges: self.challenges,
            fractions: &mut *self.fractions,
        };
        f(&mut group)
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        _encoded: impl FnOnce(&mut Self::Group<'g>),
        deg: Deg,
    ) {
        // The prover path runs only the canonical closure. Cached encodings are a
        // constraint-path optimization; concrete rows encode each active message directly.
        self.group(name, canonical, deg);
    }
}

// PROVER GROUP
// ================================================================================================

/// Per-group handle used by the prover path.
///
/// Pushes individual `(multiplicity, denominator)` fractions into the column buffer.
///
/// ## Boolean-flag convention
///
/// The `flag` parameter on `add` / `remove` / `insert` is treated as a
/// 0/1 boolean selector: if `flag == F::ZERO` the interaction is
/// skipped entirely (no encode, no push); otherwise the push happens
/// with the canonical multiplicity (`+1` for `add`, `-1` for `remove`,
/// `multiplicity` for `insert`). This matches the constraint path's
/// `(V_g, U_g)` algebra, which silently assumes flag is 0 or 1 —
/// non-boolean flags produce wrong results on both sides.
pub struct ProverGroup<'g, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'g Challenges<EF>,
    fractions: &'g mut Vec<(F, EF)>,
}

impl<'g, F, EF> LookupGroup for ProverGroup<'g, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Expr = F;
    type ExprEF = EF;

    type Batch<'b>
        = ProverBatch<'b, F, EF>
    where
        Self: 'b;

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: F,
        multiplicity: F,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<F, EF>,
    {
        // The prover path short-circuits on `flag == F::ZERO`, while the constraint path
        // evaluates the encode unconditionally. The two agree only when `flag ∈ {0, 1}`.
        // Every Miden bus emitter drives `flag` as a product of decoder/op selectors constrained
        // to be boolean by the AIR. This assertion preserves parity with the constraint path.
        debug_assert!(
            flag == F::ZERO || flag == F::ONE,
            "ProverGroup::insert flag must be in {{0, 1}}; non-boolean flag would diverge \
             from the constraint path",
        );
        if flag == F::ZERO || multiplicity == F::ZERO {
            return;
        }
        let v = msg().encode(self.challenges);
        self.fractions.push((multiplicity, v));
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: F,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        // Same boolean-flag invariant as `insert`; see comment above.
        debug_assert!(
            flag == F::ZERO || flag == F::ONE,
            "ProverGroup::batch flag must be in {{0, 1}}; non-boolean flag would diverge \
             from the constraint path",
        );
        // When `active == false` every push inside the batch is a no-op — the
        // `msg.encode()` call is skipped too. The `build` closure still runs so
        // it can produce its `R` return value without requiring `R: Default`.
        let active = flag != F::ZERO;
        let mut batch = ProverBatch {
            challenges: self.challenges,
            fractions: &mut *self.fractions,
            active,
        };
        build(&mut batch)
    }

    fn beta_powers(&self) -> &[EF] {
        &self.challenges.beta_powers
    }

    fn bus_prefix(&self, bus_id: usize) -> EF {
        self.challenges.bus_prefix[bus_id]
    }

    fn selected_batch2_encoded(
        &mut self,
        _name: &'static str,
        _slot0_name: &'static str,
        slot0_multiplicity: F,
        slot0_encoded: impl FnOnce() -> EF,
        _slot1_name: &'static str,
        slot1_multiplicity: F,
        slot1_encoded: impl FnOnce() -> EF,
    ) {
        if slot0_multiplicity != F::ZERO {
            self.fractions.push((slot0_multiplicity, slot0_encoded()));
        }
        if slot1_multiplicity != F::ZERO {
            self.fractions.push((slot1_multiplicity, slot1_encoded()));
        }
    }
}

// PROVER BATCH
// ================================================================================================

/// Transient handle returned by [`LookupGroup::batch`] on the prover path.
///
/// Holds the same mutable borrow of the column's fraction `Vec` as the
/// enclosing [`ProverGroup`], plus an `active` flag copied from the
/// outer `batch(flag, …)` call. Inactive batches skip message encoding and do not push.
///
/// Each push appends one fraction entry when active and its multiplicity is nonzero. There's no
/// `(N, D)` state inside the batch — LogUp's aux-trace builder handles the combination downstream.
pub struct ProverBatch<'b, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'b Challenges<EF>,
    fractions: &'b mut Vec<(F, EF)>,
    active: bool,
}

impl<'b, F, EF> LookupBatch for ProverBatch<'b, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Expr = F;
    type ExprEF = EF;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: F, msg: M, _deg: Deg)
    where
        M: LookupMessage<F, EF>,
    {
        if !self.active || multiplicity == F::ZERO {
            return;
        }
        let v = msg.encode(self.challenges);
        self.fractions.push((multiplicity, v));
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: F,
        encoded: impl FnOnce() -> EF,
        _deg: Deg,
    ) {
        if !self.active || multiplicity == F::ZERO {
            return;
        }
        let v = encoded();
        self.fractions.push((multiplicity, v));
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{marker::PhantomData, vec, vec::Vec};

    use miden_crypto::{
        Felt,
        field::{Algebra, BinomialExtensionField, PrimeCharacteristicRing},
    };
    use p3_field::Dup;

    use super::*;
    use crate::{
        air::native,
        lookup::{
            Deg, LookupAir, accumulate_slow, message::LookupMessage, native as native_lookup,
        },
    };

    type QuadFelt = BinomialExtensionField<Felt, 2>;

    /// Encodes to `bus_prefix[0] + value`; the fixture's challenges keep it nonzero.
    #[derive(Clone, Copy, Debug)]
    struct SmokeMsg {
        value: Felt,
    }

    impl LookupMessage<Felt, QuadFelt> for SmokeMsg {
        fn encode(&self, challenges: &Challenges<QuadFelt>) -> QuadFelt {
            challenges.bus_prefix[0] + challenges.beta_powers[0] * self.value
        }
    }

    /// Two-column stand-in for the real Miden lookup AIR, with a handcrafted `eval` body
    /// that respects its own shape on **every** row — no mutual-exclusion assumptions, so
    /// random (non-trace) input data drives it without tripping the shape debug_assert.
    ///
    /// - Column 0 always pushes 2 fractions (one `add`, one `remove`) with shape 2.
    /// - Column 1 pushes 1 fraction via an inside-batch `insert` with shape 1.
    struct SmokeAir;

    const SMOKE_SHAPE: [usize; 2] = [2, 1];

    impl<LB> native_lookup::LookupAir<LB> for SmokeAir
    where
        LB: native_lookup::LookupBuilder<F = Felt, Expr = Felt, ExprEF = QuadFelt>,
    {
        fn column_shape(&self) -> &[usize] {
            &SMOKE_SHAPE
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }
        fn eval(&self, _frame: &native_lookup::LookupFrame<'_, Felt>, builder: &mut LB) {
            builder.next_column(
                |col| {
                    col.group(
                        "smoke_grp_0",
                        |g| {
                            g.add(
                                "smoke_add",
                                Felt::ONE,
                                || SmokeMsg { value: Felt::ONE },
                                Deg { v: 0, u: 0 },
                            );
                            g.remove(
                                "smoke_remove",
                                Felt::ONE,
                                || SmokeMsg { value: Felt::new_unchecked(2) },
                                Deg { v: 0, u: 0 },
                            );
                        },
                        Deg { v: 0, u: 0 },
                    );
                },
                Deg { v: 0, u: 0 },
            );
            builder.next_column(
                |col| {
                    col.group(
                        "smoke_grp_1",
                        |g| {
                            g.batch(
                                "smoke_batch",
                                Felt::ONE,
                                |b| {
                                    b.insert(
                                        "smoke_batch_insert",
                                        Felt::ONE,
                                        SmokeMsg { value: Felt::new_unchecked(3) },
                                        Deg { v: 0, u: 0 },
                                    );
                                },
                                Deg { v: 0, u: 0 },
                            );
                        },
                        Deg { v: 0, u: 0 },
                    );
                },
                Deg { v: 0, u: 0 },
            );
        }
    }

    /// End-to-end collection sanity check: run `SmokeAir::eval` through
    /// `ProverLookupBuilder` over several rows and verify the per-column counts match the
    /// handcrafted `eval` body, that `accumulate_slow` produces exactly `num_rows` entries
    /// per column starting at zero, and that the normalized cyclic recurrence holds.
    #[test]
    fn prover_lookup_builder_collects_into_fractions() {
        const NUM_ROWS: usize = 8;

        let air = SmokeAir;

        // These challenges give nonzero denominators for all three fixture messages.
        let alpha = QuadFelt::new([Felt::new_unchecked(7), Felt::new_unchecked(11)]);
        let beta = QuadFelt::new([Felt::new_unchecked(13), Felt::new_unchecked(17)]);
        // SmokeAir hard-codes `max_message_width = 1` / `num_bus_ids = 1` in its
        // `LookupAir` impl — the trait-method path can't be called directly because
        // `LookupAir<LB>` is generic over `LB` and disambiguation fails at a value call.
        let challenges = Challenges::<QuadFelt>::new(alpha, beta, 1, 1);

        // SmokeAir reads no frame fields. One unread zero column represents the same eight
        // inert rows for the native collector; a zero-width matrix cannot carry a row count.
        let main = RowMajorMatrix::new(vec![Felt::ZERO; NUM_ROWS], 1);
        let fractions = native_lookup::build_lookup_fractions(&air, &main, None, &[], &challenges);

        // Two columns, counts buffer has num_rows * num_cols entries.
        assert_eq!(fractions.num_columns(), 2);
        assert_eq!(fractions.shape(), &SMOKE_SHAPE);
        assert_eq!(fractions.counts().len(), NUM_ROWS * 2);

        // Per-row counts: column 0 pushes 2, column 1 pushes 1. Total = 3 per row.
        for row_counts in fractions.counts().chunks(2) {
            assert_eq!(row_counts, &[2, 1]);
        }
        assert_eq!(fractions.fractions().len(), 3 * NUM_ROWS);

        // Every pushed fraction has a non-zero denominator and the expected
        // multiplicity pattern. Within each row the builder writes col 0 (add 1,
        // remove 1) then col 1 (insert 1 with multiplicity 1), so the flat order is
        // [(+1, d1), (-1, d2), (+1, d3)] repeated NUM_ROWS times.
        for (i, (m, d)) in fractions.fractions().iter().enumerate() {
            assert_ne!(*d, QuadFelt::ZERO);
            let expected_m = match i % 3 {
                0 => Felt::ONE,
                1 => Felt::NEG_ONE,
                _ => Felt::ONE,
            };
            assert_eq!(*m, expected_m);
        }

        let (aux, sigma_prime) = accumulate_slow(&fractions);
        assert_eq!(aux.len(), 2);
        for col_aux in &aux {
            assert_eq!(col_aux.len(), NUM_ROWS);
        }
        assert_eq!(aux[0][0], QuadFelt::ZERO, "accumulator initial must be zero");

        let d1 = SmokeMsg { value: Felt::ONE }.encode(&challenges);
        let d2 = SmokeMsg { value: Felt::new_unchecked(2) }.encode(&challenges);
        let d3 = SmokeMsg { value: Felt::new_unchecked(3) }.encode(&challenges);
        let delta0 = d1.try_inverse().unwrap() - d2.try_inverse().unwrap();
        let delta1 = d3.try_inverse().unwrap();
        let row_total = delta0 + delta1;
        assert_eq!(sigma_prime, row_total);
        // Every row has the same total, so centering by sigma_prime keeps the accumulator zero,
        // including on the last-to-first edge.
        assert!(aux[0].iter().all(|&entry| entry == QuadFelt::ZERO));
        // Column 1 stores the per-row fraction on every row.
        for &entry in &aux[1] {
            assert_eq!(entry, delta1);
        }
    }

    struct RowTaggedAir;

    const ROW_TAGGED_SHAPE: [usize; 1] = [1];

    impl<LB> native_lookup::LookupAir<LB> for RowTaggedAir
    where
        LB: native_lookup::LookupBuilder<F = Felt, Expr = Felt, ExprEF = QuadFelt>,
    {
        fn column_shape(&self) -> &[usize] {
            &ROW_TAGGED_SHAPE
        }

        fn max_message_width(&self) -> usize {
            1
        }

        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &native_lookup::LookupFrame<'_, Felt>, builder: &mut LB) {
            let row_tag = frame.main.current[0];
            let active = frame.main.current[1];
            builder.next_column(
                |col| {
                    col.group(
                        "row_tagged",
                        |group| {
                            group.add(
                                "row_tag",
                                active,
                                || SmokeMsg { value: row_tag },
                                Deg { v: 0, u: 0 },
                            );
                        },
                        Deg { v: 0, u: 0 },
                    );
                },
                Deg { v: 0, u: 0 },
            );
        }
    }

    #[derive(Clone)]
    struct WindowAir<F>(PhantomData<fn() -> F>);

    impl<F: Field> WindowAir<F> {
        fn new() -> Self {
            Self(PhantomData)
        }
    }

    #[derive(Debug)]
    struct WindowMsg<E> {
        value: E,
    }

    impl<E, EE> LookupMessage<E, EE> for WindowMsg<E>
    where
        E: PrimeCharacteristicRing,
        EE: Algebra<E>,
    {
        fn encode(&self, challenges: &Challenges<EE>) -> EE {
            challenges.bus_prefix[0].dup() + challenges.beta_powers[0].dup() * self.value.dup()
        }
    }

    impl<F: Field, LB> crate::lookup::native::LookupAir<LB> for WindowAir<F>
    where
        LB: crate::lookup::native::LookupBuilder<F = F>,
    {
        fn column_shape(&self) -> &[usize] {
            &[1]
        }

        fn max_message_width(&self) -> usize {
            1
        }

        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &crate::lookup::native::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            let value =
                frame.main.current[0].dup() + frame.main.next[0].double() + frame.periodic[0].dup();
            let encoded_value = value.dup();
            // Keep the single original interaction. The two descriptions also
            // exercise cached encoding, a nested batch and a nonunit callback
            // result while borrowing expressions outside the mutable handle.
            let count = builder.next_column(
                |col| {
                    col.group_with_cached_encoding(
                        "window",
                        |group| {
                            group.add(
                                "row",
                                LB::Expr::ONE,
                                || WindowMsg { value: value.dup() },
                                Deg { v: 0, u: 1 },
                            );
                        },
                        |group| {
                            let encoded =
                                group.bus_prefix(0) + group.beta_powers()[0].dup() * encoded_value;
                            group.batch(
                                "window_batch",
                                LB::Expr::ONE,
                                |batch| {
                                    batch.insert_encoded(
                                        "row",
                                        LB::Expr::ONE,
                                        || encoded,
                                        Deg { v: 0, u: 1 },
                                    );
                                },
                                Deg { v: 0, u: 1 },
                            );
                        },
                        Deg { v: 0, u: 1 },
                    );
                    1usize
                },
                Deg { v: 0, u: 1 },
            );
            assert_eq!(count, 1);
        }
    }

    impl<F: Field, LB: LookupBuilder<F = F>> LookupAir<LB> for WindowAir<F> {
        fn column_shape(&self) -> &[usize] {
            &[1]
        }

        fn max_message_width(&self) -> usize {
            1
        }

        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, builder: &mut LB) {
            crate::air::native::migration::eval_lookup(self, builder, 0);
        }
    }

    // This source harness connects the same declaration to the actual private
    // scalar/packed/debug folders via the existing public prove/check helpers.
    impl<F: Field> crate::air::BaseAir<F> for WindowAir<F> {
        fn width(&self) -> usize {
            1
        }

        fn periodic_columns(&self) -> alloc::borrow::Cow<'_, [Vec<F>]> {
            native::LiftedAir::spec(self).periodic_columns
        }
    }

    impl<F: Field, EF: ExtensionField<F>> crate::air::LiftedAir<F, EF> for WindowAir<F> {
        type EvalData<B: Algebra<F>, E: Algebra<B>> = ();

        fn num_randomness(&self) -> usize {
            2
        }

        fn aux_width(&self) -> usize {
            1
        }

        fn num_aux_values(&self) -> usize {
            1
        }

        fn build_aux_trace(
            &self,
            main: &RowMajorMatrix<F>,
            public: &[F],
            statement: &[F],
            challenges: &[EF],
        ) -> (RowMajorMatrix<EF>, Vec<EF>) {
            let auxiliary = <Self as native::ProverAir<EF>>::build_aux_trace(
                self,
                native::AuxTraceInputs {
                    main,
                    preprocessed: None,
                    public_values: public,
                    statement,
                    challenges,
                },
            )
            .expect("valid expression-window auxiliary inputs");
            (auxiliary.columns, auxiliary.exports)
        }

        fn eval<AB: crate::air::LiftedAirBuilder<F = F>>(&self, builder: &mut AB, _data: &()) {
            native::migration::eval_source(self, builder);
        }
    }

    impl<F: Field> native::LiftedAir for WindowAir<F> {
        type F = F;

        fn spec(&self) -> native::AirSpec<'_, F> {
            native::AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: alloc::borrow::Cow::Owned(vec![vec![F::ZERO, F::ONE]]),
            }
        }

        fn eval<AB: native::LiftedAirBuilder<F = F>>(
            &self,
            frame: &native::Frame<'_, AB>,
            inputs: native::Inputs<'_, AB>,
            builder: &mut AB,
        ) {
            crate::lookup::native::eval_lookup(self, frame, inputs, builder);
        }
    }

    impl<F: Field, EF: ExtensionField<F>> native::ProverAir<EF> for WindowAir<F> {
        type Error = crate::lookup::native::LookupError;

        fn build_aux_trace(
            &self,
            inputs: native::AuxTraceInputs<'_, F, EF>,
        ) -> Result<native::AuxTrace<EF>, Self::Error> {
            crate::lookup::native::build_logup_aux_trace(self, inputs)
        }
    }

    #[test]
    fn expression_window_has_real_constraint_witness_and_validation_callers() {
        use crate::{
            air::{LiftedAir, ProverStatement, Statement},
            testing::configs::goldilocks_poseidon2::{
                Felt as TestFelt, QuadFelt as TestQuadFelt, TestMultiAir, prove_and_verify,
                test_challenger,
            },
        };

        let air = WindowAir::<TestFelt>::new();
        let trace = RowMajorMatrix::new(vec![TestFelt::ONE; 8], 1);
        let statement = Statement::new(
            TestMultiAir::new(vec![native::DirectKernel::new(air.clone()).unwrap()]),
            vec![],
            vec![],
        )
        .expect("no public inputs");
        let statement = ProverStatement::new(statement, vec![trace.clone()]).unwrap();
        crate::check_constraints(&statement, None, test_challenger());
        // This existing helper reaches packed prover and scalar OOD folders;
        // constraint_degree reaches the existing non-Copy symbolic builder.
        let _degree =
            <WindowAir<TestFelt> as LiftedAir<TestFelt, TestQuadFelt>>::constraint_degree(&air);
        prove_and_verify(&air, &[], &[trace]);

        #[cfg(feature = "std")]
        crate::lookup::debug::validation::validate(
            &WindowAir::<Felt>::new(),
            crate::lookup::debug::validation::ValidateLayout {
                preprocessed_width: 0,
                trace_width: 1,
                num_public_values: 0,
                num_periodic_columns: 1,
                permutation_width: 1,
                num_permutation_challenges: 2,
                num_permutation_values: 1,
            },
        )
        .expect("canonical and encoded window descriptions agree");
    }

    fn native_window_direct_pilot<F: Field, EF: ExtensionField<F>>() {
        use native::AirKernel;

        let source = WindowAir::<F>::new();
        let expected = native::capture_with::<_, EF>(&source).unwrap();
        assert!(expected.descriptor.analysis().layout().base_indices().is_empty());
        assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[0, 1]);
        let kernel = native::DirectKernel::new(source).unwrap();
        let main = RowMajorMatrix::new(vec![F::ONE; 8], 1);
        let challenges = [EF::from_u32(7), EF::from_u32(13)];
        let auxiliary = native::ProverAir::build_aux_trace(
            &kernel,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        assert_eq!(auxiliary.columns.width(), 1);
        assert_eq!(auxiliary.columns.height(), 8);
        // Independent fraction arithmetic for the constant trace: current+2*next+periodic
        // alternates between3 and4, so its normalized export is the two-fraction mean.
        let encoding = Challenges::new(challenges[0], challenges[1], 1, 1);
        let fraction = |value| {
            (encoding.bus_prefix[0] + encoding.beta_powers[0] * F::from_u32(value)).inverse()
        };
        let mean = (fraction(3) + fraction(4)) * EF::from_u32(2).inverse();
        assert_eq!(auxiliary.exports, vec![mean]);
        assert!(native::LiftedAir::build_preprocessed_trace(&kernel).is_none());

        let observed = native::capture_from_spec::<F, EF>(
            kernel.descriptor().spec().as_borrowed(),
            |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
        )
        .unwrap();
        assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
        assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
    }

    #[test]
    fn native_window_sources_keep_both_actual_field_routes() {
        native_window_direct_pilot::<Felt, QuadFelt>();
        native_window_direct_pilot::<
            crate::testing::configs::Felt,
            crate::testing::configs::QuadFelt,
        >();

        #[cfg(feature = "std")]
        {
            // The validator intentionally supports the production Felt/QuadFelt pair only.
            let source = WindowAir::<Felt>::new();
            let spec = native::LiftedAir::spec(&source);
            crate::lookup::native::validate_native(&source, &spec)
                .expect("native canonical and encoded window descriptions agree");
        }
    }

    #[test]
    fn fraction_chunk_preserves_row_windows_and_periodic_offsets() {
        let period = 2 * crate::lookup::aux_builder::ACCUMULATE_ROWS_PER_CHUNK;
        let num_rows = period + 1;
        let main = RowMajorMatrix::new(
            (0..num_rows).map(|row| Felt::from_usize(3 * row + 1)).collect(),
            1,
        );
        let periodic = vec![(0..period).map(Felt::from_usize).collect()];
        let challenges = Challenges::new(QuadFelt::from_u32(7), QuadFelt::from_u32(13), 1, 1);
        // Start inside the trace and include the last-to-first edge.
        let rows = period / 2 - 1..num_rows;
        let air = WindowAir::<Felt>::new();
        let shape = <WindowAir<Felt> as native_lookup::LookupAir<
            ProverLookupBuilder<'_, Felt, QuadFelt>,
        >>::column_shape(&air);
        let actual = build_lookup_fraction_chunk_with(
            &main,
            None,
            &periodic,
            &challenges,
            shape,
            rows.clone(),
            |frame, builder| native_lookup::LookupAir::eval(&air, frame, builder),
        );
        let expected: Vec<_> = rows
            .map(|row| {
                let value = main.values[row]
                    + main.values[(row + 1) % num_rows].double()
                    + Felt::from_usize(row % period);
                (Felt::ONE, challenges.bus_prefix[0] + value)
            })
            .collect();
        assert_eq!(actual.counts(), vec![1; expected.len()]);
        assert_eq!(actual.fractions(), expected);
    }

    #[test]
    fn multi_chunk_collection_preserves_row_order() {
        const NUM_ROWS: usize = 2 * crate::lookup::aux_builder::ACCUMULATE_ROWS_PER_CHUNK + 1;

        let mut trace_values = Vec::with_capacity(2 * NUM_ROWS);
        let mut expected_counts = Vec::with_capacity(NUM_ROWS);
        let mut expected_tags = Vec::with_capacity(NUM_ROWS);
        for row in 0..NUM_ROWS {
            let row_tag = Felt::from_usize(row + 1);
            let active = row % 3 != 0;
            trace_values.extend([row_tag, if active { Felt::ONE } else { Felt::ZERO }]);
            expected_counts.push(usize::from(active));
            if active {
                expected_tags.push(row_tag);
            }
        }
        let trace = RowMajorMatrix::new(trace_values, 2);
        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::new([Felt::new_unchecked(7), Felt::new_unchecked(11)]),
            QuadFelt::new([Felt::new_unchecked(13), Felt::new_unchecked(17)]),
            1,
            1,
        );

        let fractions =
            native_lookup::build_lookup_fractions(&RowTaggedAir, &trace, None, &[], &challenges);

        assert_eq!(fractions.counts(), expected_counts);
        assert_eq!(fractions.fractions().len(), expected_tags.len());
        for (&row_tag, &(multiplicity, denominator)) in
            expected_tags.iter().zip(fractions.fractions())
        {
            assert_eq!(multiplicity, Felt::ONE);
            assert_eq!(denominator, SmokeMsg { value: row_tag }.encode(&challenges));
        }
    }
}
