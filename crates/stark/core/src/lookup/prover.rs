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
use thiserror::Error;

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupFractions,
    LookupFrame, LookupGroup, LookupMessage,
    aux_builder::{
        ACCUMULATE_ROWS_PER_CHUNK, accumulate_fraction_chunk, write_centered_accumulator,
    },
};
use crate::air::{AuxTrace, AuxTraceInputs, LiftedAir, SpecError};

// PROVER LOOKUP BUILDER
// ================================================================================================

/// [`LookupBuilder`] collecting interactions from one concrete row.
///
/// All expression-like associated types collapse to concrete field values on this path.
pub struct ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
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
    /// Create fraction-collection state for one row from the declared column shape.
    ///
    /// Row expressions are passed separately to the declaration in a LookupFrame. Challenges
    /// and output storage are shared with the surrounding collector, without copying rows.
    pub fn new(
        challenges: &'a Challenges<EF>,
        shape: &[usize],
        fractions: &'a mut LookupFractions<F, EF>,
    ) -> Self {
        let num_columns = shape.len();
        debug_assert_eq!(fractions.num_columns(), num_columns, "fraction-buffer width mismatch");
        Self {
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

/// Shared chunk scheduling and ordered concatenation, independent of declaration syntax.
fn collect_lookup_chunks<F, EF>(
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

/// Read cyclic row pairs and periodic values for native lookup collection.
fn build_lookup_fraction_chunk_with<F, EF>(
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    periodic_columns: &[Vec<F>],
    challenges: &Challenges<EF>,
    shape: &[usize],
    rows: Range<usize>,
    eval: impl Fn(&super::LookupFrame<'_, F>, &mut ProverLookupBuilder<'_, F, EF>),
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
        let (preprocessed_current, preprocessed_next) = if preprocessed_width == 0 {
            (empty_row, empty_row)
        } else {
            let curr = &preprocessed_flat[r * preprocessed_width..(r + 1) * preprocessed_width];
            let next = &preprocessed_flat
                [nxt_idx * preprocessed_width..(nxt_idx + 1) * preprocessed_width];
            (curr, next)
        };
        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }
        let frame = super::LookupFrame {
            main: crate::air::Rows { current: curr, next },
            preprocessed: crate::air::Rows {
                current: preprocessed_current,
                next: preprocessed_next,
            },
            periodic: &periodic_row,
        };
        let mut lb = ProverLookupBuilder::new(challenges, shape, &mut chunk);
        eval(&frame, &mut lb);
        lb.finish();
    }
    chunk
}

impl<F: Field, EF: ExtensionField<F>> LookupBuilder for ProverLookupBuilder<'_, F, EF> {
    type F = F;
    type Expr = F;
    type ExprEF = EF;
    type Column<'c>
        = ProverColumn<'c, F, EF>
    where
        Self: 'c;

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

// LOOKUP WITNESS CONSTRUCTION
// ================================================================================================

/// Recoverable source metadata and witness-input shape failures.
/// Lookup denominators and the normalization divisor are assumed nonzero.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LookupError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error("main trace width {actual} differs from declared width {expected}")]
    MainWidth { expected: usize, actual: usize },
    #[error("main trace must have positive, complete rows")]
    MainShape,
    #[error("preprocessed trace presence or shape differs from its declaration and main height")]
    PreprocessedShape,
    #[error("public input count {actual} differs from declared count {expected}")]
    PublicValues { expected: usize, actual: usize },
    #[error("challenge count {actual} differs from declared count {expected}, or is below two")]
    Challenges { expected: usize, actual: usize },
    #[error("a lookup must declare columns, message slots, bus IDs and at least one export")]
    LookupShape,
    #[error("auxiliary width {width} cannot hold {columns} lookup columns")]
    AuxiliaryWidth { width: usize, columns: usize },
    #[error("lookup witness storage overflows host indexing")]
    Overflow,
}

/// Collect a complete trace through the native declaration surface.
///
/// This low-level collector retains the existing fraction layout and trusted shape contracts.
/// It does no inversion. Witness construction should normally use [`build_logup_aux_trace`],
/// which validates caller dimensions before constructing the witness.
pub fn build_lookup_fractions<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: Option<&RowMajorMatrix<F>>,
    periodic: &[Vec<F>],
    challenges: &Challenges<EF>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    A: Sync,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    collect_lookup_chunks(air.column_shape(), main.height(), |rows| {
        collect_chunk(air, main, preprocessed, periodic, challenges, rows)
    })
}

fn collect_chunk<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: Option<&RowMajorMatrix<F>>,
    periodic: &[Vec<F>],
    challenges: &Challenges<EF>,
    rows: Range<usize>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    build_lookup_fraction_chunk_with(
        main,
        preprocessed,
        periodic,
        challenges,
        air.column_shape(),
        rows,
        |frame: &LookupFrame<'_, F>, builder| air.eval(frame, builder),
    )
}

/// Build the normalized cyclic LogUp witness without rebuilding any fixed matrices.
///
/// Columns occupy the declared lookup prefix. The returned matrix has the source's full auxiliary
/// width with any suffix zero-initialized; the source witness fills its own additional registers.
/// Exactly one export, `sigma / height`, is initialized here. A source with further exports must
/// append them in its own declared order before returning its complete `ProverAir` result.
///
/// Chunk collection, inversion and centering share the prover callback arithmetic.
/// All active lookup denominators and the trace-length divisor are assumed nonzero.
pub fn build_logup_aux_trace<A, F, EF>(
    air: &A,
    inputs: AuxTraceInputs<'_, F, EF>,
) -> Result<AuxTrace<EF>, LookupError>
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F = F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let _span = tracing::trace_span!(target: "miden::vm::prove", "build_aux_trace_logup").entered();

    let spec = air.spec();
    spec.validate()?;
    if inputs.main.width() != spec.main_width {
        return Err(LookupError::MainWidth {
            expected: spec.main_width,
            actual: inputs.main.width(),
        });
    }
    if !inputs.main.values.len().is_multiple_of(spec.main_width) || inputs.main.values.is_empty() {
        return Err(LookupError::MainShape);
    }
    let height = inputs.main.height();
    match (spec.preprocessed, inputs.preprocessed) {
        (None, None) => {},
        (Some(shape), Some(matrix))
            if matrix.width() == shape.width
                && matrix.values.len() == shape.width * (1usize << shape.log_height)
                && matrix.height() == height => {},
        _ => return Err(LookupError::PreprocessedShape),
    }
    if inputs.public_values.len() != spec.num_public_values {
        return Err(LookupError::PublicValues {
            expected: spec.num_public_values,
            actual: inputs.public_values.len(),
        });
    }
    if inputs.challenges.len() != spec.num_challenges || inputs.challenges.len() < 2 {
        return Err(LookupError::Challenges {
            expected: spec.num_challenges,
            actual: inputs.challenges.len(),
        });
    }
    let shape = air.column_shape();
    let columns = shape.len();
    if columns == 0
        || air.max_message_width() == 0
        || air.num_bus_ids() == 0
        || air.num_bus_ids() > u32::MAX as usize
        || spec.num_exports == 0
    {
        return Err(LookupError::LookupShape);
    }
    if spec.aux_width < columns {
        return Err(LookupError::AuxiliaryWidth { width: spec.aux_width, columns });
    }
    // Collection reserves height*sum(shape) fractions and height*columns count slots.
    shape
        .iter()
        .try_fold(0usize, |sum, &count| sum.checked_add(count))
        .and_then(|sum| sum.checked_mul(height))
        .ok_or(LookupError::Overflow)?;
    let cells = height.checked_mul(spec.aux_width).ok_or(LookupError::Overflow)?;
    let rows_per_chunk = ACCUMULATE_ROWS_PER_CHUNK.min(height);
    let challenges = Challenges::new(
        inputs.challenges[0],
        inputs.challenges[1],
        air.max_message_width(),
        air.num_bus_ids(),
    );
    let mut output = EF::zero_vec(cells);
    let mut row_totals = EF::zero_vec(height);

    use miden_crypto::parallel::*;
    output
        .par_chunks_mut(rows_per_chunk * spec.aux_width)
        .zip(row_totals.par_chunks_mut(rows_per_chunk))
        .enumerate()
        .for_each(|(chunk_index, (out, totals))| {
            let row_lo = chunk_index * rows_per_chunk;
            let chunk = collect_chunk(
                air,
                inputs.main,
                inputs.preprocessed,
                &spec.periodic_columns,
                &challenges,
                row_lo..row_lo + totals.len(),
            );
            accumulate_fraction_chunk(
                chunk.fractions(),
                chunk.counts(),
                columns,
                spec.aux_width,
                out,
                totals,
            );
        });
    let mean = write_centered_accumulator(&row_totals, &mut output, spec.aux_width);
    Ok(AuxTrace {
        columns: RowMajorMatrix::new(output, spec.aux_width),
        exports: vec![mean],
    })
}

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
        air, lookup,
        lookup::{Deg, accumulate_slow, message::LookupMessage},
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

    impl<LB> lookup::LookupAir<LB> for SmokeAir
    where
        LB: lookup::LookupBuilder<F = Felt, Expr = Felt, ExprEF = QuadFelt>,
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
        fn eval(&self, _frame: &lookup::LookupFrame<'_, Felt>, builder: &mut LB) {
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
        let fractions = lookup::build_lookup_fractions(&air, &main, None, &[], &challenges);

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

    impl<LB> lookup::LookupAir<LB> for RowTaggedAir
    where
        LB: lookup::LookupBuilder<F = Felt, Expr = Felt, ExprEF = QuadFelt>,
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

        fn eval(&self, frame: &lookup::LookupFrame<'_, Felt>, builder: &mut LB) {
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

    impl<F: Field, LB> crate::lookup::LookupAir<LB> for WindowAir<F>
    where
        LB: crate::lookup::LookupBuilder<F = F>,
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

        fn eval(&self, frame: &crate::lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
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

    impl<F: Field> air::LiftedAir for WindowAir<F> {
        type F = F;

        fn spec(&self) -> air::AirSpec<'_, F> {
            air::AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: alloc::borrow::Cow::Owned(vec![vec![F::ZERO, F::ONE]]),
            }
        }

        fn eval<AB: air::LiftedAirBuilder<F = F>>(
            &self,
            frame: &air::Frame<'_, AB>,
            inputs: air::Inputs<'_, AB>,
            builder: &mut AB,
        ) {
            crate::lookup::eval_lookup(self, frame, inputs, builder);
        }
    }

    impl<F: Field, EF: ExtensionField<F>> air::ProverAir<EF> for WindowAir<F> {
        type Error = crate::lookup::LookupError;

        fn build_aux_trace(
            &self,
            inputs: air::AuxTraceInputs<'_, F, EF>,
        ) -> Result<air::AuxTrace<EF>, Self::Error> {
            crate::lookup::build_logup_aux_trace(self, inputs)
        }
    }

    #[test]
    fn expression_window_roundtrips_through_proof_folders_and_checker() {
        use crate::{
            air::{ProverStatement, Statement},
            testing::configs::goldilocks_poseidon2::{
                Felt as TestFelt, TestMultiAir, prove_and_verify_statement, test_challenger,
            },
        };

        let kernel = air::DirectKernel::new(WindowAir::<TestFelt>::new()).unwrap();
        let trace = RowMajorMatrix::new(vec![TestFelt::ONE; 8], 1);
        let statement = Statement::new(TestMultiAir::new(vec![kernel]), vec![], vec![]).unwrap();
        let prover = ProverStatement::new(statement, vec![trace]).unwrap();
        crate::check_constraints(&prover, None, test_challenger());
        prove_and_verify_statement(prover);

        #[cfg(feature = "std")]
        {
            let source = WindowAir::<Felt>::new();
            crate::lookup::validate_native(&source, &air::LiftedAir::spec(&source)).unwrap();
        }
    }

    fn check_window_witness<F: Field, EF: ExtensionField<F>>() {
        let source = WindowAir::<F>::new();
        let main = RowMajorMatrix::new(vec![F::ONE; 8], 1);
        let challenges = [EF::from_u32(7), EF::from_u32(13)];
        let auxiliary = build_logup_aux_trace(
            &source,
            AuxTraceInputs {
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
        // On a constant trace, current + 2 * next + periodic alternates between 3 and 4.
        let encoding = Challenges::new(challenges[0], challenges[1], 1, 1);
        let fraction = |value| {
            (encoding.bus_prefix[0] + encoding.beta_powers[0] * F::from_u32(value)).inverse()
        };
        let mean = (fraction(3) + fraction(4)) * EF::from_u32(2).inverse();
        assert_eq!(auxiliary.exports, vec![mean]);
    }

    #[test]
    fn window_witness_matches_the_fraction_mean_in_both_runner_fields() {
        check_window_witness::<Felt, QuadFelt>();
        check_window_witness::<crate::testing::configs::Felt, crate::testing::configs::QuadFelt>();
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
        let shape = <WindowAir<Felt> as lookup::LookupAir<
            ProverLookupBuilder<'_, Felt, QuadFelt>,
        >>::column_shape(&air);
        let actual = build_lookup_fraction_chunk_with(
            &main,
            None,
            &periodic,
            &challenges,
            shape,
            rows.clone(),
            |frame, builder| lookup::LookupAir::eval(&air, frame, builder),
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
            lookup::build_lookup_fractions(&RowTaggedAir, &trace, None, &[], &challenges);

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

#[cfg(test)]
mod witness_tests {
    use alloc::borrow::Cow;

    use miden_core::{Felt, field::QuadFelt};
    use p3_field::{Algebra, Dup, PrimeCharacteristicRing};

    use super::*;
    use crate::{
        air::{AirSpec, Frame, Inputs, LiftedAirBuilder},
        lookup::{Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage},
    };

    #[derive(Debug)]
    struct RowMessage<E>(E);

    impl<E: PrimeCharacteristicRing, EE: Algebra<E>> LookupMessage<E, EE> for RowMessage<E> {
        fn encode(&self, challenges: &Challenges<EE>) -> EE {
            challenges.bus_prefix[0].dup() + challenges.beta_powers[0].dup() * self.0.dup()
        }
    }

    struct Fixture {
        active: bool,
        aux_width: usize,
        periodic: Vec<Vec<Felt>>,
    }

    impl Fixture {
        fn new(active: bool) -> Self {
            Self {
                active,
                aux_width: 3,
                periodic: vec![vec![Felt::ZERO; 2]],
            }
        }
    }

    impl<LB: super::super::LookupBuilder<F = Felt>> LookupAir<LB> for Fixture {
        fn column_shape(&self) -> &[usize] {
            &[1, 2]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            let value = frame.main.current[0].dup() + frame.periodic[0].dup();
            let flag = if self.active { LB::Expr::ONE } else { LB::Expr::ZERO };
            let single = if self.active {
                Deg { v: 0, u: 1 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |column| {
                    column.group(
                        "one",
                        |group| {
                            group.add("row", flag.dup(), || RowMessage(value.dup()), single);
                        },
                        single,
                    );
                },
                single,
            );
            let batch = if self.active {
                Deg { v: 1, u: 2 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |column| {
                    column.group(
                        "two",
                        |group| {
                            group.batch(
                                "pair",
                                flag,
                                |batch| {
                                    batch.add(
                                        "first",
                                        RowMessage(value.dup() + LB::Expr::ONE),
                                        Deg { v: 0, u: 1 },
                                    );
                                    batch.add(
                                        "second",
                                        RowMessage(value + LB::Expr::TWO),
                                        Deg { v: 0, u: 1 },
                                    );
                                },
                                batch,
                            );
                        },
                        batch,
                    );
                },
                batch,
            );
        }
    }

    impl LiftedAir for Fixture {
        type F = Felt;

        fn spec(&self) -> AirSpec<'_, Felt> {
            AirSpec {
                main_width: 1,
                aux_width: self.aux_width,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&self.periodic),
            }
        }

        fn eval<B: LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &Frame<'_, B>,
            inputs: Inputs<'_, B>,
            sink: &mut B,
        ) {
            super::super::eval_lookup(self, frame, inputs, sink);
        }
    }

    fn inputs<'a>(
        main: &'a RowMajorMatrix<Felt>,
        challenges: &'a [QuadFelt],
    ) -> AuxTraceInputs<'a, Felt, QuadFelt> {
        AuxTraceInputs {
            main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges,
        }
    }

    #[test]
    fn native_witness_matches_independent_slow_accumulation_and_preserves_suffix() {
        let source = Fixture::new(true);
        let main = RowMajorMatrix::new((0..1025).map(Felt::from_usize).collect(), 1);
        let values = [QuadFelt::from_u64(7), QuadFelt::ZERO];
        let witness = build_logup_aux_trace(&source, inputs(&main, &values)).unwrap();
        let challenges = Challenges::new(values[0], values[1], 1, 1);
        let fractions = build_lookup_fractions(&source, &main, None, &source.periodic, &challenges);
        let (expected, mean) = crate::lookup::accumulate_slow(&fractions);
        assert_eq!(witness.exports, vec![mean]);
        assert_eq!(witness.columns.width(), 3);
        assert_eq!(witness.columns.height(), main.height());
        let (rows, remainder) = witness.columns.values.as_chunks::<3>();
        assert!(remainder.is_empty());
        for ((&accumulator, &fraction), row) in expected[0].iter().zip(&expected[1]).zip(rows) {
            assert_eq!(row[0], accumulator);
            assert_eq!(row[1], fraction);
            assert_eq!(row[2], QuadFelt::ZERO);
        }
        let _captured = crate::air::capture(&source).unwrap();
    }

    #[test]
    fn inactive_interactions_and_invalid_trace_shapes() {
        let source = Fixture::new(false);
        let main = RowMajorMatrix::new(vec![Felt::ONE; 4], 1);
        let values = [QuadFelt::from_u64(7), QuadFelt::ZERO];
        let witness = build_logup_aux_trace(&source, inputs(&main, &values)).unwrap();
        assert!(witness.columns.values.iter().all(Field::is_zero));
        assert_eq!(witness.exports, vec![QuadFelt::ZERO]);
        let undersized = Fixture { aux_width: 1, ..Fixture::new(false) };
        assert_eq!(
            build_logup_aux_trace(&undersized, inputs(&main, &values)).unwrap_err(),
            LookupError::AuxiliaryWidth { width: 1, columns: 2 }
        );
        let empty = RowMajorMatrix::new(vec![], 1);
        assert_eq!(
            build_logup_aux_trace(&source, inputs(&empty, &values)).unwrap_err(),
            LookupError::MainShape
        );
    }
}
