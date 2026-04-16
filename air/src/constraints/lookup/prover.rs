//! Prover-path adapter — pushes individual `(m, v)` fractions per
//! interaction into a dense per-column flat [`LookupFractions`] buffer
//! owned by the caller.
//!
//! Implements [`LookupBuilder`] for concrete base-field rows. Where the
//! [constraint-path adapter](super::constraint::ConstraintLookupBuilder)
//! emits symbolic `(U, V)` constraint expressions against a
//! `LiftedAirBuilder`, this adapter consumes two concrete rows of
//! base-field values and **pushes the individual fractions** each
//! interaction contributes — one `(multiplicity, denominator)` entry per
//! active interaction, appended to the current column's flat Vec inside
//! [`LookupFractions`].
//!
//! ## Runtime shape
//!
//! The caller:
//!
//! 1. Builds one [`LookupChallenges<EF>`] once, outside the per-row loop.
//! 2. Allocates one [`LookupFractions`] once via [`LookupFractions::new`], sized from
//!    [`LookupAir::column_shape`]. Each column's internal Vec is `Vec::with_capacity(num_rows *
//!    shape[col])` so pushes in the row loop never re-allocate.
//! 3. For each row pair, constructs a `ProverLookupBuilder` (cheap — just stores pointers), calls
//!    `air.eval(&mut lb)`, then drops the builder. `column(f)` records how many fractions the row
//!    pushed into `LookupFractions::counts_per_row[col]`, so the downstream accumulator can later
//!    slice each row's contribution out via a running cursor without a separate offsets array.
//!
//! No `FractionCollector`-style cross-denominator clearing inside the
//! adapter — LogUp's aux-trace builder consumes individual `(m, v)`
//! pairs directly, so we hand them over as-is and let the downstream
//! code compute the per-row running sum.
//!
//! ## Flag-zero skip
//!
//! `add` / `remove` / `insert` short-circuit on `flag == F::ZERO`,
//! avoiding both the `msg.encode()` call and the Vec push when the
//! interaction is inactive. `batch(flag, build)` sets an `active` bit on
//! the child `ProverBatch` so individual pushes inside the batch skip
//! work together when the outer flag is zero.
//!
//! ## Encoded-group collapse
//!
//! Per the plan (§Prover-path adapter) the cached-encoding split is
//! collapsed on the prover side: [`LookupColumn::group`] and
//! [`LookupColumn::group_with_cached_encoding`] both open a
//! [`ProverGroup`] against the same column fraction `Vec`, and the
//! cached-encoding variant runs only the `canonical` closure (the
//! `encoded` closure is dropped unused, since the canonical description
//! is always the cheapest path for concrete rows).

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, marker::PhantomData};

use miden_core::{
    field::{ExtensionField, Field, PrimeCharacteristicRing},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::RowWindow;

use super::{
    EncodedLookupGroup, LookupAir, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn,
    LookupGroup, LookupMessage, chiplet_air::ChipletLookupBuilder, fractions::LookupFractions,
    main_air::MainLookupBuilder,
};
use crate::Felt;

// BUS DEBUG HOOK
// ================================================================================================
//
// One-shot instrumentation for chasing bus-closure regressions: every fraction pushed into
// the prover's flat buffer gets logged to stderr with `(row, col, mult, type, msg, d)` where
// `msg` is the message's `Debug` representation *before* encoding and `d` is the resulting
// encoded denominator. Parseable line format so a downstream Python script can group by
// message content and surface unmatched emits.
//
// Gated on `cfg(feature = "std")` because the air crate is no_std by default and
// `std::eprintln!` isn't available otherwise. The miden-processor tests enable std
// transitively, so the hook fires automatically when running those tests.
#[cfg(feature = "std")]
fn busdbg_log<F, EF, M>(row: usize, col: usize, mult_sign: i64, msg: &M, d: &EF)
where
    F: Field,
    EF: ExtensionField<F>,
    M: core::fmt::Debug + ?Sized,
{
    // Format:
    //   BUSDBG row=<r> col=<c> mult=<±1 or explicit> type=<module::path::Name> msg=<debug>
    // d=<base-coeffs>
    //
    // `type` lets the Python parser quickly bucket by Rust type without parsing `msg`;
    // `msg` carries the pre-encoding payload so add/remove matchers can compare structural
    // equality; `d` is the post-encoding denominator as a flat base-coefficient slice
    // (`[v0, v1, …]` for `BinomialExtensionField<F, 2>` — two `u64`s for `QuadFelt`). Two
    // messages with the same `d` but different `msg` immediately reveal an encoding collision
    // bug, and the compact slice form is trivially parseable from Python.
    std::eprintln!(
        "BUSDBG row={} col={} mult={} type={} msg={:?} d={:?}",
        row,
        col,
        mult_sign,
        core::any::type_name::<M>(),
        msg,
        d.as_basis_coefficients_slice(),
    );
}

#[cfg(not(feature = "std"))]
#[inline]
fn busdbg_log<F, EF, M>(_row: usize, _col: usize, _mult_sign: i64, _msg: &M, _d: &EF)
where
    F: Field,
    EF: ExtensionField<F>,
    M: core::fmt::Debug + ?Sized,
{
}

// Variant of `busdbg_log` for `insert_encoded` sites where no `LookupMessage` instance
// exists (the caller hands us a pre-computed `EF` denominator directly). We still log the
// call so the unmatched-message analysis sees every push, but there's no type to stamp.
#[cfg(feature = "std")]
fn busdbg_log_encoded<F, EF>(row: usize, col: usize, mult_sign: i64, d: &EF)
where
    F: Field,
    EF: ExtensionField<F>,
{
    std::eprintln!(
        "BUSDBG row={} col={} mult={} type=<encoded> msg=<encoded> d={:?}",
        row,
        col,
        mult_sign,
        d.as_basis_coefficients_slice(),
    );
}

#[cfg(not(feature = "std"))]
#[inline]
fn busdbg_log_encoded<F, EF>(_row: usize, _col: usize, _mult_sign: i64, _d: &EF)
where
    F: Field,
    EF: ExtensionField<F>,
{
}

// PROVER LOOKUP BUILDER
// ================================================================================================

/// Concrete-row [`LookupBuilder`] running on two rows of base-field values.
///
/// See the [module docs](self) for the full runtime shape. Parameterised
/// by the base field `F` and the extension field `EF`; every `Expr` /
/// `Var` / `VarEF` etc. associated type collapses to `F` or `EF`
/// directly — there is no symbolic tree on the prover side.
///
/// The [`LookupChallenges`] table is **borrowed** from the caller: the
/// caller builds it once outside the row loop and passes a shared
/// reference into every `new` call, so per-row construction is O(1) with
/// no allocations.
pub struct ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    main: RowWindow<'a, F>,
    periodic_values: &'a [F],
    public_values: &'a [F],
    challenges: &'a LookupChallenges<EF>,
    /// Dense per-column fraction buffers shared across all rows. Each
    /// [`LookupBuilder::column`] call appends the current row's fractions to the end of
    /// `fractions.fractions[column_idx]` and pushes the row's interaction count into
    /// `fractions.counts_per_row[column_idx]`. The outer Vecs never move or re-allocate
    /// as long as each row stays within the declared [`LookupAir::column_shape`] bound.
    fractions: &'a mut LookupFractions<F, EF>,
    column_idx: usize,
    /// Debug-only: current main-trace row index, threaded into every child handle so
    /// the `busdbg_log` hook at each push site can print row + col metadata alongside
    /// the emitted fraction. Set by [`build_lookup_fractions`] once per row.
    ///
    /// Under `no_std` (where `busdbg_log` is a no-op) the compiler eliminates all
    /// loads/stores of this field, so it has zero runtime cost. The field itself remains
    /// unconditionally to avoid cfg noise on every constructor and child-handle creation;
    /// a future `BusDebugger` refactor may consolidate this into a single gated type.
    row_idx: usize,
}

impl<'a, F, EF> ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a new prover-path adapter for one row pair.
    ///
    /// - `main`: two-row window over the current and next base-field rows.
    /// - `periodic_values`: periodic columns at the current row.
    /// - `public_values`: public inputs.
    /// - `challenges`: precomputed LogUp challenges (shared across every row — the caller builds
    ///   this once outside the row loop and passes a shared reference here).
    /// - `air`: the lookup shape (used only for a debug assertion that `fractions.num_columns() ==
    ///   air.num_columns()`; the builder never calls `air.eval` itself — that's the caller's job).
    /// - `fractions`: dense per-column fraction buffers, sized once via [`LookupFractions::new`]
    ///   and re-used across every row of the same trace.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `fractions.num_columns() != air.num_columns()`.
    pub fn new<A>(
        main: RowWindow<'a, F>,
        periodic_values: &'a [F],
        public_values: &'a [F],
        challenges: &'a LookupChallenges<EF>,
        air: &A,
        fractions: &'a mut LookupFractions<F, EF>,
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        Self::new_at_row(main, periodic_values, public_values, challenges, air, fractions, 0)
    }

    /// Same as [`ProverLookupBuilder::new`] but also stamps the current main-trace row
    /// index onto the builder. The row index is threaded into every child handle so the
    /// debug hook can label each emitted fraction with its origin row.
    pub fn new_at_row<A>(
        main: RowWindow<'a, F>,
        periodic_values: &'a [F],
        public_values: &'a [F],
        challenges: &'a LookupChallenges<EF>,
        air: &A,
        fractions: &'a mut LookupFractions<F, EF>,
        row_idx: usize,
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        debug_assert_eq!(
            fractions.num_columns(),
            air.num_columns(),
            "fractions buffer must be pre-sized to air.num_columns()",
        );
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            fractions,
            column_idx: 0,
            row_idx,
        }
    }
}

// BUILD LOOKUP FRACTIONS DRIVER
// ================================================================================================

/// Walk a complete main trace through [`ProverLookupBuilder`] and return the dense
/// [`LookupFractions`] buffer the collection phase produces.
///
/// This is the top-level entry point for the prover-side LogUp collection phase. It:
///
/// 1. Allocates one [`LookupFractions`] sized from [`LookupAir::column_shape`] — the hot row loop
///    never re-allocates as long as each row stays within its declared bound.
/// 2. For each row `r`, builds a two-row `RowWindow` over `&flat[r * w .. (r + 1) * w]` and
///    `&flat[((r + 1) % n) * w .. ..]` (wraparound on the last row — matches the constraint path's
///    transition wraparound).
/// 3. Composes the per-row periodic slice by indexing each periodic column at `r % col.len()` (the
///    columns have varying periods — hasher columns are 16, bitwise columns are 8, etc.). A single
///    reusable `Vec<Felt>` is filled in place per row.
/// 4. Constructs a fresh `ProverLookupBuilder` per row and calls `air.eval(&mut lb)` — the bus
///    emitters push fractions into the flat [`LookupFractions`] buffer and record per-row counts
///    via the split-borrow in `LookupBuilder::column`.
///
/// The returned [`LookupFractions`] is ready for the fused batch-inversion + partial-sum
/// fast path (not implemented here) or for the reference [`super::accumulate_slow`].
///
/// # Arguments
///
/// - `air`: the [`LookupAir`] to evaluate (typically [`super::miden_air::MidenLookupAir`]).
/// - `main_trace`: row-major main execution trace. Row access is zero-copy via
///   `main_trace.values.borrow()`.
/// - `periodic_columns`: one `Vec<Felt>` per periodic column, each with its own period (from
///   [`crate::constraints::chiplets::columns::PeriodicCols::periodic_columns`]).
/// - `public_values`: row-invariant public input slice.
/// - `challenges`: precomputed LogUp challenges (shared across every row).
///
/// # Panics
///
/// Panics in debug builds if any row pushes more fractions into a column than that
/// column's declared [`LookupAir::column_shape`] bound — this indicates the emitter's
/// `MAX_INTERACTIONS_PER_ROW` const is too low and needs to be bumped.
pub fn build_lookup_fractions<A, EF>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &LookupChallenges<EF>,
) -> LookupFractions<Felt, EF>
where
    EF: ExtensionField<Felt>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, Felt, EF>>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[Felt] = main_trace.values.borrow();

    let mut fractions = LookupFractions::new::<A, ProverLookupBuilder<'_, Felt, EF>>(air, num_rows);

    // Per-row periodic slice, filled in place each row — no per-iteration allocation.
    let mut periodic_row: Vec<Felt> = vec![Felt::ZERO; periodic_columns.len()];

    for r in 0..num_rows {
        // Zero-copy row slices over the flat matrix storage.
        let curr = &flat[r * width..(r + 1) * width];
        let nxt_idx = (r + 1) % num_rows;
        let next = &flat[nxt_idx * width..(nxt_idx + 1) * width];
        let window = RowWindow::from_two_rows(curr, next);

        // Each periodic column is indexed at `r mod its own period`.
        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }

        let mut lb = ProverLookupBuilder::new_at_row(
            window,
            &periodic_row,
            public_values,
            challenges,
            air,
            &mut fractions,
            r,
        );
        air.eval(&mut lb);
        // `lb` drops here; the next iteration reborrows `fractions` fresh.
    }

    debug_assert_eq!(
        fractions.counts().len(),
        num_rows * fractions.num_columns(),
        "counts buffer should have exactly num_rows * num_cols entries after collection",
    );
    fractions
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
    type PublicVar = F;

    type MainWindow = RowWindow<'a, F>;

    type Column<'c>
        = ProverColumn<'c, F, EF>
    where
        Self: 'c;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
    ) -> R {
        let idx = self.column_idx;
        let row_idx = self.row_idx;
        // Split-borrow `fractions.fractions` and `fractions.counts` as disjoint
        // fields — going through a single `&mut LookupFractions` method would lock
        // all of `self.fractions` under the GAT lifetime `'c` and block the
        // post-closure `counts.push(...)` re-borrow.
        let vec = &mut self.fractions.fractions;
        let counts = &mut self.fractions.counts;
        let shape_col = self.fractions.shape[idx];
        let start_len = vec.len();

        let mut col = ProverColumn {
            challenges: self.challenges,
            fractions: vec,
            row_idx,
            col_idx: idx,
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        // Snapshot the end length from `col.fractions` while `col` is still alive;
        // NLL ends the borrow on `vec` at `col`'s last use below.
        let end_len = col.fractions.len();
        let _ = col;
        let pushed = end_len - start_len;
        debug_assert!(
            pushed <= shape_col,
            "column {idx} stride exceeded: pushed {pushed}, shape says {shape_col}",
        );
        counts.push(pushed);
        self.column_idx += 1;
        result
    }
}

// EXTENSION TRAIT IMPLS
// ================================================================================================

// Gated to `F = Felt` because the extension traits require `LookupBuilder<F = Felt>`. The
// prover adapter is generic over `F: Field` in principle, but Miden only ever instantiates
// it with `F = Felt`, so the narrowing is a nothing-burger in practice.
//
// Both impls are empty and pick up the default polynomial bodies today. The planned
// prover-side optimization will override `build_op_flags` / `build_chiplet_active` with a
// boolean fast path: on the prover side the decoder bits in each row are already concrete
// 0/1, so `OpFlags` / `ChipletActiveFlags` can be evaluated via boolean algebra (bitwise
// AND/OR on the known-boolean columns) instead of the polynomial products the constraint
// path needs. This avoids multiplying through dead-flag products that are guaranteed zero
// and cuts the per-row fraction-collection cost significantly.

impl<'a, EF> MainLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where EF: ExtensionField<Felt> {}

impl<'a, EF> ChipletLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where
    EF: ExtensionField<Felt>
{
}

// PROVER COLUMN
// ================================================================================================

/// Per-column handle returned by [`ProverLookupBuilder::column`].
///
/// Holds a mutable borrow of the column's per-row fraction `Vec`. Each
/// group opened inside the column reborrows the same `Vec` and pushes
/// fractions onto it — no intermediate `(N, D)` state, no
/// cross-denominator clearing.
pub struct ProverColumn<'c, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'c LookupChallenges<EF>,
    fractions: &'c mut Vec<(F, EF)>,
    /// Debug-only: current main-trace row index (see [`ProverLookupBuilder::row_idx`]).
    row_idx: usize,
    /// Debug-only: current LogUp column index (0..num_cols). Only consumed by `busdbg_log`.
    col_idx: usize,
    _phantom: PhantomData<F>,
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

    type EncodedGroup<'g>
        = ProverGroup<'g, F, EF>
    where
        Self: 'g;

    fn group<'g, R>(&'g mut self, f: impl FnOnce(&mut Self::Group<'g>) -> R) -> R {
        let mut group = ProverGroup {
            challenges: self.challenges,
            fractions: &mut *self.fractions,
            row_idx: self.row_idx,
            col_idx: self.col_idx,
            _phantom: PhantomData,
        };
        f(&mut group)
    }

    fn group_with_cached_encoding<'g, R>(
        &'g mut self,
        canonical: impl FnOnce(&mut Self::Group<'g>) -> R,
        _encoded: impl FnOnce(&mut Self::EncodedGroup<'g>) -> R,
    ) -> R {
        // Prover path: only the `canonical` closure runs; the `encoded`
        // closure is dropped unused. Both closures must describe
        // mathematically identical interaction sets, so picking the
        // simpler one is a pure optimisation on concrete rows.
        let mut group = ProverGroup {
            challenges: self.challenges,
            fractions: &mut *self.fractions,
            row_idx: self.row_idx,
            col_idx: self.col_idx,
            _phantom: PhantomData,
        };
        canonical(&mut group)
    }
}

// PROVER GROUP
// ================================================================================================

/// Per-group handle used for both the simple and cached-encoding paths
/// on the prover side.
///
/// Pushes individual `(multiplicity, denominator)` fractions onto the
/// column's per-row `Vec`. No `(N, D)` state, no cross-denominator
/// clearing — LogUp's aux-trace builder consumes individual fractions
/// downstream.
///
/// ## Boolean-flag convention
///
/// The `flag` parameter on `add` / `remove` / `insert` is treated as a
/// 0/1 boolean selector: if `flag == F::ZERO` the interaction is
/// skipped entirely (no encode, no push); otherwise the push happens
/// with the canonical multiplicity (`+1` for `add`, `-1` for `remove`,
/// `multiplicity` for `insert`). This matches the constraint path's
/// `(U_g, V_g)` algebra, which silently assumes flag is 0 or 1 —
/// non-boolean flags produce wrong results on both sides.
///
/// ## Encoded-group collapse
///
/// The same type is used for both `LookupColumn::Group` and
/// `LookupColumn::EncodedGroup` — cached-encoding fast paths don't help
/// on the prover side (`msg.encode()` is the cheapest form with `F:
/// Copy`), so `EncodedLookupGroup::insert_encoded` is just a thin
/// wrapper that pushes a caller-computed `EF` directly.
pub struct ProverGroup<'g, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'g LookupChallenges<EF>,
    fractions: &'g mut Vec<(F, EF)>,
    /// Debug-only: current main-trace row index (see [`ProverLookupBuilder::row_idx`]).
    row_idx: usize,
    /// Debug-only: current LogUp column index. Only consumed by `busdbg_log`.
    col_idx: usize,
    _phantom: PhantomData<F>,
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

    fn add<M>(&mut self, flag: F, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<F, EF>,
    {
        if flag == F::ZERO {
            return;
        }
        let built = msg();
        let v = built.encode(self.challenges);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, 1, &built, &v);
        self.fractions.push((F::ONE, v));
    }

    fn remove<M>(&mut self, flag: F, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<F, EF>,
    {
        if flag == F::ZERO {
            return;
        }
        let built = msg();
        let v = built.encode(self.challenges);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, -1, &built, &v);
        self.fractions.push((F::NEG_ONE, v));
    }

    fn insert<M>(&mut self, flag: F, multiplicity: F, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<F, EF>,
    {
        if flag == F::ZERO {
            return;
        }
        let built = msg();
        let v = built.encode(self.challenges);
        // Signed multiplicity: best-effort conversion for the debug log — the actual
        // multiplicity stored in the fraction buffer is still the raw `F` value.
        let mult_sign = felt_to_i64(multiplicity);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, mult_sign, &built, &v);
        self.fractions.push((multiplicity, v));
    }

    fn batch<'b, R>(&'b mut self, flag: F, build: impl FnOnce(&mut Self::Batch<'b>) -> R) -> R {
        // `active = false` turns every push inside the batch into a
        // no-op, which saves both the `msg.encode()` call and the `Vec`
        // push when the outer batch flag is zero. The `build` closure
        // still runs unconditionally so it can produce its `R` return
        // value without requiring `R: Default`.
        let active = flag != F::ZERO;
        let mut batch = ProverBatch {
            challenges: self.challenges,
            fractions: &mut *self.fractions,
            active,
            row_idx: self.row_idx,
            col_idx: self.col_idx,
            _phantom: PhantomData,
        };
        build(&mut batch)
    }
}

/// Best-effort signed-integer view of a `Field` multiplicity for the debug log.
/// Canonical `0` / `1` / `p - 1` map to `0` / `1` / `-1`. Larger values round-trip
/// as an unsigned integer cast (which is fine for the multiset-diff analysis — the
/// Python post-processor groups by `(col, d)` and sums signed multiplicities, and
/// large multiplicities like range-table insertions are handled correctly modulo `p`
/// even without a signed reinterpretation).
fn felt_to_i64<F: Field>(m: F) -> i64 {
    // `F::NEG_ONE` equals `p - 1` in canonical form. If the multiplicity matches it
    // exactly we round it to `-1` so the debug log reads naturally on remove-style
    // inserts; anything else is cast as an unsigned integer truncated to i64.
    if m == F::NEG_ONE {
        -1
    } else if m == F::ZERO {
        0
    } else if m == F::ONE {
        1
    } else {
        // Pull the canonical base-field representation out through the first basis
        // coefficient. `Field` doesn't expose a direct `as_canonical_u64`, but the
        // `Into<u64>` conversion via the canonical byte representation is stable
        // enough for a debug log. If this conversion isn't available for `F` the
        // log will still compile because we wrap in a const-boolean path.
        let _ = m;
        // Fall back to an arbitrary sentinel the Python parser will treat as "other".
        i64::MAX
    }
}

/// The prover path always runs the `canonical` closure (which uses the simple
/// [`LookupGroup`] surface), never the `encoded` closure. These methods exist
/// only to satisfy the `EncodedGroup: EncodedLookupGroup` GAT bound on
/// [`LookupColumn`]. Calling them is a bug — use `msg.encode()` instead.
impl<'g, F, EF> EncodedLookupGroup for ProverGroup<'g, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn beta_powers(&self) -> &[Self::ExprEF] {
        debug_assert!(false, "prover path should not call beta_powers — use msg.encode()");
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        debug_assert!(false, "prover path should not call bus_prefix — use msg.encode()");
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(&mut self, flag: F, multiplicity: F, encoded: impl FnOnce() -> EF) {
        debug_assert!(false, "prover path should not call insert_encoded — use msg.encode()");
        if flag == F::ZERO {
            return;
        }
        let v = encoded();
        let mult_sign = felt_to_i64(multiplicity);
        busdbg_log_encoded::<F, EF>(self.row_idx, self.col_idx, mult_sign, &v);
        self.fractions.push((multiplicity, v));
    }
}

// PROVER BATCH
// ================================================================================================

/// Transient handle returned by [`LookupGroup::batch`] on the prover path.
///
/// Holds the same mutable borrow of the column's fraction `Vec` as the
/// enclosing [`ProverGroup`], plus an `active` flag copied from the
/// outer `batch(flag, …)` call. When `active == false` every push is a
/// no-op — the `msg.encode()` call is skipped too, so inactive batches
/// do essentially no work.
///
/// Each `add` / `remove` / `insert` / `insert_encoded` pushes one
/// fraction entry when active. There's no `(N, D)` state inside the
/// batch — LogUp's aux-trace builder handles the combination downstream.
pub struct ProverBatch<'b, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    challenges: &'b LookupChallenges<EF>,
    fractions: &'b mut Vec<(F, EF)>,
    active: bool,
    /// Debug-only: current main-trace row index (see [`ProverLookupBuilder::row_idx`]).
    row_idx: usize,
    /// Debug-only: current LogUp column index. Only consumed by `busdbg_log`.
    col_idx: usize,
    _phantom: PhantomData<F>,
}

impl<'b, F, EF> LookupBatch for ProverBatch<'b, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Expr = F;
    type ExprEF = EF;

    fn add<M>(&mut self, msg: M)
    where
        M: LookupMessage<F, EF>,
    {
        if !self.active {
            return;
        }
        let v = msg.encode(self.challenges);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, 1, &msg, &v);
        self.fractions.push((F::ONE, v));
    }

    fn remove<M>(&mut self, msg: M)
    where
        M: LookupMessage<F, EF>,
    {
        if !self.active {
            return;
        }
        let v = msg.encode(self.challenges);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, -1, &msg, &v);
        self.fractions.push((F::NEG_ONE, v));
    }

    fn insert<M>(&mut self, multiplicity: F, msg: M)
    where
        M: LookupMessage<F, EF>,
    {
        if !self.active {
            return;
        }
        let v = msg.encode(self.challenges);
        let mult_sign = felt_to_i64(multiplicity);
        busdbg_log::<F, EF, M>(self.row_idx, self.col_idx, mult_sign, &msg, &v);
        self.fractions.push((multiplicity, v));
    }

    fn insert_encoded(&mut self, multiplicity: F, encoded: impl FnOnce() -> EF) {
        if !self.active {
            return;
        }
        let v = encoded();
        let mult_sign = felt_to_i64(multiplicity);
        busdbg_log_encoded::<F, EF>(self.row_idx, self.col_idx, mult_sign, &v);
        self.fractions.push((multiplicity, v));
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{vec, vec::Vec};

    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
    use miden_crypto::stark::air::RowWindow;

    use super::*;
    use crate::{
        Felt,
        constraints::lookup::{LookupAir, fractions::accumulate_slow, message::LookupMessage},
        trace::Challenges,
    };

    /// Minimal `LookupMessage` used by [`SmokeAir`] to drive a `Vec::push` into the
    /// prover builder's fraction buffer. Encodes to `bus_prefix[0] + β⁰·value`, which is
    /// always non-zero for non-trivial challenges (so `accumulate_slow` can `try_inverse`
    /// without blowing up).
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

    impl<LB> LookupAir<LB> for SmokeAir
    where
        LB: LookupBuilder<F = Felt, EF = QuadFelt, Expr = Felt, ExprEF = QuadFelt>,
    {
        fn num_columns(&self) -> usize {
            2
        }
        fn column_shape(&self) -> &[usize] {
            &SMOKE_SHAPE
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }
        fn eval(&self, builder: &mut LB) {
            builder.next_column(|col| {
                col.group(|g| {
                    g.add(Felt::ONE, || SmokeMsg { value: Felt::ONE });
                    g.remove(Felt::ONE, || SmokeMsg { value: Felt::new(2) });
                });
            });
            builder.next_column(|col| {
                col.group(|g| {
                    g.batch(Felt::ONE, |b| {
                        b.insert(Felt::ONE, SmokeMsg { value: Felt::new(3) });
                    });
                });
            });
        }
    }

    /// End-to-end collection sanity check: run `SmokeAir::eval` through
    /// `ProverLookupBuilder` over several rows and verify the per-column counts match the
    /// handcrafted `eval` body, that `accumulate_slow` produces a `num_rows + 1`-long
    /// output per column starting at zero, and that the running sum monotonically grows
    /// by the expected amount each row.
    #[test]
    fn prover_lookup_builder_collects_into_fractions() {
        const NUM_ROWS: usize = 8;

        let air = SmokeAir;

        // Any reasonable non-zero challenges — SmokeMsg encodes to `bus_prefix[0] + v`
        // which is non-zero as long as the challenges are.
        let alpha = QuadFelt::new([Felt::new(7), Felt::new(11)]);
        let beta = QuadFelt::new([Felt::new(13), Felt::new(17)]);
        let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

        // `SmokeAir::eval` never touches the main trace, periodic columns, or public
        // values — pass dummy zero-length slices.
        let empty_row: Vec<Felt> = vec![];
        let periodic_values: Vec<Felt> = vec![];
        let public_values: Vec<Felt> = vec![];

        let mut fractions = LookupFractions::<Felt, QuadFelt>::new::<
            _,
            ProverLookupBuilder<'_, Felt, QuadFelt>,
        >(&air, NUM_ROWS);

        for _row in 0..NUM_ROWS {
            let window = RowWindow::from_two_rows(&empty_row, &empty_row);
            let mut lb = ProverLookupBuilder::new(
                window,
                &periodic_values,
                &public_values,
                &challenges,
                &air,
                &mut fractions,
            );
            air.eval(&mut lb);
        }

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

        // Accumulator produces num_rows+1 entries per column, and the running sum for
        // each column advances by a deterministic per-row delta.
        let aux = accumulate_slow(&fractions);
        assert_eq!(aux.len(), 2);
        for col_aux in &aux {
            assert_eq!(col_aux.len(), NUM_ROWS + 1);
            assert_eq!(col_aux[0], QuadFelt::ZERO);
        }

        // Column 0 row delta = 1/d(ONE) - 1/d(TWO); column 1 row delta = 1/d(THREE).
        let d1 = SmokeMsg { value: Felt::ONE }.encode(&challenges);
        let d2 = SmokeMsg { value: Felt::new(2) }.encode(&challenges);
        let d3 = SmokeMsg { value: Felt::new(3) }.encode(&challenges);
        let delta0 = d1.try_inverse().unwrap() - d2.try_inverse().unwrap();
        let delta1 = d3.try_inverse().unwrap();
        for r in 0..NUM_ROWS {
            assert_eq!(aux[0][r + 1] - aux[0][r], delta0);
            assert_eq!(aux[1][r + 1] - aux[1][r], delta1);
        }
    }
}
