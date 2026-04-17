//! Test-support [`LookupBuilder`] that evaluates a [`super::LookupAir`] concretely on one
//! row and exposes the per-column `(U_col, V_col)` folds the constraint-path algebra
//! would produce.
//!
//! ## Role
//!
//! The existing [`super::prover::ProverLookupBuilder`] consumes concrete row data and
//! emits per-fraction `(multiplicity, denominator)` pairs into a [`super::LookupFractions`]
//! buffer; downstream, [`super::fractions::accumulate`] produces per-column partial sums
//! by computing `Σ m_i · d_i^{-1}` over each row's slice.
//!
//! [`ColumnOracleBuilder`] computes the **same algebraic quantity** via a completely
//! different formula: it runs the constraint-path `(U_g, V_g)` algebra per group, folds
//! groups into a per-column `(U_col, V_col)` pair using the standard LogUp
//! cross-multiplication rule (matching
//! [`super::constraint::ConstraintColumn::fold_group`] verbatim), and leaves the caller to
//! compute `V_col · U_col^{-1}` as the expected per-row aux-column delta.
//!
//! If the two paths agree on every `(row, col)` delta for a real program's trace, every
//! layer of the LogUp pipeline (emit, encode, collect, batched invert, partial sum) is
//! self-consistent against the constraint-path algebra.
//!
//! ## Per-group algebra
//!
//! Same formulas as [`super::dual_builder::DualGroup`], which itself mirrors
//! [`super::constraint::ConstraintGroup`]. For a simple-path [`LookupGroup`]:
//!
//! ```text
//!   add(flag, msg):    U_g += (v_msg - 1) · flag,  V_g += flag
//!   remove(flag, msg): U_g += (v_msg - 1) · flag,  V_g -= flag
//!   insert(flag, m, msg): U_g += (v_msg - 1) · flag,  V_g += flag · m
//! ```
//!
//! starting from `(U_g, V_g) = (ONE, ZERO)`. This formulation relies on the
//! mutual-exclusion invariant: in a plain `group(...)` at most **one** `add`/`remove`/`insert`
//! call fires with a non-zero flag per row. For multiple simultaneous interactions use
//! `group.batch(flag, |b| { ... })` — inside the batch, `(N, D) ← (N·v + m·D, D·v)` absorbs
//! each sub-interaction by cross-multiplication, then the final `(N, D)` is folded into
//! `(U_g, V_g)` via `U_g += (D - 1) · flag`, `V_g += N · flag`.
//!
//! ## Per-column fold
//!
//! Multiple sibling groups on the same column (e.g. M1's `block_stack` + `range_table`)
//! are combined via cross-multiplication, matching
//! [`super::constraint::ConstraintColumn::fold_group`]:
//!
//! ```text
//!   (U_col, V_col) starts at (ONE, ZERO)
//!   per group:
//!     V_col_new = V_col · U_g + V_g · U_col
//!     U_col_new = U_col · U_g
//! ```

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::RowWindow;

use super::{
    Deg, LookupAir, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn, LookupGroup,
    LookupMessage, chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder,
};

// COLUMN ORACLE BUILDER
// ================================================================================================

/// Test-support [`LookupBuilder`] exposing per-column `(U_col, V_col)` folds computed via
/// the constraint-path algebra.
///
/// Constructed once per row with a row-window, periodic/public slices, challenges, and a
/// mutable `column_folds` scratch buffer of length `num_columns` which the builder resets
/// to `(ONE, ZERO)` at construction and then updates as each `column(...)` call closes.
/// After the top-level `air.eval(&mut oracle)` returns, `column_folds[col_idx]` holds the
/// folded `(U_col, V_col)` pair for that column on the current row.
///
/// Every associated type collapses to `Felt` / `QuadFelt` — same shape as
/// [`super::dual_builder::DualBuilder`] and [`super::prover::ProverLookupBuilder`]. The
/// builder is purely a test oracle; the production constraint path is still
/// [`super::constraint::ConstraintLookupBuilder`].
pub struct ColumnOracleBuilder<'a> {
    main: RowWindow<'a, Felt>,
    periodic_values: &'a [Felt],
    public_values: &'a [Felt],
    challenges: &'a LookupChallenges<QuadFelt>,
    /// Per-column folded `(U_col, V_col)`. Initialised to `(ONE, ZERO)` in
    /// [`Self::new`]; each `column(...)` call updates exactly one entry via
    /// [`OracleColumn::fold_group`].
    column_folds: &'a mut [(QuadFelt, QuadFelt)],
    column_idx: usize,
}

impl<'a> ColumnOracleBuilder<'a> {
    /// Create a new oracle for one row. `column_folds` must have exactly `air.num_columns()`
    /// entries; the builder resets each to `(ONE, ZERO)` before any `column(...)` call runs.
    pub fn new(
        main: RowWindow<'a, Felt>,
        periodic_values: &'a [Felt],
        public_values: &'a [Felt],
        challenges: &'a LookupChallenges<QuadFelt>,
        column_folds: &'a mut [(QuadFelt, QuadFelt)],
    ) -> Self {
        for fold in column_folds.iter_mut() {
            *fold = (QuadFelt::ONE, QuadFelt::ZERO);
        }
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            column_folds,
            column_idx: 0,
        }
    }
}

impl<'a> LookupBuilder for ColumnOracleBuilder<'a> {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;

    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    type PeriodicVar = Felt;
    type PublicVar = Felt;

    type MainWindow = RowWindow<'a, Felt>;

    type Column<'c>
        = OracleColumn<'c>
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
        _deg: Deg,
    ) -> R {
        let idx = self.column_idx;
        let mut col = OracleColumn {
            challenges: self.challenges,
            fold: &mut self.column_folds[idx],
        };
        let result = f(&mut col);
        // `col` drops here, releasing the borrow on the fold slot before we touch
        // `self.column_idx`.
        self.column_idx += 1;
        result
    }
}

// Empty marker impls — same as `ProverLookupBuilder` / `DualBuilder`. The oracle always
// uses the polynomial path for `OpFlags` / `ChipletActiveFlags` construction.
impl<'a> MainLookupBuilder for ColumnOracleBuilder<'a> {}
impl<'a> ChipletLookupBuilder for ColumnOracleBuilder<'a> {}

// ORACLE COLUMN
// ================================================================================================

/// Per-column handle for [`ColumnOracleBuilder`]. Holds a mutable borrow of the parent's
/// `column_folds[idx]` slot; each sibling `group(...)` call folds its `(U_g, V_g)` into the
/// slot via [`Self::fold_group`] before returning.
pub struct OracleColumn<'c> {
    challenges: &'c LookupChallenges<QuadFelt>,
    fold: &'c mut (QuadFelt, QuadFelt),
}

impl<'c> OracleColumn<'c> {
    /// Fold an inner group's `(U_g, V_g)` into this column's running `(U_col, V_col)` using
    /// cross-multiplication. Matches [`super::constraint::ConstraintColumn::fold_group`]
    /// verbatim.
    fn fold_group(&mut self, u_g: QuadFelt, v_g: QuadFelt) {
        let (u_col, v_col) = *self.fold;
        self.fold.1 = v_col * u_g + v_g * u_col;
        self.fold.0 = u_col * u_g;
    }
}

impl<'c> LookupColumn for OracleColumn<'c> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Group<'g>
        = OracleGroup<'g>
    where
        Self: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = OracleGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
        };
        f(&mut group);
        self.fold_group(group.u, group.v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'g>),
        _encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Oracle runs only the canonical closure. The
        // `miden_lookup_air_cached_encoding_equivalence` test already guarantees canonical
        // and encoded produce identical `(U_g, V_g)` pairs, so running only one is
        // sufficient and cheaper.
        let mut group = OracleGroup {
            challenges: self.challenges,
            u: QuadFelt::ONE,
            v: QuadFelt::ZERO,
        };
        canonical(&mut group);
        self.fold_group(group.u, group.v);
    }
}

// ORACLE GROUP
// ================================================================================================

/// Per-group handle for [`OracleColumn`]. Accumulates a local `(U_g, V_g)` using the same
/// formulas as [`super::dual_builder::DualGroup`] / [`super::constraint::ConstraintGroup`].
///
/// Used for both the plain `group(...)` path and the canonical closure of
/// `group_with_cached_encoding`. The encoding primitives (`beta_powers`,
/// `bus_prefix`, `insert_encoded`) are provided for trait completeness
/// even though the oracle only runs canonical closures.
pub struct OracleGroup<'g> {
    challenges: &'g LookupChallenges<QuadFelt>,
    u: QuadFelt,
    v: QuadFelt,
}

impl<'g> LookupGroup for OracleGroup<'g> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    type Batch<'b>
        = OracleBatch<'b>
    where
        Self: 'b;

    fn insert<M>(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        let v_msg = msg().encode(self.challenges);
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        // Start with `(N, D) = (0, 1)` (empty-batch identity), run the build closure,
        // then fold the final `(N, D)` into `(U_g, V_g)`:
        //   U_g += (D - 1) · flag
        //   V_g += N · flag
        let mut batch = OracleBatch {
            challenges: self.challenges,
            n: QuadFelt::ZERO,
            d: QuadFelt::ONE,
        };
        build(&mut batch);
        let OracleBatch { n, d, .. } = batch;
        self.u += (d - QuadFelt::ONE) * flag;
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> QuadFelt,
        _deg: Deg,
    ) {
        // Not reached today (the oracle only runs canonical closures), but provided for
        // trait completeness.
        let v_msg = encoded();
        self.u += (v_msg - QuadFelt::ONE) * flag;
        self.v += flag * multiplicity;
    }
}

// ORACLE BATCH
// ================================================================================================

/// Transient handle for [`OracleGroup::batch`]. Mirrors
/// [`super::dual_builder::DualBatch`]: maintains an internal `(N, D)` pair and absorbs
/// each interaction via cross-multiplication, with `(N, D) ← (N·v + m·D, D·v)`. The outer
/// group folds the final pair into its `(U_g, V_g)` once `build` returns.
pub struct OracleBatch<'b> {
    challenges: &'b LookupChallenges<QuadFelt>,
    n: QuadFelt,
    d: QuadFelt,
}

impl<'b> LookupBatch for OracleBatch<'b> {
    type Expr = Felt;
    type ExprEF = QuadFelt;

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        let v_msg = msg.encode(self.challenges);
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        let v_msg = encoded();
        let d_prev = self.d;
        self.n = self.n * v_msg + d_prev * multiplicity;
        self.d *= v_msg;
    }
}

// COLUMN-FOLD DRIVER
// ================================================================================================

/// Walk a complete main trace through [`ColumnOracleBuilder`] and return the per-row
/// folded `(U_col, V_col)` pairs the constraint-path algebra produces.
///
/// Mirrors [`super::prover::build_lookup_fractions`] but on the constraint-path side:
/// per row `r`, constructs a two-row `RowWindow` over `&flat[r * w .. (r + 1) * w]` and
/// `&flat[((r + 1) % n) * w .. ..]` (wraparound on the last row), composes the per-row
/// periodic slice by indexing each periodic column at `r mod its period`, runs
/// `air.eval(&mut ColumnOracleBuilder)`, and snapshots the resulting `column_folds` into
/// the returned matrix.
///
/// Returns `folds` where `folds[r][col] = (U_col, V_col)` — the constraint-path oracle's
/// folded pair for column `col` at row `r`. The caller computes the expected aux-column
/// delta as `V_col · U_col^{-1}` and compares against the prover-path output of
/// [`super::fractions::accumulate`].
///
/// # Panics
///
/// Panics if `air.num_columns() != column_folds.len()` at any point (via the internal
/// `ColumnOracleBuilder::new` length check), which can't happen in practice since
/// `column_folds` is sized from `air.num_columns()` inside this function.
pub fn collect_column_oracle_folds<A>(
    air: &A,
    main_trace: &RowMajorMatrix<Felt>,
    periodic_columns: &[Vec<Felt>],
    public_values: &[Felt],
    challenges: &LookupChallenges<QuadFelt>,
) -> Vec<Vec<(QuadFelt, QuadFelt)>>
where
    for<'a> A: LookupAir<ColumnOracleBuilder<'a>>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[Felt] = main_trace.values.borrow();
    let num_cols = air.num_columns();

    let mut folds_per_row: Vec<Vec<(QuadFelt, QuadFelt)>> = Vec::with_capacity(num_rows);
    let mut column_folds = vec![(QuadFelt::ONE, QuadFelt::ZERO); num_cols];
    let mut periodic_row: Vec<Felt> = vec![Felt::ZERO; periodic_columns.len()];

    for r in 0..num_rows {
        // Zero-copy row slices over the flat matrix storage — same as
        // `build_lookup_fractions`.
        let curr = &flat[r * width..(r + 1) * width];
        let nxt_idx = (r + 1) % num_rows;
        let next = &flat[nxt_idx * width..(nxt_idx + 1) * width];
        let window = RowWindow::from_two_rows(curr, next);

        // Per-row periodic slice.
        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }

        // Run the oracle. `ColumnOracleBuilder::new` resets `column_folds` to the
        // `(ONE, ZERO)` identity for every row, so no manual reset is needed here.
        {
            let mut oracle = ColumnOracleBuilder::new(
                window,
                &periodic_row,
                public_values,
                challenges,
                &mut column_folds,
            );
            air.eval(&mut oracle);
        }

        // Snapshot the folds for this row.
        folds_per_row.push(column_folds.clone());
    }

    folds_per_row
}
