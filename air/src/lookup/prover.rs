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
//! 1. Builds one [`Challenges<EF>`] once, outside the per-row loop.
//! 2. Allocates one [`LookupFractions`] once via [`LookupFractions::new`], sized from
//!    [`LookupAir::column_shape`]. Each column's internal Vec is `Vec::with_capacity(num_rows *
//!    shape[col])` so pushes in the row loop never re-allocate.
//! 3. For each row pair, constructs a `ProverLookupBuilder` (cheap — just stores pointers), calls
//!    `air.eval(&mut lb)`, then drops the builder. `column(f)` records how many fractions the row
//!    pushed into `LookupFractions::counts_per_row[col]`, so the downstream accumulator can later
//!    slice each row's contribution out via a running cursor without a separate offsets array.
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
use core::borrow::Borrow;

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::RowWindow;

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupFractions,
    LookupGroup, LookupMessage,
};

// PROVER LOOKUP BUILDER
// ================================================================================================

/// Concrete-row `LookupBuilder` running on two rows of base-field values.
///
/// See the module docs for the full runtime shape. Parameterised
/// by the base field `F` and the extension field `EF`; every `Expr` /
/// `Var` / `VarEF` etc. associated type collapses to `F` or `EF`
/// directly — there is no symbolic tree on the prover side.
///
/// The [`Challenges`] table is **borrowed** from the caller: the
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
    challenges: &'a Challenges<EF>,
    /// Dense per-column fraction buffers shared across all rows. Each
    /// [`LookupBuilder::next_column`] call appends the current row's fractions to the end of
    /// `fractions.fractions[column_idx]` and pushes the row's interaction count into
    /// `fractions.counts_per_row[column_idx]`. The outer Vecs never move or re-allocate
    /// as long as each row stays within the declared [`LookupAir::column_shape`] bound.
    fractions: &'a mut LookupFractions<F, EF>,
    column_idx: usize,
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
        challenges: &'a Challenges<EF>,
        air: &A,
        fractions: &'a mut LookupFractions<F, EF>,
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
            challenges,
            fractions,
            column_idx: 0,
        }
    }
}

// BUILD LOOKUP FRACTIONS DRIVER
// ================================================================================================

/// Walk a complete main trace through [`ProverLookupBuilder`] and return the dense
/// [`LookupFractions`] buffer the collection phase produces.
///
/// Generic over the base field `F` and extension field `EF`. The caller supplies the
/// main trace and periodic columns — this function does row slicing, periodic-column
/// indexing, and fraction collection. Concrete AIRs wrap this with their own
/// periodic-column layout.
///
/// # Arguments
///
/// - `air`: the [`LookupAir`] to evaluate.
/// - `main_trace`: row-major main execution trace. Row access is zero-copy via
///   `main_trace.values.borrow()`.
/// - `periodic_columns`: one `Vec<F>` per periodic column, each with its own period.
/// - `challenges`: precomputed LogUp challenges (shared across every row).
///
/// # Panics
///
/// Panics in debug builds if any row pushes more fractions into a column than that
/// column's declared [`LookupAir::column_shape`] bound — this indicates the emitter's
/// `MAX_INTERACTIONS_PER_ROW` const is too low and needs to be bumped.
pub fn build_lookup_fractions<A, F, EF>(
    air: &A,
    main_trace: &RowMajorMatrix<F>,
    periodic_columns: &[Vec<F>],
    challenges: &Challenges<EF>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let num_rows = main_trace.height();
    let width = main_trace.width();
    let flat: &[F] = main_trace.values.borrow();

    let mut fractions = LookupFractions::new::<A, ProverLookupBuilder<'_, F, EF>>(air, num_rows);

    // Per-row periodic slice, filled in place each row — no per-iteration allocation.
    let mut periodic_row: Vec<F> = vec![F::ZERO; periodic_columns.len()];

    for r in 0..num_rows {
        let curr = &flat[r * width..(r + 1) * width];
        let nxt_idx = (r + 1) % num_rows;
        let next = &flat[nxt_idx * width..(nxt_idx + 1) * width];
        let window = RowWindow::from_two_rows(curr, next);

        for (i, col) in periodic_columns.iter().enumerate() {
            periodic_row[i] = col[r % col.len()];
        }

        let mut lb =
            ProverLookupBuilder::new(window, &periodic_row, challenges, air, &mut fractions);
        air.eval(&mut lb);
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

    fn next_column<'c, R>(
        &'c mut self,
        f: impl FnOnce(&mut Self::Column<'c>) -> R,
        _deg: Deg,
    ) -> R {
        let idx = self.column_idx;
        // Split-borrow disjoint fields of `LookupFractions` so the post-closure
        // `counts.push(...)` isn't blocked by the GAT-lifetime borrow on `fractions`.
        let vec = &mut self.fractions.fractions;
        let counts = &mut self.fractions.counts;
        let shape_col = self.fractions.shape[idx];
        let start_len = vec.len();

        // Scope the `ProverColumn` so its borrow on `vec` ends before `counts.push`.
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

/// Per-column handle returned by [`ProverLookupBuilder::next_column`].
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
        // Prover path runs only the `canonical` closure; both closures must describe
        // identical interaction sets, so the `encoded` fast path has no advantage on
        // concrete rows and is discarded.
        self.group(name, canonical, deg);
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
/// ## Encoded-group methods
///
/// The encoding primitives (`beta_powers`, `bus_prefix`, `insert_encoded`)
/// use the default panicking implementations from [`LookupGroup`] — the
/// prover path always runs the `canonical` closure, never the `encoded`
/// one, so these methods should never be reached.
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
        if flag == F::ZERO {
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
/// Each push appends one fraction entry when active. There's no `(N, D)` state
/// inside the batch — LogUp's aux-trace builder handles the combination downstream.
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
        if !self.active {
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
        if !self.active {
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

    use std::{vec, vec::Vec};

    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
    use miden_crypto::stark::air::RowWindow;

    use super::*;
    use crate::{
        Felt,
        lookup::{Deg, LookupAir, accumulate_slow, message::LookupMessage},
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
            builder.next_column(
                |col| {
                    col.group(
                        "smoke_grp_0",
                        |g| {
                            g.add(
                                "smoke_add",
                                Felt::ONE,
                                || SmokeMsg { value: Felt::ONE },
                                Deg { n: 0, d: 0 },
                            );
                            g.remove(
                                "smoke_remove",
                                Felt::ONE,
                                || SmokeMsg { value: Felt::new_unchecked(2) },
                                Deg { n: 0, d: 0 },
                            );
                        },
                        Deg { n: 0, d: 0 },
                    );
                },
                Deg { n: 0, d: 0 },
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
                                        Deg { n: 0, d: 0 },
                                    );
                                },
                                Deg { n: 0, d: 0 },
                            );
                        },
                        Deg { n: 0, d: 0 },
                    );
                },
                Deg { n: 0, d: 0 },
            );
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
        let alpha = QuadFelt::new([Felt::new_unchecked(7), Felt::new_unchecked(11)]);
        let beta = QuadFelt::new([Felt::new_unchecked(13), Felt::new_unchecked(17)]);
        // SmokeAir hard-codes `max_message_width = 1` / `num_bus_ids = 1` in its
        // `LookupAir` impl — the trait-method path can't be called directly because
        // `LookupAir<LB>` is generic over `LB` and disambiguation fails at a value call.
        let challenges = Challenges::<QuadFelt>::new(alpha, beta, 1, 1);

        // `SmokeAir::eval` never touches the main trace, periodic columns, or public
        // values — pass dummy zero-length slices.
        let empty_row: Vec<Felt> = vec![];
        let periodic_values: Vec<Felt> = vec![];

        let mut fractions = LookupFractions::<Felt, QuadFelt>::new::<
            _,
            ProverLookupBuilder<'_, Felt, QuadFelt>,
        >(&air, NUM_ROWS);

        for _row in 0..NUM_ROWS {
            let window = RowWindow::from_two_rows(&empty_row, &empty_row);
            let mut lb = ProverLookupBuilder::new(
                window,
                &periodic_values,
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

        let aux = accumulate_slow(&fractions);
        assert_eq!(aux.len(), 2);
        for col_aux in &aux {
            assert_eq!(col_aux.len(), NUM_ROWS + 1);
        }
        assert_eq!(aux[0][0], QuadFelt::ZERO, "accumulator initial must be zero");

        let d1 = SmokeMsg { value: Felt::ONE }.encode(&challenges);
        let d2 = SmokeMsg { value: Felt::new_unchecked(2) }.encode(&challenges);
        let d3 = SmokeMsg { value: Felt::new_unchecked(3) }.encode(&challenges);
        let delta0 = d1.try_inverse().unwrap() - d2.try_inverse().unwrap();
        let delta1 = d3.try_inverse().unwrap();
        // Column 0 (accumulator): each row delta = own fraction + col 1's fraction.
        for r in 0..NUM_ROWS {
            assert_eq!(aux[0][r + 1] - aux[0][r], delta0 + delta1);
        }
        // Column 1 (fraction, aux_curr): value at row r is the per-row fraction.
        for &entry in aux[1].iter().take(NUM_ROWS) {
            assert_eq!(entry, delta1);
        }
    }
}
