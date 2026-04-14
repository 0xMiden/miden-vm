//! Prover-path adapter — pushes individual `(m, v)` fractions per
//! interaction into per-column `Vec`s owned by the caller.
//!
//! Implements [`LookupBuilder`] for concrete base-field rows. Where the
//! [constraint-path adapter](super::constraint::ConstraintLookupBuilder)
//! emits symbolic `(U, V)` constraint expressions against a
//! `LiftedAirBuilder`, this adapter consumes two concrete rows of
//! base-field values and **pushes the individual fractions** each
//! interaction contributes — one `(multiplicity, denominator)` entry per
//! active interaction, into a per-column `Vec` the caller owns.
//!
//! ## Runtime shape
//!
//! The caller:
//!
//! 1. Builds one [`LookupChallenges<EF>`] once, outside the per-row loop.
//! 2. Pre-allocates a `[Vec<(F, EF)>]` with exactly `air.num_columns()` entries. Each inner `Vec`
//!    will receive the fractions for one permutation column across one row evaluation.
//! 3. For each row pair, constructs a `ProverLookupBuilder` (cheap — just stores pointers), calls
//!    `air.eval(&mut lb)`, drops the builder to release its borrow, reads / accumulates the
//!    per-column `Vec`s into the aux-trace running sum, then `.clear()`s each `Vec` before the next
//!    row.
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

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::field::{ExtensionField, Field};
use miden_crypto::stark::air::RowWindow;

use super::{
    EncodedLookupGroup, LookupAir, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn,
    LookupGroup, LookupMessage, chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder,
};
use crate::Felt;

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
    /// One fraction list per permutation column, indexed by
    /// [`Self::column_idx`]. Each [`LookupBuilder::column`] call
    /// appends to the current column's list via
    /// [`ProverGroup::add`] / `remove` / `insert` / `batch`, then
    /// advances the cursor. The caller owns the outer slice *and*
    /// every inner `Vec`; between rows they read out the fractions
    /// and call `.clear()` on each `Vec` to rewind.
    column_fractions: &'a mut [Vec<(F, EF)>],
    column_idx: usize,
}

impl<'a, F, EF> ProverLookupBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a new prover-path adapter for one row.
    ///
    /// - `main`: two-row window over the current and next base-field rows.
    /// - `periodic_values`: periodic columns at the current row.
    /// - `public_values`: public inputs.
    /// - `challenges`: precomputed LogUp challenges (shared across every row — the caller builds
    ///   this once outside the row loop and passes a shared reference here).
    /// - `air`: the lookup shape (used only for a debug assertion that `column_fractions.len() ==
    ///   air.num_columns()`; the builder never calls `air.eval` itself — that's the caller's job).
    /// - `column_fractions`: pre-allocated per-column fraction lists. Must have exactly
    ///   `air.num_columns()` entries. Each inner `Vec` is appended to by the interaction closures
    ///   and should be cleared by the caller between rows.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `column_fractions.len() != air.num_columns()`.
    pub fn new<A>(
        main: RowWindow<'a, F>,
        periodic_values: &'a [F],
        public_values: &'a [F],
        challenges: &'a LookupChallenges<EF>,
        air: &A,
        column_fractions: &'a mut [Vec<(F, EF)>],
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        debug_assert_eq!(
            column_fractions.len(),
            air.num_columns(),
            "column_fractions buffer must be pre-sized to air.num_columns()",
        );
        Self {
            main,
            periodic_values,
            public_values,
            challenges,
            column_fractions,
            column_idx: 0,
        }
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

    fn column<'c, R>(&'c mut self, f: impl FnOnce(&mut Self::Column<'c>) -> R) -> R {
        let idx = self.column_idx;
        let mut col = ProverColumn {
            challenges: self.challenges,
            fractions: &mut self.column_fractions[idx],
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        // `col` drops here, releasing the borrow on `self.column_fractions[idx]`
        // before we touch `self.column_idx`.
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
// prover-side optimization will replace these bodies with a boolean fast path that skips
// the dead flag products for rows where decoder bits are already concrete 0/1.

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
        let v = msg().encode(self.challenges);
        self.fractions.push((F::ONE, v));
    }

    fn remove<M>(&mut self, flag: F, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<F, EF>,
    {
        if flag == F::ZERO {
            return;
        }
        let v = msg().encode(self.challenges);
        self.fractions.push((F::NEG_ONE, v));
    }

    fn insert<M>(&mut self, flag: F, multiplicity: F, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<F, EF>,
    {
        if flag == F::ZERO {
            return;
        }
        let v = msg().encode(self.challenges);
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
            _phantom: PhantomData,
        };
        build(&mut batch)
    }
}

impl<'g, F, EF> EncodedLookupGroup for ProverGroup<'g, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id]
    }

    fn insert_encoded(&mut self, flag: F, multiplicity: F, encoded: impl FnOnce() -> EF) {
        if flag == F::ZERO {
            return;
        }
        let v = encoded();
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
        self.fractions.push((multiplicity, v));
    }

    fn insert_encoded(&mut self, multiplicity: F, encoded: impl FnOnce() -> EF) {
        if !self.active {
            return;
        }
        let v = encoded();
        self.fractions.push((multiplicity, v));
    }
}
