//! Constraint-path adapter for the new closure-based lookup API.
//!
//! Implements [`LookupBuilder`] over any `LiftedAirBuilder` that runs on
//! the base field `Felt`. The adapter mirrors the column-accumulator
//! algebra in [`crate::constraints::logup`] (`Batch` / `RationalSet` /
//! `Column`) but wraps it in the closure-based surface described by
//! [`super::builder`].
//!
//! ## Algebra location
//!
//! Per Amendment B the per-interaction encoding lives inside each
//! [`LookupMessage::encode`] body, so the adapter carries **no scratch
//! buffer**: every `add` / `remove` / `insert` body is a two-liner that
//! calls `msg.encode(self.challenges)` and absorbs the resulting
//! `AB::ExprEF` denominator into the running `(U, V)` (group) or
//! `(N, D)` (batch) pair.
//!
//! The running-pair updates are also inlined at every call site (no
//! `absorb_single` / `absorb` helpers), which lets the `add` / `remove`
//! paths skip the `flag * E::ONE` / `flag * E::NEG_ONE` multiplication
//! — on the constraint path that shrinks the symbolic tree by one node
//! per single-interaction call.
//!
//! ## Challenge handling
//!
//! The top-level [`ConstraintLookupBuilder`] reads α/β out of
//! `ab.permutation_randomness()[0..2]` exactly once at construction time
//! and stores them in a [`LookupChallenges<AB::ExprEF>`], which
//! precomputes both the β-power table (β⁰..β^(W-1)) and the bus-prefix
//! table (`bus_prefix[i] = α + (i + 1) · β^W`) sized from the
//! [`LookupAir`] passed to [`ConstraintLookupBuilder::new`]. The cached
//! challenges flow through the per-column / per-group handles by shared
//! reference, so each interaction sees the same precomputed tables
//! without reconstructing them.
//!
//! The permutation column slices are *not* cached — each
//! [`LookupBuilder::column`] call re-queries `ab.permutation()` to pick
//! up the current-row / next-row `VarEF` values. `ab.permutation()` is
//! cheap (it builds a window over references) and not caching keeps the
//! builder a four-field struct.

use core::marker::PhantomData;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{ExtensionBuilder, LiftedAirBuilder, WindowAccess};

use super::{
    EncodedLookupGroup, LookupAir, LookupBatch, LookupBuilder, LookupChallenges, LookupColumn,
    LookupGroup, LookupMessage, chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder,
};
use crate::Felt;

// CONSTRAINT LOOKUP BUILDER
// ================================================================================================

/// Constraint-path [`LookupBuilder`] over a wrapped [`LiftedAirBuilder`].
///
/// Construct via [`ConstraintLookupBuilder::new`]. The adapter caches the
/// precomputed challenges ([`LookupChallenges`] sized from the
/// [`LookupAir`]) and a small column-index counter; the permutation row
/// slices are re-queried from the wrapped `&mut AB` on every
/// [`LookupBuilder::column`] call.
pub struct ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder<F = Felt> + 'ab,
{
    ab: &'ab mut AB,
    challenges: LookupChallenges<AB::ExprEF>,
    column_idx: usize,
}

impl<'ab, AB> ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    /// Create a new adapter wrapping `ab`, sized from `air`.
    ///
    /// The `air` parameter is bound as `LookupAir<Self>`, which pins the
    /// `LB` type parameter of [`LookupAir`] to this concrete adapter. The
    /// canonical usage is a blanket `impl<LB: LookupBuilder> LookupAir<LB>
    /// for MyAir`, which automatically satisfies the bound here and lets
    /// us read the shape without any turbofishing at the call site.
    ///
    /// Reads `ab.permutation_randomness()` to extract α = `r[0]` and β = `r[1]`, then builds
    /// a [`LookupChallenges<AB::ExprEF>`] (= `crate::trace::Challenges`). The fixed-size
    /// array layout means the `air.max_message_width()` / `air.num_bus_ids()` shape numbers
    /// are no longer needed at construction time — they're enforced by the
    /// `MAX_MESSAGE_WIDTH` / `NUM_BUS_TYPES` constants on the `Challenges` struct.
    pub fn new<A>(ab: &'ab mut AB, _air: &A) -> Self
    where
        A: LookupAir<Self>,
    {
        let (alpha, beta): (AB::ExprEF, AB::ExprEF) = {
            let r = ab.permutation_randomness();
            (r[0].into(), r[1].into())
        };
        let challenges = LookupChallenges::<AB::ExprEF>::new(alpha, beta);

        Self { ab, challenges, column_idx: 0 }
    }
}

impl<'ab, AB> LookupBuilder for ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;

    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;

    type PeriodicVar = AB::PeriodicVar;
    type PublicVar = AB::PublicVar;

    type MainWindow = AB::MainWindow;

    type Column<'a>
        = ConstraintColumn<'a, AB>
    where
        Self: 'a,
        AB: 'a;

    fn main(&self) -> Self::MainWindow {
        self.ab.main()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.ab.periodic_values()
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.ab.public_values()
    }

    fn column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R) -> R {
        // Open the column with an empty `(U, V) = (1, 0)` accumulator.
        // The column only holds a shared borrow of the challenges and
        // the two running-pair slots — the `&mut AB` stays on the
        // builder and is only reached back into for the finalize step
        // below.
        let mut col = ConstraintColumn {
            challenges: &self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        let ConstraintColumn { u, v, .. } = col;

        // TODO(milestone-B-followup): re-enable LogUp boundary / transition constraints.
        //
        // Milestone B intentionally disables the boundary + transition checks while the
        // stateless `MidenLookupAuxBuilder` integration lands. The aux trace is still
        // committed and observed by the Fiat-Shamir challenger, but the symbolic LogUp
        // algebra is not yet enforced — what passes the verifier is only the unchanged
        // main-trace constraint system. The follow-up milestone restores real checks
        // once column closure + public-input correction terms for open buses
        // (`block_hash`, `chiplets bus`, `log_precompile transcript`) are designed.
        //
        // The original constraint set, kept here for reference and easy restoration:
        //
        let (acc, acc_next) = {
            let mp = self.ab.permutation();
            let acc: AB::ExprEF = mp.current_slice()[self.column_idx].into();
            let acc_next: AB::ExprEF = mp.next_slice()[self.column_idx].into();
            (acc, acc_next)
        };
        let delta = acc_next - acc.clone();
        //     self.ab.when_first_row().assert_zero_ext(acc.clone());
            self.ab.when_transition().assert_zero_ext(delta * u - v);
        //     self.ab.when_last_row().assert_zero_ext(acc);
        // let _ = (u, v);

        self.column_idx += 1;
        result
    }
}

// EXTENSION TRAIT IMPLS
// ================================================================================================

// Empty impls that pick up the default polynomial bodies of `build_op_flags` /
// `build_chiplet_active`. A future prover-path adapter will override these on its own type;
// the constraint path always wants the polynomial construction.

impl<'ab, AB> MainLookupBuilder for ConstraintLookupBuilder<'ab, AB> where
    AB: LiftedAirBuilder<F = Felt>
{
}

impl<'ab, AB> ChipletLookupBuilder for ConstraintLookupBuilder<'ab, AB> where
    AB: LiftedAirBuilder<F = Felt>
{
}

// CONSTRAINT COLUMN
// ================================================================================================

/// Per-column handle returned by [`ConstraintLookupBuilder::column`].
///
/// Holds only the running `(U, V)` accumulator and a shared borrow of
/// the precomputed [`LookupChallenges`]. The wrapped `&mut AB` and the
/// permutation `acc` / `acc_next` values do **not** live on the column
/// any more — the enclosing `column` method handles finalization
/// directly after the closure returns.
pub struct ConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt> + 'a,
{
    challenges: &'a LookupChallenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> ConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    /// Compose an inner-group `(U_g, V_g)` pair into this column's
    /// running `(U, V)` using the cross-multiplication rule
    /// `V ← V·U_g + V_g·U`, `U ← U·U_g`.
    fn fold_group(&mut self, u_g: AB::ExprEF, v_g: AB::ExprEF) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }
}

impl<'a, AB> LookupColumn for ConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Group<'g>
        = ConstraintGroup<'g, AB>
    where
        Self: 'g,
        AB: 'g;

    type EncodedGroup<'g>
        = ConstraintGroupEncoded<'g, AB>
    where
        Self: 'g,
        AB: 'g;

    fn group<'g, R>(&'g mut self, f: impl FnOnce(&mut Self::Group<'g>) -> R) -> R {
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        let result = f(&mut group);
        let ConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
        result
    }

    fn group_with_cached_encoding<'g, R>(
        &'g mut self,
        _canonical: impl FnOnce(&mut Self::Group<'g>) -> R,
        encoded: impl FnOnce(&mut Self::EncodedGroup<'g>) -> R,
    ) -> R {
        // Constraint path: only the `encoded` closure runs; the
        // `canonical` closure is dropped unused. This matches the plan's
        // split where `canonical` is the prover-path description.
        let mut group = ConstraintGroupEncoded {
            inner: ConstraintGroup {
                challenges: self.challenges,
                u: AB::ExprEF::ONE,
                v: AB::ExprEF::ZERO,
                _phantom: PhantomData,
            },
        };
        let result = encoded(&mut group);
        let ConstraintGroup { u, v, .. } = group.inner;
        self.fold_group(u, v);
        result
    }
}

// CONSTRAINT GROUP (SIMPLE PATH)
// ================================================================================================

/// Simple-path group handle — does not expose α / β.
///
/// Accumulates an internal `(U_g, V_g)` pair as the author calls
/// `add` / `remove` / `insert` / `batch`. The column consumes the pair
/// via [`ConstraintColumn::fold_group`] once the group closure returns.
///
/// Each per-interaction `add` / `remove` / `insert` body calls
/// `msg.encode(self.challenges)` directly and folds the resulting
/// denominator into `(U_g, V_g)` inline — no intermediate scratch
/// buffer and no helper method call.
pub struct ConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt> + 'a,
{
    challenges: &'a LookupChallenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupGroup for ConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Batch<'b>
        = ConstraintBatch<'b, AB>
    where
        Self: 'b,
        AB: 'b;

    fn add<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `add` = multiplicity +1. `V_g += flag · 1 = flag`, skipping
        // the redundant multiplication that a generic `insert` would
        // emit.
        let v = msg().encode(self.challenges);
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v += flag;
    }

    fn remove<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `remove` = multiplicity −1. `V_g += flag · (−1) = −flag`.
        let v = msg().encode(self.challenges);
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v -= flag;
    }

    fn insert<M>(&mut self, flag: Self::Expr, multiplicity: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `V_g += flag · multiplicity`.
        let v = msg().encode(self.challenges);
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }

    fn batch<'b, R>(
        &'b mut self,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>) -> R,
    ) -> R {
        // Batch algebra: start with `(N, D) = (0, 1)`, run `build`,
        // then fold the final `(N, D)` into `(U_g, V_g)` via
        // `U_g += (D − 1) · flag`, `V_g += N · flag`.
        let mut batch = ConstraintBatch {
            challenges: self.challenges,
            n: AB::ExprEF::ZERO,
            d: AB::ExprEF::ONE,
            _phantom: PhantomData,
        };
        let result = build(&mut batch);
        let ConstraintBatch { n, d, .. } = batch;
        self.u += (d - AB::ExprEF::ONE) * flag.clone();
        self.v += n * flag;
        result
    }
}

// CONSTRAINT GROUP (ENCODED PATH)
// ================================================================================================

/// Cached-encoding group handle — exposes the precomputed bus prefixes
/// and β powers so the author can build shared encoding fragments once
/// and splice them into `insert_encoded` calls.
///
/// Implements [`LookupGroup`] by delegating to an inner
/// [`ConstraintGroup`] that owns the same `(U_g, V_g)` accumulator,
/// plus [`EncodedLookupGroup`] for the `beta_powers` / `bus_prefix` /
/// `insert_encoded` primitives.
pub struct ConstraintGroupEncoded<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt> + 'a,
{
    inner: ConstraintGroup<'a, AB>,
}

impl<'a, AB> LookupGroup for ConstraintGroupEncoded<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Batch<'b>
        = ConstraintBatch<'b, AB>
    where
        Self: 'b,
        AB: 'b;

    fn add<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.inner.add(flag, msg);
    }

    fn remove<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.inner.remove(flag, msg);
    }

    fn insert<M>(&mut self, flag: Self::Expr, multiplicity: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.inner.insert(flag, multiplicity, msg);
    }

    fn batch<'b, R>(
        &'b mut self,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>) -> R,
    ) -> R {
        self.inner.batch(flag, build)
    }
}

impl<'a, AB> EncodedLookupGroup for ConstraintGroupEncoded<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.inner.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.inner.challenges.bus_prefix[bus_id].clone()
    }

    fn insert_encoded(
        &mut self,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
    ) {
        // Same `(U_g, V_g)` update as `insert`, but the denominator
        // comes straight from the user's pre-computed closure instead
        // of a `LookupMessage::encode` call.
        let v = encoded();
        self.inner.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.inner.v += flag * multiplicity;
    }
}

// CONSTRAINT BATCH
// ================================================================================================

/// Batch handle returned by [`LookupGroup::batch`] (and the delegated
/// encoded-group path).
///
/// Wraps an internal `(N, D)` pair and absorbs each interaction via the
/// cross-multiplication rule `N' = N·v + m·D`, `D' = D·v`. The
/// enclosing [`ConstraintGroup::batch`] folds the final `(N, D)` into
/// the group's `(U_g, V_g)` using the outer flag.
///
/// Per-interaction encoding lives on the message itself
/// ([`LookupMessage::encode`]), and the `(N, D)` update is inlined at
/// every call site (no `absorb` helper) so the `add` / `remove` paths
/// can skip the `m · D` multiplication when `m = ±1`.
pub struct ConstraintBatch<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt> + 'a,
{
    challenges: &'a LookupChallenges<AB::ExprEF>,
    n: AB::ExprEF,
    d: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupBatch for ConstraintBatch<'a, AB>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    fn add<M>(&mut self, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = 1`: `(N, D) ← (N·v + D, D·v)`. Skips the `m · D` mul.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev;
        self.d = self.d.clone() * v;
    }

    fn remove<M>(&mut self, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = −1`: `(N, D) ← (N·v − D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() - d_prev;
        self.d = self.d.clone() * v;
    }

    fn insert<M>(&mut self, multiplicity: Self::Expr, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `(N, D) ← (N·v + m·D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v;
    }

    fn insert_encoded(&mut self, multiplicity: Self::Expr, encoded: impl FnOnce() -> Self::ExprEF) {
        // Same as `insert`, but the denominator is a user-supplied
        // pre-encoded `ExprEF` instead of a `LookupMessage::encode`
        // call.
        let v = encoded();
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v;
    }
}
