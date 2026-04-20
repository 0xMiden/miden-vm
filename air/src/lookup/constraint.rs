//! Constraint-path adapter for the new closure-based lookup API.
//!
//! Implements [`LookupBuilder`] over any `LiftedAirBuilder`. The adapter
//! mirrors the column-accumulator algebra in the per-group `(U, V)` / per-batch `(N, D)`
//! running pairs and wraps it in the closure-based surface described by
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
//! and stores them in a [`Challenges<AB::ExprEF>`], which
//! precomputes both the β-power table (β⁰..β^(W-1)) and the bus-prefix
//! table (`bus_prefix[i] = α + (i + 1) · β^W`) sized from the
//! [`LookupAir`] passed to [`ConstraintLookupBuilder::new`]. The cached
//! challenges flow through the per-column / per-group handles by shared
//! reference, so each interaction sees the same precomputed tables
//! without reconstructing them.
//!
//! The permutation column slices are *not* cached — each
//! [`LookupBuilder::next_column`] call re-queries `ab.permutation()` to pick
//! up the current-row / next-row `VarEF` values. `ab.permutation()` is
//! cheap (it builds a window over references) and not caching keeps the
//! builder a four-field struct.

use core::marker::PhantomData;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{ExtensionBuilder, LiftedAirBuilder, WindowAccess};

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
    LookupMessage,
};

// CONSTRAINT LOOKUP BUILDER
// ================================================================================================

/// Constraint-path [`LookupBuilder`] over a wrapped [`LiftedAirBuilder`].
///
/// Construct via [`ConstraintLookupBuilder::new`]. The adapter caches the
/// precomputed challenges ([`Challenges`] sized from the
/// [`LookupAir`]) and a small column-index counter; the permutation row
/// slices are re-queried from the wrapped `&mut AB` on every
/// [`LookupBuilder::next_column`] call.
pub struct ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder + 'ab,
{
    ab: &'ab mut AB,
    challenges: Challenges<AB::ExprEF>,
    column_idx: usize,
}

impl<'ab, AB> ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder,
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
    /// a [`Challenges<AB::ExprEF>`] (= `crate::lookup::Challenges`) sized from
    /// `air.max_message_width()` / `air.num_bus_ids()`.
    pub fn new<A>(ab: &'ab mut AB, air: &A) -> Self
    where
        A: LookupAir<Self>,
    {
        let (alpha, beta): (AB::ExprEF, AB::ExprEF) = {
            let r = ab.permutation_randomness();
            (r[0].into(), r[1].into())
        };
        let challenges =
            Challenges::<AB::ExprEF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());

        Self { ab, challenges, column_idx: 0 }
    }
}

impl<'ab, AB> LookupBuilder for ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder,
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

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        _deg: Deg,
    ) -> R {
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

        // Pick up `acc` / `acc_next` from `ab.permutation()` and the committed
        // final from `ab.permutation_values()` now that the column borrow is released.
        let (acc, acc_next, committed_final) = {
            let mp = self.ab.permutation();
            let acc: AB::ExprEF = mp.current_slice()[self.column_idx].into();
            let acc_next: AB::ExprEF = mp.next_slice()[self.column_idx].into();
            let committed_final: AB::ExprEF =
                self.ab.permutation_values()[self.column_idx].clone().into();
            (acc, acc_next, committed_final)
        };

        // LogUp boundary + transition + last-row constraints.
        //
        //   when_first_row:  acc[0] == 0
        //   when_transition: (acc_next - acc) · U − V == 0          (rows 0..N-2)
        //   when_last_row:   acc == committed_final
        //
        // ## Last-row binding
        //
        // The natural closing check is `when_last_row: (committed_final − acc) · U − V`,
        // but `when_last_row`'s selector multiplies the expression by an extra polynomial
        // factor that pushes M_2+5 to degree 10, exceeding the degree-9 budget.
        //
        // Our model assumes the last row of the AIR never fires any interactions: on the
        // last row `U = 1, V = 0` for every column. This allows a lower-degree closing
        // constraint — simply binding the accumulator to the committed final value:
        //
        //   `when_last_row: acc − committed_final == 0`    (degree 1 + selector)
        let delta_transition = acc_next - acc.clone();
        self.ab.when_first_row().assert_zero_ext(acc.clone());
        self.ab.when_transition().assert_zero_ext(delta_transition * u - v);
        self.ab.when_last_row().assert_eq_ext(acc, committed_final);

        self.column_idx += 1;
        result
    }
}

// CONSTRAINT COLUMN
// ================================================================================================

/// Per-column handle returned by [`ConstraintLookupBuilder::next_column`].
///
/// Holds only the running `(U, V)` accumulator and a shared borrow of
/// the precomputed [`Challenges`]. The wrapped `&mut AB` and the
/// permutation `acc` / `acc_next` values do **not** live on the column
/// any more — the enclosing `column` method handles finalization
/// directly after the closure returns.
pub struct ConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> ConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder,
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
    AB: LiftedAirBuilder,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Group<'g>
        = ConstraintGroup<'g, AB>
    where
        Self: 'g,
        AB: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        f(&mut group);
        let ConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        _canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        // Constraint path: only the `encoded` closure runs; the
        // `canonical` closure is dropped unused. This matches the plan's
        // split where `canonical` is the prover-path description.
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        encoded(&mut group);
        let ConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }
}

// CONSTRAINT GROUP
// ================================================================================================

/// Per-group handle for the constraint path.
///
/// Implements [`LookupGroup`] with working `beta_powers`, `bus_prefix`,
/// and `insert_encoded` overrides (the constraint path always has the
/// precomputed challenge tables available).
///
/// Accumulates an internal `(U_g, V_g)` pair as the author calls
/// `add` / `remove` / `insert` / `batch`. The column consumes the pair
/// via `ConstraintColumn::fold_group` once the group closure returns.
///
/// Each per-interaction `add` / `remove` / `insert` body calls
/// `msg.encode(self.challenges)` directly and folds the resulting
/// denominator into `(U_g, V_g)` inline — no intermediate scratch
/// buffer and no helper method call.
pub struct ConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupGroup for ConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Batch<'b>
        = ConstraintBatch<'b, AB>
    where
        Self: 'b,
        AB: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Self::Expr, msg: impl FnOnce() -> M, _deg: Deg)
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

    fn remove<M>(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        msg: impl FnOnce() -> M,
        _deg: Deg,
    ) where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `remove` = multiplicity −1. `V_g += flag · (−1) = −flag`.
        let v = msg().encode(self.challenges);
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v -= flag;
    }

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
        // General case: `V_g += flag · multiplicity`.
        let v = msg().encode(self.challenges);
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
    }

    fn batch<'b>(
        &'b mut self,
        _name: &'static str,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'b>),
        _deg: Deg,
    ) {
        // Batch algebra: start with `(N, D) = (0, 1)`, run `build`,
        // then fold the final `(N, D)` into `(U_g, V_g)` via
        // `U_g += (D − 1) · flag`, `V_g += N · flag`.
        let mut batch = ConstraintBatch {
            challenges: self.challenges,
            n: AB::ExprEF::ZERO,
            d: AB::ExprEF::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let ConstraintBatch { n, d, .. } = batch;
        self.u += (d - AB::ExprEF::ONE) * flag.clone();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id].clone()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same `(U_g, V_g)` update as `insert`, but the denominator
        // comes straight from the user's pre-computed closure instead
        // of a `LookupMessage::encode` call.
        let v = encoded();
        self.u += (v - AB::ExprEF::ONE) * flag.clone();
        self.v += flag * multiplicity;
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
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    n: AB::ExprEF,
    d: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupBatch for ConstraintBatch<'a, AB>
where
    AB: LiftedAirBuilder,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    fn add<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = 1`: `(N, D) ← (N·v + D, D·v)`. Skips the `m · D` mul.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev;
        self.d = self.d.clone() * v;
    }

    fn remove<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = −1`: `(N, D) ← (N·v − D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() - d_prev;
        self.d = self.d.clone() * v;
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `(N, D) ← (N·v + m·D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v;
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same as `insert`, but the denominator is a user-supplied
        // pre-encoded `ExprEF` instead of a `LookupMessage::encode`
        // call.
        let v = encoded();
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v;
    }
}
