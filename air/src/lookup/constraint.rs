//! Constraint-path adapter for the closure-based lookup API.
//!
//! Implements [`LookupBuilder`] over any `LiftedAirBuilder`. Each column's
//! constraints are emitted inline during [`LookupBuilder::next_column`].
//!
//! ## LogUp constraint structure
//!
//! The aux trace has one **accumulator** (col 0) and several **fraction columns** (cols 1+).
//! Each bus interaction on row `r` contributes a rational term `mᵢ / dᵢ` to one of the
//! columns. Because the verifier cannot check rational equations directly, each column
//! stores the *numerator–denominator pair* `(Nᵢ, Dᵢ)` — the cross-multiplied sum of all
//! interactions assigned to that column on row `r`. The constraints then check:
//!
//! - **Fraction columns** (i > 0): `Dᵢ · acc[i] - Nᵢ = 0` on transition rows. This asserts that the
//!   prover-supplied value `acc[i]` equals `Nᵢ/Dᵢ`, the sum of fractions for column `i` on that
//!   row.
//!
//! - **Accumulator** (col 0): the single running sum across the entire trace.
//!   - `when_first:      acc[0] = 0` — starts at zero.
//!   - `when_transition: D₀ · (acc_next[0] - Σᵢ acc[i]) - N₀ = 0` — the next accumulator value
//!     equals the current value plus every column's per-row contribution (including col 0's own
//!     interactions folded via `N₀/D₀`).
//!   - `when_last:       acc[0] = committed_final` — binds the final sum to the value committed
//!     during the Fiat-Shamir transcript, ensuring the global LogUp sum is correct.
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
//! builder small.

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
/// Column 0 is the sole running-sum accumulator; columns 1+ are fraction columns.
/// All constraints are emitted inline during [`LookupBuilder::next_column`].
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

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        _deg: Deg,
    ) -> R {
        // Open the column with an empty `(U, V) = (1, 0)` accumulator.
        // The column only holds a shared borrow of the challenges and
        // the two running-pair slots — the `&mut AB` stays on the
        // builder and is only reached back into for the constraint
        // emission below.
        let mut col = ConstraintColumn {
            challenges: &self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        let ConstraintColumn { u, v, .. } = col;

        // Pick up permutation column values now that the column borrow is released.
        let col_idx = self.column_idx;
        self.column_idx += 1;

        if col_idx == 0 {
            let (acc, acc_next, committed_final) = {
                let mp = self.ab.permutation();
                let acc: AB::ExprEF = mp.current_slice()[0].into();
                let acc_next: AB::ExprEF = mp.next_slice()[0].into();
                let committed_final: AB::ExprEF = self.ab.permutation_values()[0].clone().into();
                (acc, acc_next, committed_final)
            };

            // Σ_i acc[i] across all permutation columns.
            let all_curr_sum = {
                let mp = self.ab.permutation();
                let current = mp.current_slice();
                let mut sum: AB::ExprEF = current[0].into();
                for &aux_i in &current[1..] {
                    sum += aux_i.into();
                }
                sum
            };

            //   when_first:      acc[0] = 0
            //   when_transition: D₀ · (acc_next[0] - Σᵢ acc[i]) - N₀ = 0
            //   when_last:       acc[0] = committed_final
            //
            // The natural closing check would fold the last row's interactions into the
            // boundary constraint, but `when_last_row`'s selector adds a polynomial factor
            // that would push some columns past the degree budget. Our model assumes the
            // last row never fires any interactions (U = 1, V = 0), so we use the
            // lower-degree form: `acc − committed_final = 0`. The fraction columns below
            // enforce this algebraically via `when_last_row acc[i] = 0`.
            self.ab.when_first_row().assert_zero_ext(acc.clone());
            self.ab.when_transition().assert_zero_ext(u * (acc_next - all_curr_sum) - v);
            self.ab.when_last_row().assert_eq_ext(acc, committed_final);
        } else {
            //   when_transition: Dᵢ · acc[i] - Nᵢ = 0
            //   when_last:       acc[i] = 0  — no bus may fire on the padding row; this
            //                                  is the invariant col 0's closing check
            //                                  assumes.
            let acc_curr: AB::ExprEF = {
                let mp = self.ab.permutation();
                mp.current_slice()[col_idx].into()
            };
            self.ab.when_transition().assert_zero_ext(u * acc_curr.clone() - v);
            self.ab.when_last_row().assert_zero_ext(acc_curr);
        }

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
/// — the enclosing `next_column` method handles finalization
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

/// Batch handle returned by [`LookupGroup::batch`].
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
