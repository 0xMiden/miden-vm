//! Constraint-path adapter for the closure-based lookup API.
//!
//! Implements [`LookupBuilder`] over any `LiftedAirBuilder`. The adapter
//! accumulates per-column `(U, V)` pairs through the closure API, then emits
//! two kinds of constraints depending on the column role:
//!
//! - **Fraction columns** (non-running-sum): `D_i * aux_next_i - N_i = 0` on transition rows. Uses
//!   `aux_next` because the aux trace is offset by 1 from the main trace: `aux[0]` is the zero
//!   initial condition, `aux[r+1]` holds the value for main-trace row `r`.
//! - **Running-sum columns**: boundary + transition constraints that reference the fraction
//!   columns' `aux_next` values, emitted in [`ConstraintLookupBuilder::finalize`] after all columns
//!   have been processed.
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

use alloc::vec::Vec;
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
/// After calling `air.eval(&mut builder)`, call [`finalize`](Self::finalize) to emit the
/// running-sum columns' boundary and transition constraints.
pub struct ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder + 'ab,
{
    ab: &'ab mut AB,
    challenges: Challenges<AB::ExprEF>,
    column_idx: usize,
    running_sum_set: Vec<usize>,
    fraction_map: Vec<Vec<usize>>,
    column_shape: Vec<usize>,
    running_sum_last_row_acc: AB::ExprEF,
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

        let running_sum_set = air.running_sum_columns().to_vec();
        let fraction_map: Vec<Vec<usize>> = running_sum_set
            .iter()
            .map(|&rs| air.fraction_columns_for(rs).to_vec())
            .collect();
        let column_shape = air.column_shape().to_vec();

        Self {
            ab,
            challenges,
            column_idx: 0,
            running_sum_set,
            fraction_map,
            column_shape,
            running_sum_last_row_acc: AB::ExprEF::ZERO,
        }
    }

    fn is_running_sum(&self, col: usize) -> bool {
        self.running_sum_set.contains(&col)
    }

    /// Emit the final running-sum boundary assertion after all columns have been processed.
    ///
    /// Per-column running-sum constraints are emitted inline in `next_column`; here we only check:
    /// `when_last_row: Σ_j acc_j == committed_final`.
    pub fn finalize(self) {
        let Self { ab, running_sum_last_row_acc, .. } = self;
        let committed_final: AB::ExprEF = ab.permutation_values()[0].clone().into();
        ab.when_last_row().assert_eq_ext(running_sum_last_row_acc, committed_final);
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
        let mut col = ConstraintColumn {
            challenges: &self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        let ConstraintColumn { u, v, .. } = col;

        let col_idx = self.column_idx;
        self.column_idx += 1;

        let is_padding = self.column_shape.get(col_idx).copied() == Some(0);

        if self.is_running_sum(col_idx) {
            // Running-sum column: emit boundary/transition constraints immediately and
            // accumulate its last-row value into the single committed boundary assertion.
            let rs_pos = self.running_sum_set.iter().position(|&c| c == col_idx).unwrap();
            let (acc, acc_next, frac_sum) = {
                let mp = self.ab.permutation();
                let acc: AB::ExprEF = mp.current_slice()[col_idx].into();
                let acc_next: AB::ExprEF = mp.next_slice()[col_idx].into();
                let next = mp.next_slice();
                let mut sum = AB::ExprEF::ZERO;
                for &frac_col in &self.fraction_map[rs_pos] {
                    let aux_i: AB::ExprEF = next[frac_col].into();
                    sum += aux_i;
                }
                (acc, acc_next, sum)
            };

            // U_j * (acc_next_j - acc_j - Σ frac_aux_j) - V_j == 0
            let delta = acc_next - acc.clone() - frac_sum;
            self.ab.when_first_row().assert_zero_ext(acc.clone());
            self.ab.when_transition().assert_zero_ext(delta * u - v);
            self.running_sum_last_row_acc += acc;
        } else if !is_padding {
            // Fraction column: U_i * aux_next_i - V_i = 0 on transition rows.
            // Uses aux_next because aux[0] is the zero initial condition and
            // aux[r+1] holds the per-row fraction for main-trace row r.
            let acc_next: AB::ExprEF = {
                let mp = self.ab.permutation();
                mp.next_slice()[col_idx].into()
            };

            self.ab.when_transition().assert_zero_ext(u * acc_next - v);
        }
        // Padding column (shape 0): no constraints.

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
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev;
        self.d = self.d.clone() * v;
    }

    fn remove<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        let v = msg.encode(self.challenges);
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() - d_prev;
        self.d = self.d.clone() * v;
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
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
        let v = encoded();
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * multiplicity;
        self.d = self.d.clone() * v;
    }
}
