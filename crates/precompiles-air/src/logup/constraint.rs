//! Constraint-path adapter for normalized cyclic LogUp running sums.
//!
//! The fraction algebra and centered recurrence match the Miden VM lookup implementation. This
//! builder also presents preprocessed and main columns as one lookup window and limits the
//! running-sum fold to the declared LogUp columns, excluding trailing auxiliary registers from
//! the bus balance.

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::field::PrimeCharacteristicRing;
use miden_lifted_air::{BaseAir, ExtensionBuilder, LiftedAirBuilder, WindowAccess};

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
    LookupMessage,
};

// COMBINED MAIN WINDOW
// ================================================================================================
//
// The LogUp lookup eval reads its operands through `LookupBuilder::main()`.
// A chiplet with **preprocessed** (verifier-known) columns — e.g.
// BytePairLut's fixed `(a, b, c)` table — needs those columns visible to
// the eval alongside its witness `main` columns. But
// [`WindowAccess::current_slice`] must return one contiguous slice, and the
// preprocessed and main rows live in separate committed traces. So for a
// preprocessed chiplet we present an **owned** `[preprocessed ++ main]`
// concatenation; chiplets without preprocessed columns (the common case)
// pass the wrapped `main` window straight through with no copy.
//
// The matching prover-side trace is built the same way (the chiplet's
// `build_aux` prepends its reconstructed preprocessed table to the witness
// main trace), so both paths read identical column indices.

/// Owned `[preprocessed ++ main]` two-row window. Copies the joined rows
/// (cells are `Copy`) so it satisfies [`WindowAccess`]'s contiguous-slice
/// contract over two separate source windows.
#[derive(Clone)]
pub struct CombinedWindow<T> {
    current: Vec<T>,
    next: Vec<T>,
}

impl<T: Copy> CombinedWindow<T> {
    fn new<P, M>(preprocessed: &P, main: &M) -> Self
    where
        P: WindowAccess<T>,
        M: WindowAccess<T>,
    {
        let join = |p: &[T], m: &[T]| {
            let mut v = Vec::with_capacity(p.len() + m.len());
            v.extend_from_slice(p);
            v.extend_from_slice(m);
            v
        };
        Self {
            current: join(preprocessed.current_slice(), main.current_slice()),
            next: join(preprocessed.next_slice(), main.next_slice()),
        }
    }
}

impl<T> WindowAccess<T> for CombinedWindow<T> {
    fn current_slice(&self) -> &[T] {
        &self.current
    }

    fn next_slice(&self) -> &[T] {
        &self.next
    }
}

/// The window [`CyclicConstraintLookupBuilder::main`] presents to the
/// lookup eval: the wrapped builder's main window verbatim, or — for a
/// chiplet declaring preprocessed columns — an owned `[preprocessed ++
/// main]` concatenation so the eval can read the fixed table inline.
#[derive(Clone)]
pub enum LookupMainWindow<W, T> {
    /// No preprocessed columns: the wrapped `main` window, unchanged.
    Plain(W),
    /// `[preprocessed ++ main]`, owned (see [`CombinedWindow`]).
    Combined(CombinedWindow<T>),
}

impl<W, T> WindowAccess<T> for LookupMainWindow<W, T>
where
    W: WindowAccess<T>,
{
    fn current_slice(&self) -> &[T] {
        match self {
            LookupMainWindow::Plain(w) => w.current_slice(),
            LookupMainWindow::Combined(c) => c.current_slice(),
        }
    }

    fn next_slice(&self) -> &[T] {
        match self {
            LookupMainWindow::Plain(w) => w.next_slice(),
            LookupMainWindow::Combined(c) => c.next_slice(),
        }
    }
}

// CYCLIC CONSTRAINT LOOKUP BUILDER
// ================================================================================================

/// Constraint-path [`LookupBuilder`] over a wrapped [`LiftedAirBuilder`].
///
/// Column 0 is the sole centered running-sum accumulator; columns 1+ are fraction columns. All
/// constraints are emitted inline during [`LookupBuilder::next_column`] using the normalized
/// cyclic form described in [`super`].
pub struct CyclicConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder + 'ab,
{
    ab: &'ab mut AB,
    challenges: Challenges<AB::ExprEF>,
    column_idx: usize,
    /// Number of LogUp auxiliary columns. The column-0 recurrence folds in only
    /// `current[1..num_logup_cols]`, excluding any trailing auxiliary registers.
    num_logup_cols: usize,
    /// Whether [`main`](LookupBuilder::main) must combine preprocessed and witness columns.
    has_preprocessed: bool,
}

impl<'ab, AB> CyclicConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder,
{
    pub fn new<A>(ab: &'ab mut AB, air: &A) -> Self
    where
        A: BaseAir<AB::F> + LookupAir<Self>,
    {
        let num_logup_cols = air.num_columns();
        let has_preprocessed = air.preprocessed_width() > 0;
        let (alpha, beta): (AB::ExprEF, AB::ExprEF) = {
            let r = ab.permutation_randomness();
            (r[0].into(), r[1].into())
        };
        let challenges =
            Challenges::<AB::ExprEF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());

        Self {
            ab,
            challenges,
            column_idx: 0,
            num_logup_cols,
            has_preprocessed,
        }
    }
}

impl<'ab, AB> LookupBuilder for CyclicConstraintLookupBuilder<'ab, AB>
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

    type MainWindow = LookupMainWindow<AB::MainWindow, AB::Var>;
    type PreprocessedWindow = AB::PreprocessedWindow;

    type Column<'a>
        = CyclicConstraintColumn<'a, AB>
    where
        Self: 'a,
        AB: 'a;

    fn main(&self) -> Self::MainWindow {
        // Splice in preprocessed columns when the AIR declares them, so the
        // lookup eval reads `[preprocessed ++ main]` (e.g. BytePairLut's
        // fixed table). Gated on `has_preprocessed` rather than probing the
        // window: a no-preprocessed AIR must not touch `ab.preprocessed()`
        // (the `SymbolicAirBuilder` panics on its 0-row window), so the
        // common case is a no-copy pass-through.
        if self.has_preprocessed {
            LookupMainWindow::Combined(CombinedWindow::new(self.ab.preprocessed(), &self.ab.main()))
        } else {
            LookupMainWindow::Plain(self.ab.main())
        }
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.ab.preprocessed()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.ab.periodic_values()
    }

    fn next_column<'a, R>(
        &'a mut self,
        f: impl FnOnce(&mut Self::Column<'a>) -> R,
        _deg: Deg,
    ) -> R {
        let mut col = CyclicConstraintColumn {
            challenges: &self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        let result = f(&mut col);
        let CyclicConstraintColumn { u, v, .. } = col;

        let col_idx = self.column_idx;
        self.column_idx += 1;

        if col_idx == 0 {
            // Centered cyclic running sum. `sigma_prime = sigma / n` lives at
            // `permutation_values()[0]`:
            //   when_first: acc[0] = 0
            //   every row:  D₀·(acc_next[0] − Σ_{i<L} acc[i] + sigma_prime) − N₀ = 0
            // The permutation window wraps on the last row, so summing the recurrence proves
            // `n * sigma_prime = sigma` while including last-row interactions.
            let (acc, acc_next, sigma_prime) = {
                let mp = self.ab.permutation();
                let acc: AB::ExprEF = mp.current_slice()[0].into();
                let acc_next: AB::ExprEF = mp.next_slice()[0].into();
                let sigma_prime: AB::ExprEF = self.ab.permutation_values()[0].clone().into();
                (acc, acc_next, sigma_prime)
            };

            // Sum only the LogUp columns. Trailing auxiliary registers remain independently
            // constrained and do not contribute to the cross-AIR bus balance.
            let num_logup_cols = self.num_logup_cols;
            let all_curr_sum = {
                let mp = self.ab.permutation();
                let current = mp.current_slice();
                let mut sum: AB::ExprEF = current[0].into();
                for &aux_i in &current[1..num_logup_cols] {
                    sum += aux_i.into();
                }
                sum
            };

            self.ab.when_first_row().assert_zero_ext(acc);
            self.ab.assert_zero_ext(u * (acc_next - all_curr_sum + sigma_prime) - v);
        } else {
            // Fraction columns are constrained on every row, including the last.
            let acc_curr: AB::ExprEF = {
                let mp = self.ab.permutation();
                mp.current_slice()[col_idx].into()
            };
            self.ab.assert_zero_ext(u * acc_curr - v);
        }

        result
    }
}

// CYCLIC CONSTRAINT COLUMN
// ================================================================================================

/// Per-column handle returned by
/// [`CyclicConstraintLookupBuilder::next_column`].
///
/// Holds one column's cross-multiplied `(V, U)` fraction accumulator.
pub struct CyclicConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> CyclicConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder,
{
    fn fold_group(&mut self, u_g: AB::ExprEF, v_g: AB::ExprEF) {
        self.v = self.v.clone() * u_g.clone() + v_g * self.u.clone();
        self.u = self.u.clone() * u_g;
    }
}

impl<'a, AB> LookupColumn for CyclicConstraintColumn<'a, AB>
where
    AB: LiftedAirBuilder,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Group<'g>
        = CyclicConstraintGroup<'g, AB>
    where
        Self: 'g,
        AB: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = CyclicConstraintGroup {
            challenges: self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        f(&mut group);
        let CyclicConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }

    fn group_with_cached_encoding<'g>(
        &'g mut self,
        _name: &'static str,
        _canonical: impl FnOnce(&mut Self::Group<'g>),
        encoded: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = CyclicConstraintGroup {
            challenges: self.challenges,
            u: AB::ExprEF::ONE,
            v: AB::ExprEF::ZERO,
            _phantom: PhantomData,
        };
        encoded(&mut group);
        let CyclicConstraintGroup { u, v, .. } = group;
        self.fold_group(u, v);
    }
}

// CYCLIC CONSTRAINT GROUP
// ================================================================================================

/// Holds one group's cross-multiplied `(V, U)` fraction accumulator.
pub struct CyclicConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    u: AB::ExprEF,
    v: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupGroup for CyclicConstraintGroup<'a, AB>
where
    AB: LiftedAirBuilder,
{
    type Expr = AB::Expr;
    type ExprEF = AB::ExprEF;

    type Batch<'b>
        = CyclicConstraintBatch<'b, AB>
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
        let mut batch = CyclicConstraintBatch {
            challenges: self.challenges,
            n: AB::ExprEF::ZERO,
            d: AB::ExprEF::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let CyclicConstraintBatch { n, d, .. } = batch;
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

// CYCLIC CONSTRAINT BATCH
// ================================================================================================

/// Batch handle returned by [`LookupGroup::batch`].
pub struct CyclicConstraintBatch<'a, AB>
where
    AB: LiftedAirBuilder + 'a,
{
    challenges: &'a Challenges<AB::ExprEF>,
    n: AB::ExprEF,
    d: AB::ExprEF,
    _phantom: PhantomData<AB>,
}

impl<'a, AB> LookupBatch for CyclicConstraintBatch<'a, AB>
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
