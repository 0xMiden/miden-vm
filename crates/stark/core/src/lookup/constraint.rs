//! Constraint-path adapter for the closure-based LogUp API.
//!
//! The adapter turns each row's interactions into cross-multiplied `(V, U)` pairs. Fraction
//! columns check `U · aux − V = 0`; column 0 is the running accumulator.
//!
//! ## LogUp constraint structure
//!
//! The aux trace has one **accumulator** (col 0) and several **fraction columns** (cols 1+).
//! Each bus interaction on row `r` contributes a rational term `mᵢ / dᵢ` to one of the
//! columns. Because the verifier cannot check rational equations directly, each column
//! stores the *numerator–denominator pair* `(Nᵢ, Dᵢ)` — the cross-multiplied sum of all
//! interactions assigned to that column on row `r`. The constraints then check:
//!
//! - Fraction columns (i > 0): `Dᵢ · acc[i] - Nᵢ = 0` on every row. This binds `acc[i]` to `Nᵢ/Dᵢ`,
//!   the row's fraction sum for column `i`.
//!
//! - **Accumulator** (col 0): a normalized cyclic running sum.
//!   - `when_first: acc[0] = 0` anchors the witness.
//!   - On every row, including the last-to-first edge, `D₀ · (acc_next[0] - Σᵢ acc[i] +
//!     sigma_prime) - N₀ = 0`.
//!   - The committed value is `sigma_prime = sigma / n`. Summing the cyclic recurrence over all `n`
//!     rows binds `n · sigma_prime` to the trace's global LogUp sum `sigma`.
//!
//! ## Algebra location
//!
//! Per Amendment B the per-interaction encoding lives inside each
//! [`LookupMessage::encode`] body, so the adapter carries **no scratch
//! buffer**: every `add` / `remove` / `insert` body is a two-liner that
//! calls `msg.encode(self.challenges)` and absorbs the resulting
//! `AB::ExprEF` denominator into the running `(V, U)` (group) or
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

use p3_field::{Algebra, PrimeCharacteristicRing};

use super::{
    Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
    LookupMessage,
};
use crate::air::{LiftedAirBuilder, WindowAccess};

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
    num_columns: usize,
}

impl<'ab, AB> ConstraintLookupBuilder<'ab, AB>
where
    AB: LiftedAirBuilder,
{
    pub fn new<A>(ab: &'ab mut AB, air: &A) -> Self
    where
        A: LookupAir<Self>,
    {
        let num_columns = air.column_shape().len();
        assert!(num_columns > 0, "a LogUp argument must declare at least one column");
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
            num_columns,
        }
    }

    /// Finish one symbolic lookup evaluation and validate its declared column shape.
    pub fn finish(self) {
        assert_eq!(
            self.column_idx, self.num_columns,
            "LookupAir::eval emitted {} columns, but column_shape declares {}",
            self.column_idx, self.num_columns,
        );
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
    type PreprocessedWindow = AB::PreprocessedWindow;

    type Column<'a>
        = ConstraintColumn<'a, AB::Expr, AB::ExprEF>
    where
        Self: 'a,
        AB: 'a;

    fn main(&self) -> Self::MainWindow {
        self.ab.main()
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
        // Open the column with an empty `(V, U) = (0, 1)` accumulator.
        // The column only holds a shared borrow of the challenges and
        // the two running-pair slots — the `&mut AB` stays on the
        // builder and is only reached back into for the constraint
        // emission below.
        let mut col = ConstraintColumn::new(&self.challenges);
        let result = f(&mut col);
        let (u, v) = col.into_pair();

        // Pick up permutation column values now that the column borrow is released.
        let col_idx = self.column_idx;
        assert!(
            col_idx < self.num_columns,
            "LookupAir::eval emitted more columns than column_shape declares ({})",
            self.num_columns,
        );
        self.column_idx += 1;

        let (anchor, relation) = {
            let window = self.ab.permutation();
            let current = window.current_slice();
            assert!(
                current.len() >= self.num_columns,
                "auxiliary trace has {} columns, but LogUp declares {}",
                current.len(),
                self.num_columns,
            );
            let (band, accumulator) = if col_idx == 0 {
                (
                    &current[..self.num_columns],
                    Some(AccumulatorInputs {
                        next: window.next_slice()[0].into(),
                        sigma: self.ab.permutation_values()[0].clone().into(),
                        first: self.ab.is_first_row(),
                    }),
                )
            } else {
                (&current[col_idx..col_idx + 1], None)
            };
            column_constraints(u, v, band.iter().copied().map(Into::into), accumulator)
        };
        if let Some(anchor) = anchor {
            self.ab.assert_zero_ext(anchor);
        }
        self.ab.assert_zero_ext(relation);

        result
    }
}

/// Inputs used only when closing the accumulator column.
pub(super) struct AccumulatorInputs<E, EE> {
    pub next: EE,
    pub sigma: EE,
    pub first: E,
}

/// One finalization formula shared by old and native constraint adapters.
///
/// `current` contains the declared LogUp prefix for the accumulator, or just the selected
/// fraction-column value otherwise. Trailing auxiliary registers never enter the recurrence.
/// The optional anchor precedes the all-row equation and retains the old `acc * first` order.
pub(super) fn column_constraints<E, EE>(
    u: EE,
    v: EE,
    mut current: impl Iterator<Item = EE>,
    accumulator: Option<AccumulatorInputs<E, EE>>,
) -> (Option<EE>, EE)
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    let acc = current.next().expect("a lookup column must supply its current auxiliary value");
    if let Some(AccumulatorInputs { next, sigma, first }) = accumulator {
        let mut sum = acc.dup();
        for value in current {
            sum += value;
        }
        // This remains unfiltered on the last-to-first edge. Summing over all rows gives
        // n*sigma = the global LogUp sum; the anchor fixes the additive constant.
        (Some(acc * first), u * (next - sum + sigma) - v)
    } else {
        (None, u * acc - v)
    }
}

// CONSTRAINT COLUMN
// ================================================================================================

/// Per-column arithmetic shared by legacy and native constraint adapters.
///
/// Holds only the running `(V, U)` accumulator and shared precomputed challenges. Inputs and
/// mutable assertion emission stay with the top-level adapter, outside this callback's borrow.
pub struct ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    u: EE,
    v: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    pub(super) fn new(challenges: &'a Challenges<EE>) -> Self {
        Self {
            challenges,
            u: EE::ONE,
            v: EE::ZERO,
            _phantom: PhantomData,
        }
    }

    pub(super) fn into_pair(self) -> (EE, EE) {
        (self.u, self.v)
    }

    /// Compose an inner group with `V ← V·U_g + V_g·U`, `U ← U·U_g`.
    fn fold_group(&mut self, u_g: EE, v_g: EE) {
        self.v = self.v.dup() * u_g.dup() + v_g * self.u.dup();
        self.u = self.u.dup() * u_g;
    }
}

impl<'a, E, EE> LookupColumn for ConstraintColumn<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    type Group<'g>
        = ConstraintGroup<'g, E, EE>
    where
        Self: 'g,
        E: 'g,
        EE: 'g;

    fn group<'g>(
        &'g mut self,
        _name: &'static str,
        f: impl FnOnce(&mut Self::Group<'g>),
        _deg: Deg,
    ) {
        let mut group = ConstraintGroup {
            challenges: self.challenges,
            u: EE::ONE,
            v: EE::ZERO,
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
            u: EE::ONE,
            v: EE::ZERO,
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
/// Accumulates an internal `(V_g, U_g)` pair as the author calls
/// `add` / `remove` / `insert` / `batch`. The column consumes the pair
/// via `ConstraintColumn::fold_group` once the group closure returns.
///
/// Each per-interaction `add` / `remove` / `insert` body calls
/// `msg.encode(self.challenges)` directly and folds the resulting
/// denominator into `(V_g, U_g)` inline — no intermediate scratch
/// buffer and no helper method call.
pub struct ConstraintGroup<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    u: EE,
    v: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> LookupGroup for ConstraintGroup<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    type Batch<'b>
        = ConstraintBatch<'b, E, EE>
    where
        Self: 'b,
        E: 'b,
        EE: 'b;

    fn add<M>(&mut self, _name: &'static str, flag: Self::Expr, msg: impl FnOnce() -> M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `add` = multiplicity +1. `V_g += flag · 1 = flag`, skipping
        // the redundant multiplication that a generic `insert` would
        // emit.
        let v = msg().encode(self.challenges);
        self.u += (v - EE::ONE) * flag.dup();
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
        self.u += (v - EE::ONE) * flag.dup();
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
        self.u += (v - EE::ONE) * flag.dup();
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
        // then fold the final `(N, D)` into `(V_g, U_g)` via
        // `V_g += N · flag`, `U_g += (D − 1) · flag`.
        let mut batch = ConstraintBatch {
            challenges: self.challenges,
            n: EE::ZERO,
            d: EE::ONE,
            _phantom: PhantomData,
        };
        build(&mut batch);
        let ConstraintBatch { n, d, .. } = batch;
        self.u += (d - EE::ONE) * flag.dup();
        self.v += n * flag;
    }

    fn beta_powers(&self) -> &[Self::ExprEF] {
        &self.challenges.beta_powers[..]
    }

    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        self.challenges.bus_prefix[bus_id].dup()
    }

    fn insert_encoded(
        &mut self,
        _name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        // Same `(V_g, U_g)` update as `insert`, but the denominator
        // comes straight from the user's pre-computed closure instead
        // of a `LookupMessage::encode` call.
        let v = encoded();
        self.u += (v - EE::ONE) * flag.dup();
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
/// the group's `(V_g, U_g)` using the outer flag.
///
/// Per-interaction encoding lives on the message itself
/// ([`LookupMessage::encode`]), and the `(N, D)` update is inlined at
/// every call site (no `absorb` helper) so the `add` / `remove` paths
/// can skip the `m · D` multiplication when `m = ±1`.
pub struct ConstraintBatch<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    challenges: &'a Challenges<EE>,
    n: EE,
    d: EE,
    _phantom: PhantomData<E>,
}

impl<'a, E, EE> LookupBatch for ConstraintBatch<'a, E, EE>
where
    E: PrimeCharacteristicRing,
    EE: Algebra<E>,
{
    type Expr = E;
    type ExprEF = EE;

    fn add<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = 1`: `(N, D) ← (N·v + D, D·v)`. Skips the `m · D` mul.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev;
        self.d = self.d.dup() * v;
    }

    fn remove<M>(&mut self, _name: &'static str, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // `m = −1`: `(N, D) ← (N·v − D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() - d_prev;
        self.d = self.d.dup() * v;
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Self::Expr, msg: M, _deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        // General case: `(N, D) ← (N·v + m·D, D·v)`.
        let v = msg.encode(self.challenges);
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev * multiplicity;
        self.d = self.d.dup() * v;
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
        let d_prev = self.d.dup();
        self.n = self.n.dup() * v.dup() + d_prev * multiplicity;
        self.d = self.d.dup() * v;
    }
}
