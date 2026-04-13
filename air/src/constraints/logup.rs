//! LogUp rational-fraction algebra for bus constraint packing.
//!
//! Provides three structs mirroring the LogUp accumulator algebra:
//!
//! 1. [`Batch`] — simultaneous interactions normalized to `N / D`
//! 2. [`RationalSet`] — mutually exclusive batches compressed to `V / U` via selector gating
//! 3. [`Column`] — independent sets combined by clearing cross-denominators
//!
//! And two traits for generic interaction description:
//!
//! 4. [`InteractionSink`] — abstraction over the accumulation backend (constraints vs prover)
//! 5. [`InteractionGroup`] — a group of related interactions with optional constraint optimization
//!
//! The final constraint emitted per column is `Δ · U − V = 0` where `Δ = acc_next − acc`.
//!
//! See `docs/src/design/bus_packing_summary.md` §1–7 for the full derivation.
//! See `docs/src/design/bus_api_design_notes.md` for the interaction group design.

use core::marker::PhantomData;

use miden_core::field::{Algebra, PrimeCharacteristicRing};
use miden_crypto::stark::air::{ExtensionBuilder, LiftedAirBuilder};

use super::logup_msg::LogUpMessage;
use crate::{Felt, trace::Challenges};

// BATCH OF SIMULTANEOUS INTERACTIONS
// ================================================================================================

/// A batch of simultaneously active interactions, normalized to the fraction `N / D`.
///
/// `E` is the base-field expression type (for multiplicities), `EF` is the extension-field
/// expression type (for denominators and the accumulated pair).
///
/// Given interactions `(m₁, v₁), ..., (mₙ, vₙ)`:
/// - `D = Π vᵢ`
/// - `N = Σ mᵢ · Π_{j≠i} vⱼ`
///
/// Built iteratively: start with `(N, D) = (0, 1)`, then for each interaction `(m, v)`:
/// - `N ← N · v + m · D`
/// - `D ← D · v`
pub struct Batch<'c, E, EF: PrimeCharacteristicRing> {
    challenges: &'c Challenges<EF>,
    n: EF,
    d: EF,
    _phantom: PhantomData<E>,
}

impl<'c, E, EF> Batch<'c, E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Empty batch: `N = 0, D = 1`.
    pub fn new(challenges: &'c Challenges<EF>) -> Self {
        Self {
            challenges,
            n: EF::ZERO,
            d: EF::ONE,
            _phantom: PhantomData,
        }
    }

    /// Absorb an insert interaction (multiplicity = +1).
    pub fn add(&mut self, msg: impl LogUpMessage<E, EF>) {
        self.insert(E::ONE, msg);
    }

    /// Absorb a remove interaction (multiplicity = −1).
    pub fn remove(&mut self, msg: impl LogUpMessage<E, EF>) {
        self.insert(E::NEG_ONE, msg);
    }

    /// Absorb an interaction with arbitrary base-field multiplicity.
    pub fn insert(&mut self, m: E, msg: impl LogUpMessage<E, EF>) {
        let v: EF = msg.encode(self.challenges);
        self.insert_encoded(m, v);
    }

    /// Absorb an insert interaction with a pre-encoded denominator (multiplicity = +1).
    pub fn add_encoded(&mut self, v: EF) {
        self.insert_encoded(E::ONE, v);
    }

    /// Absorb a remove interaction with a pre-encoded denominator (multiplicity = −1).
    pub fn remove_encoded(&mut self, v: EF) {
        self.insert_encoded(E::NEG_ONE, v);
    }

    /// Absorb an interaction with a pre-encoded denominator and arbitrary multiplicity.
    pub fn insert_encoded(&mut self, m: E, v: EF) {
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * m;
        self.d = self.d.clone() * v;
    }
}

// SET OF MUTUALLY EXCLUSIVE BATCHES
// ================================================================================================

/// A set of mutually exclusive batches, compressed into a single rational pair `V / U`.
///
/// `E` is the base-field expression type, `EF` is the extension-field expression type.
///
/// Given ME batches `(N₁, D₁), ..., (Nₖ, Dₖ)` with boolean selectors `s₁, ..., sₖ`:
/// - `U = 1 + Σ sᵣ · (Dᵣ − 1)`
/// - `V = Σ sᵣ · Nᵣ`
///
/// When no selector is active: `U = 1, V = 0` (contributes zero).
/// When selector `sᵣ = 1`: `U = Dᵣ, V = Nᵣ` (contributes `Nᵣ / Dᵣ`).
pub struct RationalSet<'c, E, EF: PrimeCharacteristicRing> {
    challenges: &'c Challenges<EF>,
    u: EF,
    v: EF,
    _phantom: PhantomData<E>,
}

impl<'c, E, EF> RationalSet<'c, E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Empty set: `U = 1, V = 0` (identity — contributes nothing).
    pub fn new(challenges: &'c Challenges<EF>) -> Self {
        Self {
            challenges,
            u: EF::ONE,
            v: EF::ZERO,
            _phantom: PhantomData,
        }
    }

    /// Add a selector-gated single insert interaction: `+1 / v`.
    ///
    /// Equivalent to `fold_batch(selector, Batch { N=1, D=v })` but avoids
    /// constructing a Batch and the redundant `selector * 1` multiply for V.
    pub fn add_single<M: LogUpMessage<E, EF>>(&mut self, selector: E, msg_fn: impl FnOnce() -> M) {
        let v: EF = msg_fn().encode(self.challenges);
        self.u += (v - EF::ONE) * selector.clone();
        self.v += selector;
    }

    /// Add a selector-gated single remove interaction: `−1 / v`.
    ///
    /// Equivalent to `fold_batch(selector, Batch { N=-1, D=v })` but avoids
    /// constructing a Batch and the redundant `selector * (-1)` multiply for V.
    pub fn remove_single<M: LogUpMessage<E, EF>>(
        &mut self,
        selector: E,
        msg_fn: impl FnOnce() -> M,
    ) {
        let v: EF = msg_fn().encode(self.challenges);
        self.u += (v - EF::ONE) * selector.clone();
        self.v -= selector;
    }

    /// Add a selector-gated single interaction with arbitrary multiplicity: `m / v`.
    pub fn insert_single<M: LogUpMessage<E, EF>>(
        &mut self,
        selector: E,
        m: E,
        msg_fn: impl FnOnce() -> M,
    ) {
        let v: EF = msg_fn().encode(self.challenges);
        self.u += (v - EF::ONE) * selector.clone();
        self.v += selector * m;
    }

    /// Accumulate a shared-denominator interaction from multiple ME flags with known
    /// multiplicities.
    ///
    /// Each `(flag, multiplicity)` pair contributes `multiplicity / v` when `flag = 1`.
    /// The gate `Σ flag_i` controls U, while the numerator `Σ m_i · flag_i` contributes
    /// to V directly — avoiding the degree blowup of `insert_single(gate, numerator, msg)`.
    ///
    /// **Caller proof obligation**: the flags are ME booleans.
    pub fn insert_me<M: LogUpMessage<E, EF>, const N: usize>(
        &mut self,
        entries: [(E, E); N],
        msg_fn: impl FnOnce() -> M,
    ) {
        const { assert!(N > 0) };
        let v: EF = msg_fn().encode(self.challenges);
        let (gate, numerator) = entries
            .into_iter()
            .map(|(flag, m)| (flag.clone(), m * flag))
            .reduce(|(g, n), (g2, n2)| (g + g2, n + n2))
            .unwrap();
        self.u += (v - EF::ONE) * gate;
        self.v += numerator;
    }

    /// Specialized `insert_me` for the virtual-table add/remove pattern: `+1 / v` when
    /// `f_add = 1`, `−1 / v` when `f_remove = 1`.
    ///
    /// No multiplies for the numerator — just `f_add − f_remove` (addition/subtraction only).
    ///
    /// **Caller proof obligation**: `f_add` and `f_remove` are ME booleans.
    pub fn replace<M: LogUpMessage<E, EF>>(
        &mut self,
        f_add: E,
        f_remove: E,
        msg_fn: impl FnOnce() -> M,
    ) {
        let v: EF = msg_fn().encode(self.challenges);
        let gate = f_add.clone() + f_remove.clone();
        let numerator = f_add - f_remove;
        self.u += (v - EF::ONE) * gate;
        self.v += numerator;
    }

    /// Add a selector-gated batch of simultaneous interactions.
    pub fn add_batch(&mut self, selector: E, build: impl FnOnce(&mut Batch<'c, E, EF>)) {
        let mut b = Batch::new(self.challenges);
        build(&mut b);
        self.u += (b.d - EF::ONE) * selector.clone();
        self.v += b.n * selector;
    }

    /// Create a set for an always-active interaction (no selector gating).
    pub fn always(
        challenges: &'c Challenges<EF>,
        build: impl FnOnce(&mut Batch<'c, E, EF>),
    ) -> Self {
        let mut b = Batch::new(challenges);
        build(&mut b);
        Self {
            challenges,
            u: b.d,
            v: b.n,
            _phantom: PhantomData,
        }
    }

    // --- Pre-encoded denominator methods ---

    /// Expose the challenges for use by [`InteractionGroup`] implementations.
    pub fn challenges(&self) -> &Challenges<EF> {
        self.challenges
    }

    /// Like [`add_single`](Self::add_single) but with a pre-computed denominator.
    ///
    /// The closure `v_fn` produces the denominator `v`; it is called unconditionally
    /// by `RationalSet` but may be skipped by a prover-side sink when `flag = 0`.
    pub fn add_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        let v = v_fn();
        self.u += (v - EF::ONE) * flag.clone();
        self.v += flag;
    }

    /// Like [`remove_single`](Self::remove_single) but with a pre-computed denominator.
    pub fn remove_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        let v = v_fn();
        self.u += (v - EF::ONE) * flag.clone();
        self.v -= flag;
    }

    /// Like [`insert_single`](Self::insert_single) but with a pre-computed denominator.
    pub fn insert_encoded(&mut self, flag: E, m: E, v_fn: impl FnOnce() -> EF) {
        let v = v_fn();
        self.u += (v - EF::ONE) * flag.clone();
        self.v += flag * m;
    }

    /// Add an [`InteractionGroup`] to this set.
    ///
    /// Dispatches to [`InteractionGroup::fold_constraints`], which may use an
    /// optimized encoding strategy (cached fragments) or fall back to the
    /// generic [`InteractionGroup::fold`].
    pub fn add_group(&mut self, group: impl InteractionGroup<E, EF>) {
        group.fold_constraints(self);
    }
}

// INTERACTION TRAITS
// ================================================================================================

/// Abstraction over the accumulation backend for bus interactions.
///
/// Implemented by [`RationalSet`] for constraint evaluation (always evaluates all
/// interactions) and by a future `FractionCollector` for prover trace generation
/// (skips inactive interactions based on concrete flag values).
pub trait InteractionSink<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Access the encoding challenges.
    fn challenges(&self) -> &Challenges<EF>;

    // --- Default path: message closures ---

    /// Insert `+1 / v` gated by `flag`.
    fn add_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M);

    /// Insert `−1 / v` gated by `flag`.
    fn remove_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M);

    /// Insert `m / v` gated by `flag`.
    fn insert_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, m: E, msg_fn: impl FnOnce() -> M);

    /// Insert ME entries sharing a denominator.
    fn insert_me<M: LogUpMessage<E, EF>, const N: usize>(
        &mut self,
        entries: [(E, E); N],
        msg_fn: impl FnOnce() -> M,
    );

    /// Virtual-table add/remove with shared denominator.
    fn replace<M: LogUpMessage<E, EF>>(
        &mut self,
        f_add: E,
        f_remove: E,
        msg_fn: impl FnOnce() -> M,
    );

    /// Selector-gated batch of simultaneous interactions.
    fn add_batch(&mut self, flag: E, build: impl FnOnce(&mut Batch<'_, E, EF>));

    // --- Optimized path: pre-encoded denominators ---

    /// Insert `+1 / v` with a pre-computed denominator closure.
    fn add_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF);

    /// Insert `−1 / v` with a pre-computed denominator closure.
    fn remove_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF);

    /// Insert `m / v` with a pre-computed denominator closure.
    fn insert_encoded(&mut self, flag: E, m: E, v_fn: impl FnOnce() -> EF);

    // --- Inline interaction groups ---

    /// Add an inline interaction group with two paths.
    ///
    /// - `fold`: canonical description (prover default — sink skips inactive flags).
    /// - `fold_constraints`: constraint optimization (precomputed shared fragments).
    ///
    /// The sink dispatches to the appropriate closure: `RationalSet` calls
    /// `fold_constraints`; a future prover sink would call `fold`.
    fn add_group_with(
        &mut self,
        fold: impl FnOnce(&mut Self),
        fold_constraints: impl FnOnce(&mut Self),
    );
}

impl<'c, E, EF> InteractionSink<E, EF> for RationalSet<'c, E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn challenges(&self) -> &Challenges<EF> {
        self.challenges
    }

    fn add_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M) {
        self.add_single(flag, msg_fn);
    }

    fn remove_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M) {
        self.remove_single(flag, msg_fn);
    }

    fn insert_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, m: E, msg_fn: impl FnOnce() -> M) {
        self.insert_single(flag, m, msg_fn);
    }

    fn insert_me<M: LogUpMessage<E, EF>, const N: usize>(
        &mut self,
        entries: [(E, E); N],
        msg_fn: impl FnOnce() -> M,
    ) {
        self.insert_me(entries, msg_fn);
    }

    fn replace<M: LogUpMessage<E, EF>>(
        &mut self,
        f_add: E,
        f_remove: E,
        msg_fn: impl FnOnce() -> M,
    ) {
        self.replace(f_add, f_remove, msg_fn);
    }

    fn add_batch(&mut self, flag: E, build: impl FnOnce(&mut Batch<'_, E, EF>)) {
        self.add_batch(flag, build);
    }

    fn add_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        self.add_encoded(flag, v_fn);
    }

    fn remove_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        self.remove_encoded(flag, v_fn);
    }

    fn insert_encoded(&mut self, flag: E, m: E, v_fn: impl FnOnce() -> EF) {
        self.insert_encoded(flag, m, v_fn);
    }

    fn add_group_with(
        &mut self,
        _fold: impl FnOnce(&mut Self),
        fold_constraints: impl FnOnce(&mut Self),
    ) {
        fold_constraints(self);
    }
}

/// A group of related bus interactions with optional constraint-path optimization.
///
/// [`fold`](Self::fold) is the canonical interaction description — one interaction at
/// a time, the sink handles flag-skipping. This serves as the prover default.
///
/// [`fold_constraints`](Self::fold_constraints) may be overridden to precompute shared
/// encoding fragments when multiple ME interactions share column values at the same
/// beta positions (e.g., hasher responses sharing `addr` and `node_index`).
///
/// See `docs/src/design/bus_api_design_notes.md` for the design rationale.
pub trait InteractionGroup<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Canonical interaction description.
    ///
    /// Each interaction is described independently via `sink.add_single`,
    /// `sink.remove_single`, or `sink.add_batch`. The sink may skip closures
    /// for zero-valued flags (prover path) or evaluate all unconditionally
    /// (constraint path).
    fn fold(self, sink: &mut impl InteractionSink<E, EF>);

    /// Constraint-evaluation override.
    ///
    /// Called by [`RationalSet::add_group`] instead of `fold`. Override to
    /// precompute shared encoding fragments for EF×BF savings. The default
    /// delegates to [`fold`](Self::fold).
    fn fold_constraints(self, sink: &mut impl InteractionSink<E, EF>)
    where
        Self: Sized,
    {
        self.fold(sink);
    }
}

// FRACTION COLLECTOR (PROVER PATH)
// ================================================================================================

/// Prover-side sink that collects LogUp fractions for one row.
///
/// Unlike [`RationalSet`] (which builds symbolic constraint expressions and uses
/// mutually-exclusive selector compression), the `FractionCollector` skips inactive
/// interactions (flag = 0) and accumulates active fractions using cross-denominator
/// clearing (same algebra as [`Batch`]):
///
/// - `N = Σ mᵢ · Π_{j≠i} vⱼ`
/// - `D = Π vᵢ`
///
/// After processing all interactions, the row's delta is `N/D = Σ mᵢ/vᵢ`.
///
/// Starts with `(N, D) = (0, 1)` — identity (zero contribution).
pub struct FractionCollector<'c, E, EF: PrimeCharacteristicRing> {
    challenges: &'c Challenges<EF>,
    n: EF,
    d: EF,
    _phantom: PhantomData<E>,
}

impl<'c, E, EF> FractionCollector<'c, E, EF>
where
    E: PrimeCharacteristicRing + Clone + PartialEq,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Create an empty collector: `(N, D) = (0, 1)`.
    pub fn new(challenges: &'c Challenges<EF>) -> Self {
        Self {
            challenges,
            n: EF::ZERO,
            d: EF::ONE,
            _phantom: PhantomData,
        }
    }

    /// Returns the accumulated `(numerator, denominator)` pair.
    ///
    /// The row's delta is `N / D = Σ mᵢ / vᵢ` over active interactions.
    /// Returns `(0, 1)` if no interactions were active.
    pub fn into_pair(self) -> (EF, EF) {
        (self.n, self.d)
    }

    /// Absorb a fraction `m / v` into the accumulator.
    ///
    /// Uses cross-denominator clearing: `N' = N·v + m·D`, `D' = D·v`.
    fn absorb(&mut self, m: E, v: EF) {
        let d_prev = self.d.clone();
        self.n = self.n.clone() * v.clone() + d_prev * m;
        self.d = self.d.clone() * v;
    }

    /// Absorb a batch's `(N_batch, D_batch)` as a single compound fraction.
    fn absorb_pair(&mut self, batch_n: EF, batch_d: EF) {
        let d_prev = self.d.clone();
        self.n = self.n.clone() * batch_d.clone() + batch_n * d_prev;
        self.d = self.d.clone() * batch_d;
    }
}

impl<'c, E, EF> InteractionSink<E, EF> for FractionCollector<'c, E, EF>
where
    E: PrimeCharacteristicRing + Clone + PartialEq,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn challenges(&self) -> &Challenges<EF> {
        self.challenges
    }

    fn add_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M) {
        if flag == E::ZERO {
            return;
        }
        let v = msg_fn().encode(self.challenges);
        self.absorb(E::ONE, v);
    }

    fn remove_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M) {
        if flag == E::ZERO {
            return;
        }
        let v = msg_fn().encode(self.challenges);
        self.absorb(E::NEG_ONE, v);
    }

    fn insert_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, m: E, msg_fn: impl FnOnce() -> M) {
        if flag == E::ZERO {
            return;
        }
        let v = msg_fn().encode(self.challenges);
        self.absorb(m, v);
    }

    fn insert_me<M: LogUpMessage<E, EF>, const N: usize>(
        &mut self,
        entries: [(E, E); N],
        msg_fn: impl FnOnce() -> M,
    ) {
        if let Some((_flag, m)) = entries.into_iter().find(|(f, _)| *f != E::ZERO) {
            let v = msg_fn().encode(self.challenges);
            self.absorb(m, v);
        }
    }

    fn replace<M: LogUpMessage<E, EF>>(
        &mut self,
        f_add: E,
        f_remove: E,
        msg_fn: impl FnOnce() -> M,
    ) {
        if f_add != E::ZERO {
            let v = msg_fn().encode(self.challenges);
            self.absorb(E::ONE, v);
        } else if f_remove != E::ZERO {
            let v = msg_fn().encode(self.challenges);
            self.absorb(E::NEG_ONE, v);
        }
    }

    fn add_batch(&mut self, flag: E, build: impl FnOnce(&mut Batch<'_, E, EF>)) {
        if flag == E::ZERO {
            return;
        }
        let mut b = Batch::new(self.challenges);
        build(&mut b);
        self.absorb_pair(b.n, b.d);
    }

    fn add_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        if flag == E::ZERO {
            return;
        }
        let v = v_fn();
        self.absorb(E::ONE, v);
    }

    fn remove_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF) {
        if flag == E::ZERO {
            return;
        }
        let v = v_fn();
        self.absorb(E::NEG_ONE, v);
    }

    fn insert_encoded(&mut self, flag: E, m: E, v_fn: impl FnOnce() -> EF) {
        if flag == E::ZERO {
            return;
        }
        let v = v_fn();
        self.absorb(m, v);
    }

    fn add_group_with(
        &mut self,
        fold: impl FnOnce(&mut Self),
        _fold_constraints: impl FnOnce(&mut Self),
    ) {
        fold(self);
    }
}

// COLUMN ACCUMULATOR
// ================================================================================================

/// A column accumulator that combines independent sets by clearing cross-denominators.
///
/// Given sets with pairs `(U₁, V₁), ..., (Uₜ, Vₜ)`:
/// - `U = Π Uᵢ`
/// - `V = Σ Vᵢ · Π_{j≠i} Uⱼ`
///
/// Built iteratively: start with `(U, V) = (1, 0)`, then for each set `(Ũ, Ṽ)`:
/// - `V ← V · Ũ + Ṽ · U`
/// - `U ← U · Ũ`
///
/// Initialized with the accumulator values `acc` and `acc_next` from the auxiliary trace.
/// Call [`Column::constrain`] to emit first-row, transition, and last-row constraints.
pub struct Column<E, EF> {
    acc: EF,
    acc_next: EF,
    u: EF,
    v: EF,
    _phantom: PhantomData<E>,
}

impl<E, EF> Column<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Create a column bound to accumulator values, containing exactly one set.
    pub fn from_set(acc: EF, acc_next: EF, set: RationalSet<'_, E, EF>) -> Self {
        Self {
            acc,
            acc_next,
            u: set.u,
            v: set.v,
            _phantom: PhantomData,
        }
    }

    /// Create an unbound column from a single set (for testing the algebra).
    #[cfg(test)]
    pub fn from_set_unbound(set: RationalSet<'_, E, EF>) -> Self {
        Self {
            acc: EF::ZERO,
            acc_next: EF::ZERO,
            u: set.u,
            v: set.v,
            _phantom: PhantomData,
        }
    }

    /// Add an independent set to the column.
    pub fn add_set(&mut self, set: RationalSet<'_, E, EF>) {
        self.v = self.v.clone() * set.u.clone() + set.v * self.u.clone();
        self.u = self.u.clone() * set.u;
    }

    /// Return the constraint expression `Δ · U − V` for a given delta.
    #[cfg(test)]
    pub fn constraint(&self, delta: EF) -> EF {
        delta * self.u.clone() - self.v.clone()
    }

    /// Emit all constraints for this column and consume it.
    ///
    /// - **First row**: `acc = 0`
    /// - **Transition**: `Δ · U − V = 0` where `Δ = acc_next − acc`
    /// - **Last row**: `acc = 0` (temporary — will be replaced by public-input binding)
    pub fn constrain<AB>(self, builder: &mut AB)
    where
        AB: LiftedAirBuilder<F = Felt>,
        AB::ExprEF: From<EF>,
    {
        let acc: AB::ExprEF = self.acc.into();
        let acc_next: AB::ExprEF = self.acc_next.into();
        let u: AB::ExprEF = self.u.into();
        let v: AB::ExprEF = self.v.into();
        let delta = acc_next - acc.clone();

        builder.when_first_row().assert_zero_ext(acc.clone());
        builder.when_transition().assert_zero_ext(delta * u - v);
        builder.when_last_row().assert_zero_ext(acc);
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use miden_core::{
        Felt,
        field::{Field, QuadFelt},
    };

    use super::*;
    use crate::trace::Challenges;

    type E = Felt;
    type EF = QuadFelt;

    fn ef(a: u64) -> EF {
        EF::from(Felt::new(a))
    }

    fn challenges() -> Challenges<EF> {
        Challenges::new(ef(100), ef(7))
    }

    /// A trivial test message: encodes a single field element.
    struct TestMsg<E> {
        val: E,
    }

    impl<E, EF2> LogUpMessage<E, EF2> for TestMsg<E>
    where
        E: PrimeCharacteristicRing + Clone,
        EF2: PrimeCharacteristicRing + Algebra<E>,
    {
        fn encode(&self, challenges: &Challenges<EF2>) -> EF2 {
            challenges.encode([self.val.clone()])
        }
    }

    type B<'c> = Batch<'c, E, EF>;
    type S<'c> = RationalSet<'c, E, EF>;

    #[test]
    fn empty_batch() {
        let ch = challenges();
        let batch = B::new(&ch);
        assert_eq!(batch.n, EF::ZERO);
        assert_eq!(batch.d, EF::ONE);
    }

    #[test]
    fn single_add() {
        let ch = challenges();
        let mut batch = B::new(&ch);
        batch.add(TestMsg { val: Felt::new(42) });
        // D should equal the encoded value of 42
        let expected_d = ch.encode([Felt::new(42)]);
        assert_eq!(batch.d, expected_d);
        assert_eq!(batch.n, EF::ONE);
    }

    #[test]
    fn add_then_remove() {
        let ch = challenges();
        let mut batch = B::new(&ch);
        batch.add(TestMsg { val: Felt::new(3) });
        batch.remove(TestMsg { val: Felt::new(5) });
        let v1 = ch.encode([Felt::new(3)]);
        let v2 = ch.encode([Felt::new(5)]);
        assert_eq!(batch.d, v1 * v2);
        assert_eq!(batch.n, v2 - v1);
    }

    #[test]
    fn set_add_single() {
        let ch = challenges();
        let mut set = S::new(&ch);
        set.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });
        let v = ch.encode([Felt::new(10)]);
        assert_eq!(set.u, v);
        assert_eq!(set.v, EF::ONE);
    }

    #[test]
    fn set_inactive() {
        let ch = challenges();
        let mut set = S::new(&ch);
        set.add_single(Felt::ZERO, || TestMsg { val: Felt::new(10) });
        assert_eq!(set.u, EF::ONE);
        assert_eq!(set.v, EF::ZERO);
    }

    #[test]
    fn set_add_batch_closure() {
        let ch = challenges();
        let mut set = S::new(&ch);
        set.add_batch(Felt::ONE, |b| {
            b.add(TestMsg { val: Felt::new(3) });
            b.remove(TestMsg { val: Felt::new(5) });
        });
        let v1 = ch.encode([Felt::new(3)]);
        let v2 = ch.encode([Felt::new(5)]);
        assert_eq!(set.u, v1 * v2);
        assert_eq!(set.v, v2 - v1);
    }

    #[test]
    fn column_two_sets() {
        let ch = challenges();
        let v1 = ch.encode([Felt::new(3)]);
        let v2 = ch.encode([Felt::new(7)]);

        let mut set1 = S::new(&ch);
        set1.add_single(Felt::ONE, || TestMsg { val: Felt::new(3) });
        let mut set2 = S::new(&ch);
        set2.add_single(Felt::ONE, || TestMsg { val: Felt::new(7) });

        let mut col = Column::from_set_unbound(set1);
        col.add_set(set2);

        assert_eq!(col.u, v1 * v2);
        assert_eq!(col.v, v1 + v2);
    }

    #[test]
    fn column_constraint_zero() {
        let ch = challenges();
        let v = ch.encode([Felt::new(5)]);
        let mut set = S::new(&ch);
        set.add_single(Felt::ONE, || TestMsg { val: Felt::new(5) });
        let col = Column::from_set_unbound(set);
        assert_eq!(col.constraint(v.inverse()), EF::ZERO);
    }

    #[test]
    fn three_interactions_rational_identity() {
        let ch = challenges();
        let v1 = ch.encode([Felt::new(2)]);
        let v2 = ch.encode([Felt::new(3)]);
        let v3 = ch.encode([Felt::new(5)]);

        let mut batch = B::new(&ch);
        batch.add(TestMsg { val: Felt::new(2) });
        batch.add(TestMsg { val: Felt::new(3) });
        batch.remove(TestMsg { val: Felt::new(5) });

        assert_eq!(batch.d, v1 * v2 * v3);
        let lhs = batch.n * batch.d.inverse();
        let rhs = v1.inverse() + v2.inverse() - v3.inverse();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn end_to_end() {
        let ch = challenges();
        let v1 = ch.encode([Felt::new(3)]);
        let v2 = ch.encode([Felt::new(7)]);

        let set1 = S::always(&ch, |b| b.add(TestMsg { val: Felt::new(3) }));
        let mut set2 = S::new(&ch);
        set2.add_single(Felt::ONE, || TestMsg { val: Felt::new(7) });

        let mut col = Column::from_set_unbound(set1);
        col.add_set(set2);

        let delta = v1.inverse() + v2.inverse();
        assert_eq!(col.constraint(delta), EF::ZERO);
    }

    // FRACTION COLLECTOR TESTS
    // --------------------------------------------------------------------------------------------

    type FC<'c> = FractionCollector<'c, E, EF>;

    #[test]
    fn collector_empty() {
        let ch = challenges();
        let coll = FC::new(&ch);
        let (n, d) = coll.into_pair();
        assert_eq!(n, EF::ZERO);
        assert_eq!(d, EF::ONE);
    }

    #[test]
    fn collector_add_active() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });
        let (n, d) = coll.into_pair();
        let v = ch.encode([Felt::new(10)]);
        assert_eq!(d, v);
        assert_eq!(n, EF::ONE);
    }

    #[test]
    fn collector_add_inactive() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.add_single(Felt::ZERO, || TestMsg { val: Felt::new(10) });
        let (n, d) = coll.into_pair();
        assert_eq!(n, EF::ZERO);
        assert_eq!(d, EF::ONE);
    }

    #[test]
    fn collector_remove_active() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.remove_single(Felt::ONE, || TestMsg { val: Felt::new(7) });
        let (n, d) = coll.into_pair();
        let v = ch.encode([Felt::new(7)]);
        assert_eq!(d, v);
        assert_eq!(n, EF::NEG_ONE);
    }

    /// Collector and RationalSet agree on `(N, D) == (V, U)` for a single add.
    #[test]
    fn collector_matches_set_add() {
        let ch = challenges();

        let mut set = S::new(&ch);
        set.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });

        let mut coll = FC::new(&ch);
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });
        let (n, d) = coll.into_pair();

        assert_eq!(set.u, d);
        assert_eq!(set.v, n);
    }

    /// Collector and RationalSet agree for a single remove.
    #[test]
    fn collector_matches_set_remove() {
        let ch = challenges();

        let mut set = S::new(&ch);
        set.remove_single(Felt::ONE, || TestMsg { val: Felt::new(7) });

        let mut coll = FC::new(&ch);
        coll.remove_single(Felt::ONE, || TestMsg { val: Felt::new(7) });
        let (n, d) = coll.into_pair();

        assert_eq!(set.u, d);
        assert_eq!(set.v, n);
    }

    /// Collector matches RationalSet for a batch with add + remove.
    #[test]
    fn collector_matches_set_batch() {
        let ch = challenges();

        let mut set = S::new(&ch);
        set.add_batch(Felt::ONE, |b| {
            b.add(TestMsg { val: Felt::new(3) });
            b.remove(TestMsg { val: Felt::new(5) });
        });

        let mut coll = FC::new(&ch);
        coll.add_batch(Felt::ONE, |b| {
            b.add(TestMsg { val: Felt::new(3) });
            b.remove(TestMsg { val: Felt::new(5) });
        });
        let (n, d) = coll.into_pair();

        assert_eq!(set.u, d);
        assert_eq!(set.v, n);
    }

    /// Inactive batch contributes nothing.
    #[test]
    fn collector_batch_inactive() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.add_batch(Felt::ZERO, |b| {
            b.add(TestMsg { val: Felt::new(3) });
        });
        let (n, d) = coll.into_pair();
        assert_eq!(n, EF::ZERO);
        assert_eq!(d, EF::ONE);
    }

    /// Collector with ME interactions: only the active entry contributes.
    #[test]
    fn collector_me_one_active() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.insert_me([(Felt::ZERO, Felt::new(2)), (Felt::ONE, Felt::new(3))], || TestMsg {
            val: Felt::new(10),
        });
        let (n, d) = coll.into_pair();
        let v = ch.encode([Felt::new(10)]);
        // Active entry has m=3
        assert_eq!(d, v);
        assert_eq!(n, EF::from(Felt::new(3)));
    }

    /// Collector with ME interactions: no active entry means no contribution.
    #[test]
    fn collector_me_none_active() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.insert_me([(Felt::ZERO, Felt::new(2)), (Felt::ZERO, Felt::new(3))], || TestMsg {
            val: Felt::new(10),
        });
        let (n, d) = coll.into_pair();
        assert_eq!(n, EF::ZERO);
        assert_eq!(d, EF::ONE);
    }

    /// Collector replace: f_add active.
    #[test]
    fn collector_replace_add() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.replace(Felt::ONE, Felt::ZERO, || TestMsg { val: Felt::new(5) });
        let (n, d) = coll.into_pair();
        let v = ch.encode([Felt::new(5)]);
        assert_eq!(d, v);
        assert_eq!(n, EF::ONE);
    }

    /// Collector replace: f_remove active.
    #[test]
    fn collector_replace_remove() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.replace(Felt::ZERO, Felt::ONE, || TestMsg { val: Felt::new(5) });
        let (n, d) = coll.into_pair();
        let v = ch.encode([Felt::new(5)]);
        assert_eq!(d, v);
        assert_eq!(n, EF::NEG_ONE);
    }

    /// Collector replace: both inactive.
    #[test]
    fn collector_replace_inactive() {
        let ch = challenges();
        let mut coll = FC::new(&ch);
        coll.replace(Felt::ZERO, Felt::ZERO, || TestMsg { val: Felt::new(5) });
        let (n, d) = coll.into_pair();
        assert_eq!(n, EF::ZERO);
        assert_eq!(d, EF::ONE);
    }

    /// Collector's `add_group_with` dispatches to `fold` (not `fold_constraints`).
    #[test]
    fn collector_group_with_uses_fold() {
        let ch = challenges();
        let mut coll = FC::new(&ch);

        coll.add_group_with(
            |sink| {
                sink.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });
            },
            |sink| {
                sink.add_single(Felt::ONE, || TestMsg { val: Felt::new(99) });
            },
        );

        let (n, d) = coll.into_pair();
        let v10 = ch.encode([Felt::new(10)]);
        let v99 = ch.encode([Felt::new(99)]);
        // Prover uses fold (val=10), not fold_constraints (val=99)
        assert_eq!(d, v10);
        assert_ne!(d, v99);
        assert_eq!(n, EF::ONE);
    }

    /// RationalSet's `add_group_with` dispatches to `fold_constraints`.
    #[test]
    fn set_group_with_uses_fold_constraints() {
        let ch = challenges();
        let mut set = S::new(&ch);

        set.add_group_with(
            |sink| {
                sink.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });
            },
            |sink| {
                sink.add_single(Felt::ONE, || TestMsg { val: Felt::new(99) });
            },
        );

        let v99 = ch.encode([Felt::new(99)]);
        let v10 = ch.encode([Felt::new(10)]);
        // Constraints use fold_constraints (val=99)
        assert_eq!(set.u, v99);
        assert_ne!(set.u, v10);
    }

    /// Collector with multiple active fractions gives correct sum.
    ///
    /// Two fractions 1/v1 + 1/v2 should satisfy: N/D = (v1+v2)/(v1*v2).
    #[test]
    fn collector_two_fractions_sum() {
        let ch = challenges();
        let v1 = ch.encode([Felt::new(3)]);
        let v2 = ch.encode([Felt::new(7)]);

        let mut coll = FC::new(&ch);
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(3) });
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(7) });
        let (n, d) = coll.into_pair();

        // Cross-denominator: N = v2 + v1, D = v1 * v2
        assert_eq!(d, v1 * v2);
        assert_eq!(n, v1 + v2);

        // Verify rational identity: N/D = 1/v1 + 1/v2
        let delta = n * d.inverse();
        assert_eq!(delta, v1.inverse() + v2.inverse());
    }

    /// Collector matches Column for a multi-set scenario.
    ///
    /// Column combines two independent sets by cross-denominator clearing.
    /// Collector processes fractions from both sets in sequence.
    /// They should agree: Column.u == coll.d, Column.v == coll.n.
    #[test]
    fn collector_matches_column_two_sets() {
        let ch = challenges();

        // Constraint path: two separate sets → Column
        let mut set1 = S::new(&ch);
        set1.add_single(Felt::ONE, || TestMsg { val: Felt::new(3) });
        let mut set2 = S::new(&ch);
        set2.add_single(Felt::ONE, || TestMsg { val: Felt::new(7) });
        let mut col = Column::from_set_unbound(set1);
        col.add_set(set2);

        // Prover path: single collector for both sets' interactions
        let mut coll = FC::new(&ch);
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(3) });
        coll.add_single(Felt::ONE, || TestMsg { val: Felt::new(7) });
        let (n, d) = coll.into_pair();

        assert_eq!(col.u, d);
        assert_eq!(col.v, n);
    }

    /// Pre-encoded methods match non-encoded counterparts.
    #[test]
    fn collector_encoded_matches_message() {
        let ch = challenges();

        let mut coll_msg = FC::new(&ch);
        coll_msg.add_single(Felt::ONE, || TestMsg { val: Felt::new(10) });

        let mut coll_enc = FC::new(&ch);
        let v = ch.encode([Felt::new(10)]);
        coll_enc.add_encoded(Felt::ONE, || v);

        assert_eq!(coll_msg.n, coll_enc.n);
        assert_eq!(coll_msg.d, coll_enc.d);
    }
}
