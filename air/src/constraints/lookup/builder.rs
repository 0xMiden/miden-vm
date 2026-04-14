//! Closure-based builder traits for the new LogUp lookup-argument API.
//!
//! Task #2 of the lookup-air refactor (see
//! `docs/src/design/lookup_air_plan.md`) introduces the trait stack that
//! sits on top of `LookupAir`:
//!
//! - [`LookupBuilder`] — the top-level handle mirroring the subset of `LiftedAirBuilder` a lookup
//!   author actually needs (trace access plus per-column scoping). It hides `assert_*` / `when_*` /
//!   permutation plumbing and does not expose the verifier challenges.
//! - [`LookupColumn`] — per-column handle returned by [`LookupBuilder::column`]. It owns the
//!   boundary between groups; its only job is to open a group (either the simple path or the
//!   cached-encoding dual path).
//! - [`LookupGroup`] — the simple, challenge-free interaction API used by bus authors. Every method
//!   here takes a `LookupMessage`; the enclosing adapter is responsible for encoding it under α + Σ
//!   βⁱ · payload.
//! - [`LookupBatch`] — a short-lived handle returned inside [`LookupGroup::batch`]. Represents a
//!   set of simultaneous interactions that share the outer group's flag.
//! - [`EncodedLookupGroup`] — super-trait of [`LookupGroup`] that exposes the encoding primitives
//!   (`bus_prefix`, `beta_powers`, `insert_encoded`). Only handed out on the constraint path of
//!   [`LookupColumn::group_with_cached_encoding`], so the simple path never sees challenges.
//!
//! No adapter impls live in this file — they arrive in Task #3 (constraint
//! path) and Task #4 (prover path). The bounds here are therefore chosen
//! so that both adapters can satisfy them: the constraint-path adapter
//! forwards to an inner `LiftedAirBuilder` (so the associated types ride
//! on `AB::Expr` / `AB::ExprEF` / etc.), while the prover-path adapter
//! instantiates them with the concrete `F` / `EF` field types directly.

// Task #6 (block-hash queue port) lands the first live
// `LookupBuilder::main()` call via `MidenLookupAir::eval`, so the
// trace-access method is now exercised. `periodic_values()` and
// `public_values()` remain unused until Task #7 lands the chiplet /
// range-check buses that read them. The narrow `expect` below covers
// just those two methods; remove both bullets when Task #7 ports the
// buses that consume them.
#![expect(
    dead_code,
    reason = "`LookupBuilder::periodic_values` / `public_values` stay dead until Task #7 ports the buses that read them."
)]

use miden_core::field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};
use miden_crypto::stark::air::WindowAccess;

use super::message::LookupMessage;

// LOOKUP BUILDER
// ================================================================================================

/// The trace-reading handle handed to a [`super::LookupAir`] implementation.
///
/// `LookupBuilder` deliberately mirrors the subset of `LiftedAirBuilder`'s
/// associated types needed to read `main`, `periodic_values`, and
/// `public_values`. It is **not** a sub-trait of `AirBuilder`: the constraint
/// emission surface (`assert_zero` / `when_first_row` / …) and the
/// permutation column plumbing stay hidden, which keeps the simple lookup
/// path free of challenge access.
///
/// Implementors must not shortcut the per-column scoping: a [`LookupAir`]
/// author that opens `n` columns must issue exactly `n` calls to
/// [`LookupBuilder::column`], matching [`super::LookupAir::num_columns`].
///
/// ## Associated-type layout
///
/// The base-field stack (`F`, `Expr`, `Var`) and extension-field stack
/// (`EF`, `ExprEF`, `VarEF`) mirror the upstream `AirBuilder` /
/// `ExtensionBuilder` split one-for-one; `Algebra<Var>` on `Expr` lets the
/// lookup author multiply main-trace variables with arbitrary expressions
/// without crossing trait boundaries. `PeriodicVar` / `PublicVar` /
/// `MainWindow` come from `PeriodicAirBuilder` / `AirBuilder` respectively
/// and are passed through the adapter unchanged.
///
/// The per-column handle is a generic associated type
/// ([`Self::Column`](Self::Column)) so that each `column(...)` call can
/// borrow from `self` without outliving the closure. Its bound pins the
/// expression and extension-variable types to keep them in sync with the
/// outer builder.
pub trait LookupBuilder: Sized {
    // --- base field stack (copied from AirBuilder) ---

    /// Underlying base field. Lookups only pin `Field` here (not the wider
    /// `PrimeCharacteristicRing`) because the extension-field associated
    /// types below require an `ExtensionField<Self::F>` relationship, and
    /// `ExtensionField` itself bounds on `Field`.
    type F: Field;

    /// Expression type over base-field elements. Must be an algebra over
    /// both `Self::F` (for constants) and `Self::Var` (for trace
    /// variables), matching upstream `AirBuilder::Expr`.
    type Expr: Algebra<Self::F> + Algebra<Self::Var>;

    /// Variable type over base-field trace cells. Held by value, so bound
    /// only by `Into<Self::Expr> + Copy + Send + Sync`; the full arithmetic
    /// bound soup from `AirBuilder::Var` is not required here because the
    /// `Algebra<Self::Var>` bound on `Expr` lets callers convert before
    /// composing.
    type Var: Into<Self::Expr> + Copy + Send + Sync;

    // --- extension field stack (copied from ExtensionBuilder) ---

    /// Extension field used by the auxiliary trace and the LogUp
    /// accumulators.
    type EF: ExtensionField<Self::F>;

    /// Expression type over extension-field elements; must be an algebra
    /// over both `Self::Expr` (to lift base expressions) and `Self::EF`
    /// (for extension-field constants).
    type ExprEF: Algebra<Self::Expr> + Algebra<Self::EF>;

    /// Variable type over extension-field trace cells (permutation
    /// columns and the α/β challenges).
    type VarEF: Into<Self::ExprEF> + Copy + Send + Sync;

    // --- auxiliary trace access types ---

    /// Periodic column value at the current row (copied from
    /// `PeriodicAirBuilder::PeriodicVar`).
    type PeriodicVar: Into<Self::Expr> + Copy;

    /// Public-input variable (copied from `AirBuilder::PublicVar`).
    type PublicVar: Into<Self::Expr> + Copy;

    /// Two-row window over the main trace, returned as-is from the
    /// underlying builder. Pinned to [`WindowAccess`] + `Clone` so a
    /// lookup author can split it into `current_slice()` / `next_slice()`
    /// and pass either to `borrow`-based view types without re-reading
    /// the handle.
    type MainWindow: WindowAccess<Self::Var> + Clone;

    // --- per-column handle (GAT, borrows from self) ---

    /// Per-column handle opened by [`column`](Self::column). The GAT lets
    /// the adapter stash a mutable borrow of its internal state (running
    /// `(U, V)` on the constraint path, fraction collector on the prover
    /// path) for the duration of a single column's closure.
    type Column<'a>: LookupColumn<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    // ---- trace access ----

    /// Two-row main trace window. Pass-through to the wrapped builder.
    fn main(&self) -> Self::MainWindow;

    /// Periodic column values at the current row.
    fn periodic_values(&self) -> &[Self::PeriodicVar];

    /// Public inputs.
    fn public_values(&self) -> &[Self::PublicVar];

    // ---- per-column scoping ----

    /// Open a fresh permutation column and evaluate `f` inside it.
    ///
    /// The implementation is responsible for:
    ///
    /// 1. Wiring the column handle to the adapter's internal state (current `acc` / `acc_next` for
    ///    the constraint path; the per-column fraction buffer slot for the prover path).
    /// 2. Running the closure, which must describe at least one group via [`LookupColumn::group`]
    ///    or [`LookupColumn::group_with_cached_encoding`].
    /// 3. Finalizing the column on close (emitting boundary + transition constraints, or draining
    ///    the column's fraction pair).
    /// 4. Advancing to the next permutation column index so the next `column(…)` call targets a
    ///    fresh accumulator.
    ///
    /// The closure's return value is forwarded unchanged.
    ///
    /// The lifetime `'a` on the `Self::Column<'a>` handle is tied to the
    /// `&'a mut self` borrow so that `Self: 'a` is implied by the
    /// outlives relation on the method receiver, rather than leaving it
    /// as a higher-ranked `for<'c> …` constraint.
    fn column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R) -> R;
}

// LOOKUP COLUMN
// ================================================================================================

/// Per-column handle returned by [`LookupBuilder::column`].
///
/// The only decision a column makes is how to open a group: either the
/// simple path via [`group`](Self::group) or the dual cached-encoding path
/// via [`group_with_cached_encoding`](Self::group_with_cached_encoding).
///
/// Multiple groups may be opened per column; the adapter is responsible
/// for composing them according to the column accumulator algebra
/// (`V ← V·Uᵍ + Vᵍ·U`, `U ← U·Uᵍ`). Groups opened inside the same column
/// are assumed *product-closed*, not mutually exclusive.
pub trait LookupColumn {
    /// Expression type over base-field elements. Pinned to
    /// [`LookupBuilder::Expr`] through [`LookupBuilder::Column`].
    ///
    /// `PrimeCharacteristicRing` is required so that [`LookupMessage`]'s
    /// `E: PrimeCharacteristicRing + Clone` bound is transitively
    /// satisfied when authors pass messages through `group.add(…)` etc.
    type Expr: PrimeCharacteristicRing + Clone;

    /// Expression type over extension-field elements. Pinned to
    /// [`LookupBuilder::ExprEF`] through [`LookupBuilder::Column`]. The
    /// [`Algebra<Self::Expr>`] bound lets [`LookupMessage::encode`]
    /// multiply an `Expr`-typed payload slot by an `ExprEF`-typed
    /// β-power without manually lifting.
    type ExprEF: PrimeCharacteristicRing + Clone + Algebra<Self::Expr>;

    /// Per-group handle used for the simple (challenge-free) path. GAT so
    /// the group can borrow from the column for the duration of the
    /// closure.
    type Group<'a>: LookupGroup<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    /// Per-group handle used for the cached-encoding constraint-path
    /// closure. Implements [`EncodedLookupGroup`] (a sub-trait of
    /// [`LookupGroup`]), so the author can still call `add` / `remove` /
    /// `insert` / `batch` inside it *and* reach for the encoding
    /// primitives (`alpha`, `beta_powers`, `insert_encoded`).
    type EncodedGroup<'a>: EncodedLookupGroup<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    /// Open a group using the simple, challenge-free API.
    ///
    /// Every interaction added inside the closure is folded into this
    /// group's `(Uᵍ, Vᵍ)` pair; on close, the column composes the pair
    /// into its running accumulator.
    ///
    /// The `'a` lifetime on the group handle is tied to the `&'a mut
    /// self` borrow of the column for the same reason as
    /// [`LookupBuilder::column`].
    fn group<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Group<'a>) -> R) -> R;

    /// Open a group with two sibling descriptions for the same
    /// interaction set.
    ///
    /// - `canonical` runs on the prover path. It sees the simple [`LookupGroup`] surface — no
    ///   challenges, no `insert_encoded`. Zero-valued flag closures are skipped by the backing
    ///   fraction collector.
    /// - `encoded` runs on the constraint path. It sees the [`EncodedLookupGroup`] super-trait,
    ///   exposing `alpha()`, `beta_powers()`, and `insert_encoded`. Authors use this to precompute
    ///   shared encoding fragments (e.g. a common `α + β·addr` prefix) and reuse them across
    ///   mutually-exclusive variants.
    ///
    /// Both closures must produce mathematically identical `(U, V)`
    /// pairs; the split is purely an optimization for expensive
    /// extension-field arithmetic on the symbolic path. Adapters are
    /// free to drop whichever closure they do not use.
    fn group_with_cached_encoding<'a, R>(
        &'a mut self,
        canonical: impl FnOnce(&mut Self::Group<'a>) -> R,
        encoded: impl FnOnce(&mut Self::EncodedGroup<'a>) -> R,
    ) -> R;
}

// LOOKUP GROUP
// ================================================================================================

/// Simple, challenge-free interaction API opened inside a
/// [`LookupColumn`].
///
/// Authors call `add` / `remove` / `insert` to describe one flag-gated
/// interaction at a time, or `batch` to describe several simultaneous
/// interactions that share a single outer flag.
///
/// All methods take the message through an `impl FnOnce() -> M` closure
/// so the prover-path adapter can skip the construction (and any
/// expensive derivation) when `flag == 0`.
pub trait LookupGroup {
    /// Expression type over base-field elements. Pinned to
    /// [`LookupBuilder::Expr`] through the column. The
    /// `PrimeCharacteristicRing` bound keeps [`LookupMessage`] happy when
    /// authors pass messages through `add` / `remove` / `insert`.
    type Expr: PrimeCharacteristicRing + Clone;

    /// Expression type over extension-field elements. Pinned to
    /// [`LookupBuilder::ExprEF`] through the column. The
    /// [`Algebra<Self::Expr>`] bound mirrors [`LookupColumn::ExprEF`]
    /// and lets [`LookupMessage::encode`] use `ExprEF × Expr` products.
    type ExprEF: PrimeCharacteristicRing + Clone + Algebra<Self::Expr>;

    /// Transient handle returned by [`batch`](Self::batch). GAT so the
    /// batch can borrow from `self` (and therefore from the column and
    /// the outer builder) for the duration of the closure.
    type Batch<'b>: LookupBatch<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'b;

    /// Add a single interaction with multiplicity `+1`, gated by `flag`.
    ///
    /// `msg` is deferred so the adapter can skip both the construction
    /// and the encoding when `flag == 0` on the prover path.
    fn add<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Add a single interaction with multiplicity `-1`, gated by `flag`.
    fn remove<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Add a single interaction with explicit signed multiplicity, gated
    /// by `flag`.
    ///
    /// `multiplicity` is a base-field expression so callers can mix
    /// trace columns, constants, and boolean selectors freely.
    fn insert<M>(&mut self, flag: Self::Expr, multiplicity: Self::Expr, msg: impl FnOnce() -> M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Open a batch of simultaneous interactions that all share the
    /// single outer flag `flag`.
    ///
    /// Inside the closure, messages are passed by value (see
    /// [`LookupBatch`]): the flag-zero skip is handled once at the batch
    /// level, so per-interaction closures are redundant.
    ///
    /// Multiple batches inside the same [`LookupGroup`] are **not**
    /// checked for mutual exclusion; adapters assume the author upholds
    /// this invariant (matching the existing `RationalSet` contract).
    ///
    /// The `'a` lifetime on the batch handle is tied to `&'a mut self`
    /// for the same reason as [`LookupBuilder::column`] and
    /// [`LookupColumn::group`].
    fn batch<'a, R>(
        &'a mut self,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'a>) -> R,
    ) -> R;
}

// LOOKUP BATCH
// ================================================================================================

/// Transient handle exposed inside [`LookupGroup::batch`].
///
/// A batch groups several simultaneously-active interactions under a
/// single outer flag, emitted by the enclosing group. The flag-zero skip
/// is performed once by the group when the batch opens, so within the
/// batch the message can be built unconditionally and is taken by value
/// (not through a closure).
///
/// Kept as a separate trait rather than a concrete helper struct because
/// the constraint-path and prover-path adapters need different backing
/// storage (`RationalSet` vs `FractionCollector`) and expressing that
/// split through a GAT on [`LookupGroup::Batch`] is cleaner than bolting
/// a second generic parameter onto a shared struct.
pub trait LookupBatch {
    /// Expression type over base-field elements. Must match the
    /// enclosing group's `Expr`. `PrimeCharacteristicRing` is required
    /// by [`LookupMessage`] (passed by value into the `add` / `remove` /
    /// `insert` methods below).
    type Expr: PrimeCharacteristicRing + Clone;

    /// Expression type over extension-field elements. Must match the
    /// enclosing group's `ExprEF` — [`LookupMessage::encode`] returns an
    /// extension-field value and the batch's underlying algebra operates
    /// on that type. The [`Algebra<Self::Expr>`] bound mirrors the
    /// enclosing group's `ExprEF` bound.
    type ExprEF: PrimeCharacteristicRing + Clone + Algebra<Self::Expr>;

    /// Absorb an interaction with multiplicity `+1`.
    fn add<M>(&mut self, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Absorb an interaction with multiplicity `-1`.
    fn remove<M>(&mut self, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Absorb an interaction with arbitrary signed multiplicity.
    fn insert<M>(&mut self, multiplicity: Self::Expr, msg: M)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Absorb an interaction with an already-encoded denominator.
    ///
    /// Symmetric with
    /// [`EncodedLookupGroup::insert_encoded`](super::EncodedLookupGroup::insert_encoded),
    /// but at the batch scope: the closure returns the final
    /// `Self::ExprEF` value that would otherwise come out of
    /// [`LookupMessage::encode`], and the batch folds it into its
    /// running `(N, D)` pair directly. Use this when you are inside an
    /// encoded-group batch (`ge.batch(flag, |b| …)`) and have already
    /// computed the denominator from a cached fragment shared with the
    /// sibling interactions in the batch — it saves you from wrapping
    /// the pre-computed value in a throwaway `LookupMessage` impl just
    /// to satisfy the `add` / `remove` / `insert` shape.
    ///
    /// The outer batch flag still gates the whole batch; individual
    /// `insert_encoded` calls inside the closure always run (subject to
    /// that one outer gate).
    fn insert_encoded(&mut self, multiplicity: Self::Expr, encoded: impl FnOnce() -> Self::ExprEF);
}

// ENCODED LOOKUP GROUP
// ================================================================================================

/// Extension of [`LookupGroup`] that exposes the encoding primitives.
///
/// Only handed out on the constraint path of
/// [`LookupColumn::group_with_cached_encoding`] — the simple path keeps
/// challenges invisible. Use this to precompute shared encoding fragments
/// (e.g. `β⁰·addr + β¹·node_index`) once and splice the per-variant
/// bus prefix plus tail into each `insert_encoded` call.
///
/// `insert_encoded`'s closure returns the *final* denominator expression,
/// already-encoded in `Self::ExprEF`. Adapters treat the result as if it
/// had been produced by hand-reading a
/// [`LookupChallenges`](super::LookupChallenges) entry and folding in
/// the payload, so the trait imposes no shape on what lives inside the
/// closure.
pub trait EncodedLookupGroup: LookupGroup {
    /// Precomputed powers `[β⁰, β¹, …, β^(W-1)]`, where
    /// `W = max_message_width` from the enclosing
    /// [`LookupAir`](super::LookupAir).
    ///
    /// The slice length is exactly `W` — there is **no** trailing `β^W`
    /// entry, because that power is the per-bus step baked into every
    /// [`LookupChallenges::bus_prefix`](super::LookupChallenges) entry
    /// at builder-construction time. Authors that want to build their
    /// own encoded denominator loop should iterate over `beta_powers()`
    /// directly and slice to their own message width.
    ///
    /// Returned as extension-field expressions; the adapter materializes
    /// the powers once at construction time (as `AB::ExprEF` on the
    /// constraint path) and serves them back by reference.
    fn beta_powers(&self) -> &[Self::ExprEF];

    /// Look up the precomputed bus prefix
    /// `bus_prefix[bus_id] = α + (bus_id + 1) · β^W` for the given
    /// coarse bus ID.
    ///
    /// Returns an owned [`Self::ExprEF`] by cloning the entry — the
    /// underlying storage is a `Box<[ExprEF]>` on the adapter and
    /// `ExprEF` is typically a ring element, so cloning is cheap.
    ///
    /// # Panics
    ///
    /// Panics if `bus_id as usize` is out of bounds of the adapter's
    /// `num_bus_ids` — which can only happen if the
    /// [`LookupAir::num_bus_ids`](super::LookupAir::num_bus_ids)
    /// contract was violated. Authors should ensure every bus ID they
    /// emit satisfies `bus_id < num_bus_ids`.
    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF;

    /// Add a flag-gated interaction whose denominator is already an
    /// extension-field expression.
    ///
    /// - `flag`: base-field selector. Zero flags are skipped by the prover-path adapter
    ///   (constraint-path evaluates unconditionally).
    /// - `multiplicity`: base-field signed multiplicity.
    /// - `encoded`: closure producing the final denominator. Run once on the constraint path. On
    ///   the prover path the adapter may skip the call entirely when `flag == 0`.
    fn insert_encoded(
        &mut self,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
    );
}
