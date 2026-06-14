//! Closure-based builder traits for the LogUp lookup API.
//!
//! This file defines only the author-facing traits. The constraint and prover adapters implement
//! the traits in sibling modules.

use miden_core::field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};
use miden_crypto::stark::air::WindowAccess;

use super::message::LookupMessage;

// DEGREE ANNOTATION
// ================================================================================================

/// Expected post-flag `(V, U)` contribution for one interaction or scope.
///
/// Every builder method takes a `Deg` so debug adapters can check declared degrees against the
/// symbolic expression they just accumulated. Production adapters ignore it.
///
/// - `v`: degree of the numerator (`V`) contribution after multiplying by the surrounding flag.
/// - `u`: degree of the denominator (`U`) contribution after multiplying by the surrounding flag.
///
/// Field order mirrors the `(V, U)` tuple convention used throughout the
/// adapter code: numerator first, denominator second.
///
/// Single interactions use the degree of their standalone post-flag contribution. Batch, group,
/// and column scopes use the degree of the total `(V, U)` pair they contribute to the enclosing
/// scope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Deg {
    pub v: usize,
    pub u: usize,
}

// LOOKUP BUILDER
// ================================================================================================

/// The trace-reading handle handed to a [`super::LookupAir`] implementation.
///
/// `LookupBuilder` exposes trace access and per-column scoping. It hides constraint emission,
/// permutation columns, and challenge access from lookup authors.
///
/// Implementors must not shortcut the per-column scoping: a [`super::LookupAir`]
/// author that opens `n` columns must issue exactly `n` calls to
/// [`LookupBuilder::next_column`], matching [`super::LookupAir::num_columns`].
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
    /// columns and the alpha/beta challenges).
    type VarEF: Into<Self::ExprEF> + Copy + Send + Sync;

    // --- auxiliary trace access types ---

    /// Periodic column value at the current row (copied from
    /// `PeriodicAirBuilder::PeriodicVar`).
    type PeriodicVar: Into<Self::Expr> + Copy;

    /// Two-row window over the main trace, returned as-is from the
    /// underlying builder. Pinned to [`WindowAccess`] + `Clone` so a
    /// lookup author can split it into `current_slice()` / `next_slice()`
    /// and pass either to `borrow`-based view types without re-reading
    /// the handle.
    type MainWindow: WindowAccess<Self::Var> + Clone;

    /// Two-row preprocessed trace window. Empty for AIRs without preprocessed columns.
    type PreprocessedWindow: WindowAccess<Self::Var> + Clone;

    /// Per-column handle opened by [`Self::next_column`]. Holds the adapter's per-column
    /// state (running `(V, U)` on the constraint path, fraction collector on the prover
    /// path) for the column's closure.
    type Column<'a>: LookupColumn<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    // ---- trace access ----

    /// Two-row main trace window. Pass-through to the wrapped builder.
    fn main(&self) -> Self::MainWindow;

    /// Two-row preprocessed trace window.
    fn preprocessed(&self) -> &Self::PreprocessedWindow;

    /// Periodic column values at the current row.
    fn periodic_values(&self) -> &[Self::PeriodicVar];

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
    /// 4. Advancing to the next permutation column index so the next call targets a fresh
    ///    accumulator.
    ///
    /// The closure's return value `R` is forwarded unchanged.
    fn next_column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R, deg: Deg) -> R;
}

// LOOKUP COLUMN
// ================================================================================================

/// Per-column handle returned by [`LookupBuilder::next_column`].
///
/// The only decision a column makes is how to open a group: either the
/// simple path via [`group`](Self::group) or the dual cached-encoding path
/// via [`group_with_cached_encoding`](Self::group_with_cached_encoding).
///
/// Multiple groups may be opened per column; the adapter is responsible
/// for composing them according to the column accumulator algebra
/// (`V <- V*U_g + V_g*U`, `U <- U*U_g`). Groups opened inside the same
/// column are assumed *product-closed*, not mutually exclusive.
pub trait LookupColumn {
    /// Expression type over base-field elements. Pinned to
    /// [`LookupBuilder::Expr`] through [`LookupBuilder::Column`].
    type Expr: PrimeCharacteristicRing + Clone;

    /// Expression type over extension-field elements. Pinned to
    /// [`LookupBuilder::ExprEF`] through [`LookupBuilder::Column`]. The
    /// [`Algebra<Self::Expr>`] bound lets [`LookupMessage::encode`]
    /// multiply an `Expr`-typed payload slot by an `ExprEF`-typed
    /// beta-power without manually lifting.
    type ExprEF: PrimeCharacteristicRing + Clone + Algebra<Self::Expr>;

    /// Per-group handle used for the simple (challenge-free) path.
    type Group<'a>: LookupGroup<Expr = Self::Expr, ExprEF = Self::ExprEF>
    where
        Self: 'a;

    /// Open a group using the simple, challenge-free API.
    ///
    /// Every interaction added inside the closure is folded into this
    /// group's `(V_g, U_g)` pair; on close, the column composes the pair
    /// into its running accumulator.
    fn group<'a>(&'a mut self, name: &'static str, f: impl FnOnce(&mut Self::Group<'a>), deg: Deg);

    /// Open a group with two sibling descriptions for the same
    /// interaction set.
    ///
    /// - `canonical` runs on the prover path. It sees the simple [`LookupGroup`] surface - no
    ///   challenges, no `insert_encoded`. Zero-valued flag closures are skipped by the backing
    ///   fraction collector.
    /// - `encoded` runs on the constraint path. It sees the same [`LookupGroup`] surface, plus the
    ///   encoding primitives `beta_powers()`, `bus_prefix()`, and `insert_encoded()`. Authors use
    ///   this to precompute shared encoding fragments (e.g. a common `alpha + beta*addr` prefix) and reuse
    ///   them across mutually-exclusive variants.
    ///
    /// Both closures must produce mathematically identical `(V, U)`
    /// pairs; the split is purely an optimization for expensive
    /// extension-field arithmetic on the symbolic path. Adapters are
    /// free to drop whichever closure they do not use.
    fn group_with_cached_encoding<'a>(
        &'a mut self,
        name: &'static str,
        canonical: impl FnOnce(&mut Self::Group<'a>),
        encoded: impl FnOnce(&mut Self::Group<'a>),
        deg: Deg,
    );
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
    /// and lets [`LookupMessage::encode`] use `ExprEF * Expr` products.
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
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `ONE`.
    /// Adapters may override for optimization (e.g. the constraint path avoids
    /// the redundant `flag * ONE` symbolic node).
    fn add<M>(&mut self, name: &'static str, flag: Self::Expr, msg: impl FnOnce() -> M, deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.insert(name, flag, Self::Expr::ONE, msg, deg);
    }

    /// Add a single interaction with multiplicity `-1`, gated by `flag`.
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `NEG_ONE`.
    fn remove<M>(&mut self, name: &'static str, flag: Self::Expr, msg: impl FnOnce() -> M, deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.insert(name, flag, Self::Expr::NEG_ONE, msg, deg);
    }

    /// Add a single interaction with explicit signed multiplicity, gated
    /// by `flag`.
    ///
    /// `multiplicity` is a base-field expression so callers can mix
    /// trace columns, constants, and boolean selectors freely.
    fn insert<M>(
        &mut self,
        name: &'static str,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        msg: impl FnOnce() -> M,
        deg: Deg,
    ) where
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
    fn batch<'a>(
        &'a mut self,
        name: &'static str,
        flag: Self::Expr,
        build: impl FnOnce(&mut Self::Batch<'a>),
        deg: Deg,
    );

    /// Open an ungated batch of two pre-encoded linear denominators.
    ///
    /// This is the selected-slot pattern used by the BlakeG AIR: row selection
    /// lives in the two multiplicities, and the batch contributes
    /// `(m0 * D1 + m1 * D0) / (D0 * D1)`.
    fn selected_batch2_encoded(
        &mut self,
        name: &'static str,
        slot0_name: &'static str,
        slot0_multiplicity: Self::Expr,
        slot0_encoded: impl FnOnce() -> Self::ExprEF,
        slot1_name: &'static str,
        slot1_multiplicity: Self::Expr,
        slot1_encoded: impl FnOnce() -> Self::ExprEF,
    ) {
        self.batch(
            name,
            Self::Expr::ONE,
            |batch| {
                batch.insert_encoded(
                    slot0_name,
                    slot0_multiplicity,
                    slot0_encoded,
                    Deg { v: 1, u: 1 },
                );
                batch.insert_encoded(
                    slot1_name,
                    slot1_multiplicity,
                    slot1_encoded,
                    Deg { v: 1, u: 1 },
                );
            },
            Deg { v: 2, u: 2 },
        );
    }

    // ---- encoding primitives (cached-encoding path only) ----

    /// Precomputed powers `[beta^0, beta^1, ..., beta^(W-1)]`, where
    /// `W = max_message_width` from the enclosing
    /// [`LookupAir`](super::LookupAir).
    ///
    /// The slice length is exactly `W` - there is **no** trailing `beta^W`
    /// entry, because that power is the per-bus step baked into every
    /// [`Challenges::bus_prefix`](super::Challenges) entry
    /// at builder-construction time. Authors that want to build their
    /// own encoded denominator loop should iterate over `beta_powers()`
    /// directly and slice to their own message width.
    ///
    /// Returned as extension-field expressions; the adapter materializes
    /// the powers once at construction time (as `AB::ExprEF` on the
    /// constraint path) and serves them back by reference.
    ///
    /// # Panics
    ///
    /// Default implementation panics - only valid inside the `encoded`
    /// closure of [`LookupColumn::group_with_cached_encoding`].
    fn beta_powers(&self) -> &[Self::ExprEF] {
        panic!(
            "beta_powers() is only available inside the `encoded` closure of group_with_cached_encoding"
        )
    }

    /// Look up the precomputed bus prefix
    /// `bus_prefix[bus_id] = alpha + (bus_id + 1) * beta^W` for the given
    /// coarse bus ID.
    ///
    /// Returns an owned [`Self::ExprEF`] by cloning the adapter entry.
    ///
    /// # Panics
    ///
    /// Default implementation panics - only valid inside the `encoded`
    /// closure of [`LookupColumn::group_with_cached_encoding`].
    /// Also panics if `bus_id` is out of bounds of the adapter's
    /// `num_bus_ids`.
    fn bus_prefix(&self, bus_id: usize) -> Self::ExprEF {
        let _ = bus_id;
        panic!(
            "bus_prefix() is only available inside the `encoded` closure of group_with_cached_encoding"
        )
    }

    /// Add a flag-gated interaction whose denominator is already an
    /// extension-field expression.
    ///
    /// - `flag`: base-field selector. Zero flags are skipped by the prover-path adapter
    ///   (constraint-path evaluates unconditionally).
    /// - `multiplicity`: base-field signed multiplicity.
    /// - `encoded`: closure producing the final denominator. Run once on the constraint path. On
    ///   the prover path the adapter may skip the call entirely when `flag == 0`.
    ///
    /// # Panics
    ///
    /// Default implementation panics - only valid inside the `encoded`
    /// closure of [`LookupColumn::group_with_cached_encoding`].
    fn insert_encoded(
        &mut self,
        _name: &'static str,
        _flag: Self::Expr,
        _multiplicity: Self::Expr,
        _encoded: impl FnOnce() -> Self::ExprEF,
        _deg: Deg,
    ) {
        panic!(
            "insert_encoded() is only available inside the `encoded` closure of group_with_cached_encoding"
        )
    }
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
    /// enclosing group's `ExprEF` - [`LookupMessage::encode`] returns an
    /// extension-field value and the batch's underlying algebra operates
    /// on that type. The [`Algebra<Self::Expr>`] bound mirrors the
    /// enclosing group's `ExprEF` bound.
    type ExprEF: PrimeCharacteristicRing + Clone + Algebra<Self::Expr>;

    /// Absorb an interaction with multiplicity `+1`.
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `ONE`.
    fn add<M>(&mut self, name: &'static str, msg: M, deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.insert(name, Self::Expr::ONE, msg, deg);
    }

    /// Absorb an interaction with multiplicity `-1`.
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `NEG_ONE`.
    fn remove<M>(&mut self, name: &'static str, msg: M, deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>,
    {
        self.insert(name, Self::Expr::NEG_ONE, msg, deg);
    }

    /// Absorb an interaction with arbitrary signed multiplicity.
    fn insert<M>(&mut self, name: &'static str, multiplicity: Self::Expr, msg: M, deg: Deg)
    where
        M: LookupMessage<Self::Expr, Self::ExprEF>;

    /// Absorb an interaction with an already-encoded denominator.
    fn insert_encoded(
        &mut self,
        name: &'static str,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
        deg: Deg,
    );
}

// BOUNDARY BUILDER
// ================================================================================================

/// Handle for emitting **once-per-proof** "outer" interactions - contributions to the
/// LogUp sum that are not tied to any main-trace row.
///
/// Typical sources are committed-final boundary terminals (kernel ROM init, block hash
/// seed, log-precompile terminals, public-input bus seeds). Each emission contributes
/// one signed fraction to the overall balance; no column / row / group scoping, no
/// flag gating, no `Deg` (boundary terms are plain field elements, not polynomials).
///
/// Used by [`super::LookupAir::eval_boundary`]. Default implementations on the trait
/// are a no-op, so AIRs with no boundary contributions don't need to override it.
pub trait BoundaryBuilder {
    /// Base field for boundary-interaction multiplicities and encoded message slots.
    type F: Field;

    /// Extension field used by [`LookupMessage::encode`] - matches the enclosing
    /// `LookupAir`'s `LB::EF`.
    type EF: ExtensionField<Self::F>;

    /// Public values passed to the proof (the `public_values` slice threaded through
    /// `prove_stark`).
    fn public_values(&self) -> &[Self::F];

    /// Variable-length public inputs (e.g. kernel felts). Matches the layout the
    /// prover hands to `miden_crypto::stark::prover::prove_single`.
    fn var_len_public_inputs(&self) -> &[&[Self::F]];

    /// Emit a boundary interaction with multiplicity `+1`.
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `ONE`.
    fn add<M>(&mut self, name: &'static str, msg: M)
    where
        M: LookupMessage<Self::F, Self::EF>,
    {
        self.insert(name, Self::F::ONE, msg);
    }

    /// Emit a boundary interaction with multiplicity `-1`.
    ///
    /// The default delegates to [`insert`](Self::insert) with multiplicity `NEG_ONE`.
    fn remove<M>(&mut self, name: &'static str, msg: M)
    where
        M: LookupMessage<Self::F, Self::EF>,
    {
        self.insert(name, Self::F::NEG_ONE, msg);
    }

    /// Emit a boundary interaction with an arbitrary signed multiplicity.
    fn insert<M>(&mut self, name: &'static str, multiplicity: Self::F, msg: M)
    where
        M: LookupMessage<Self::F, Self::EF>;
}
