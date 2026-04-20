//! `LookupAir` / `LookupBuilder` lookup-argument module.
//!
//! This module hosts the closure-based LogUp bus API. It coexists with the
//! legacy `logup` / `logup_msg` modules during the multi-task refactor; the
//! old modules will be collapsed into this one once every bus has been
//! ported and `ProcessorAir::eval` is wired through `MidenLookupAir`.
//!
//! The whole subtree is gated by a single module-wide
//! `#![allow(dead_code, unused_imports)]` because several adapters and
//! helpers have no live consumer until the Task #8 wiring into
//! `ProcessorAir::eval` lands. Lint levels propagate down to the
//! submodules (`builder.rs`, `bus_id.rs`, `constraint.rs`, `prover.rs`,
//! `debug/` …), so individual files do not need their own
//! `expect` / `allow` attributes.
//!
//! ### Debugging
//!
//! The [`debug`] submodule consolidates every LogUp debugging / checking builder (inventory,
//! symbolic degree pass, scope enforcement, canonical-vs-encoded equivalence, real-trace
//! balance, per-row oracle). See its docs for entry points.

#![allow(dead_code, unused_imports)]

pub mod aux_builder;
pub mod builder;
pub mod bus_id;
pub(crate) mod buses;
pub mod challenges;
pub mod chiplet_air;
pub mod constraint;
#[cfg(any(test, feature = "bus-debug"))]
pub mod debug;
mod extension_impls;
pub mod fractions;
pub mod main_air;
pub mod message;
pub mod miden_air;
pub mod prover;

pub use aux_builder::MidenLookupAuxBuilder;
pub use builder::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup};
pub use bus_id::NUM_BUS_IDS;
pub use challenges::LookupChallenges;
pub use constraint::ConstraintLookupBuilder;
#[cfg(any(test, feature = "bus-debug"))]
pub use debug::equivalence::{EquivalenceChecker as DualBuilder, GroupMismatch};
#[cfg(any(test, feature = "bus-debug"))]
pub use debug::oracle::{ColumnOracleBuilder, collect_column_oracle_folds};
pub use fractions::{LookupFractions, accumulate, accumulate_slow};
pub use message::LookupMessage;
pub use miden_air::MidenLookupAir;
pub use prover::{ProverLookupBuilder, build_lookup_fractions};

// LOOKUP AIR
// ================================================================================================

/// A declarative LogUp lookup argument.
///
/// Shaped the same way as `p3_air::Air<AB>`: generic over the builder
/// the caller picks, and evaluated once per logical "row pair" (the
/// constraint path visits every row symbolically, the prover path visits
/// every concrete row).
///
/// The trait carries both the static *shape* (column count, payload
/// width bound, bus-id upper bound) and the `eval` method that actually
/// emits the interactions. Adapter constructors take a `&impl
/// LookupAir<Self>` and read the shape via the trait — the `LB` type
/// parameter is pinned to the adapter itself, so there is no
/// ambiguity when the blanket `impl<LB: LookupBuilder> LookupAir<LB>
/// for MyAir` implementations apply.
///
/// ## Contract
///
/// - [`num_columns()`](Self::num_columns) must match the number of `LookupBuilder::next_column`
///   calls issued from [`eval`](Self::eval) — the adapter advances its internal column index each
///   time the closure returns and will panic (or produce undefined constraints) on a mismatch.
/// - [`max_message_width()`](Self::max_message_width) must be ≥ the widest payload any message in
///   the AIR emits. It counts **only** contiguous payload slots — the bus identifier is handled
///   separately through the precomputed bus-prefix table.
/// - [`num_bus_ids()`](Self::num_bus_ids) must be ≥ the largest bus ID any message in the AIR
///   emits, plus one; the adapter precomputes exactly that many bus prefixes and indexes into the
///   table with `bus_id as usize`. Task #6 reports `NUM_BUS_IDS` from this method.
pub trait LookupAir<LB: LookupBuilder> {
    /// Number of permutation columns this argument occupies.
    fn num_columns(&self) -> usize;

    /// Per-column upper bound on the number of fractions a single row can push.
    ///
    /// Length must equal [`num_columns()`](Self::num_columns). Each entry is the
    /// **mutual-exclusion-aware** max — i.e. the largest active branch count taken across
    /// all mutually exclusive groups inside the column, not the sum of every structural
    /// `add` / `remove` / `insert` / `batch` push site.
    ///
    /// The prover-path adapter uses this to size the dense per-column fraction buffer
    /// (`Vec::with_capacity`) so the hot row loop never re-allocates.
    fn column_shape(&self) -> &[usize];

    /// Upper bound on the **payload** width of any message emitted by
    /// [`eval`](Self::eval), exclusive of the bus identifier slot.
    fn max_message_width(&self) -> usize;

    /// Upper bound on any bus ID this AIR emits through
    /// [`LookupMessage::encode`](message::LookupMessage::encode),
    /// plus one. The adapter pre-computes that many bus prefixes at
    /// construction time and indexes into the table with
    /// `bus_id as usize`.
    fn num_bus_ids(&self) -> usize;

    /// Evaluate the lookup argument, describing its interactions through
    /// the builder's closure API.
    fn eval(&self, builder: &mut LB);
}
