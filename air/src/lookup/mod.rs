//! Generic `LookupAir` / `LookupBuilder` lookup-argument module.
//!
//! Holds the field-polymorphic core of the closure-based LogUp machinery: the
//! [`LookupAir`] trait, the [`LookupBuilder`] / [`LookupColumn`] / [`LookupGroup`] /
//! [`LookupBatch`] surface, the [`Challenges`] struct, the [`LookupMessage`] encode trait,
//! the two-path adapters ([`ConstraintLookupBuilder`] for symbolic constraint
//! evaluation, [`ProverLookupBuilder`] for concrete-row fraction collection), the
//! [`LookupFractions`] accumulator, and the [`build_logup_aux`] / [`build_lookup_fractions`]
//! drivers.
//!
//! The Miden-specific wiring — `MidenLookupAir`, the `buses/*` emitters, the
//! [`MidenLookupAuxBuilder`](crate::constraints::lookup::MidenLookupAuxBuilder)
//! [`AuxBuilder`] wrapper, and the degree-budget / bus-id constants — lives in
//! [`crate::constraints::lookup`]. The split keeps this module free of Miden-specific
//! types so it can eventually become its own crate without further disentangling.

#![allow(dead_code, unused_imports)]

pub mod aux_builder;
pub mod builder;
pub mod challenges;
pub mod constraint;
#[cfg(any(test, feature = "bus-debug"))]
pub mod debug;
pub mod fractions;
pub mod message;
pub mod prover;

pub use aux_builder::build_logup_aux;
pub use builder::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup};
pub use challenges::Challenges;
pub use constraint::ConstraintLookupBuilder;
pub use fractions::{LookupFractions, accumulate, accumulate_slow};
pub use message::LookupMessage;
pub use prover::{ProverLookupBuilder, build_lookup_fractions};

// Miden-side re-exports for ergonomic access via `miden_air::lookup::*`. The canonical
// definitions live in [`crate::constraints::lookup`] and [`crate::constraints::logup_msg`].
pub use crate::constraints::logup_msg::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
pub use crate::constraints::lookup::{MidenLookupAir, MidenLookupAuxBuilder};
#[cfg(feature = "bus-debug")]
pub use crate::lookup::debug::oracle::{ColumnOracleBuilder, collect_column_oracle_folds};

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
///   table with `bus_id as usize`.
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
