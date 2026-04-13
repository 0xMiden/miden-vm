//! `LookupAir` / `LookupBuilder` lookup-argument module.
//!
//! This module hosts the new closure-based LogUp bus API described in
//! `docs/src/design/lookup_air_plan.md`. It coexists with the legacy
//! `logup` / `logup_msg` modules during the multi-task refactor; the old
//! modules will be collapsed into this one once every bus has been ported
//! and `ProcessorAir::eval` is wired through `MidenLookupAir`.
//!
//! Current state (task progression):
//!
//! - **Task #1**: [`LookupMessage`] trait (see [`message`]).
//! - **Task #2**: [`LookupAir`] plus [`LookupBuilder`] / [`LookupColumn`] / [`LookupGroup`] /
//!   [`LookupBatch`] / [`EncodedLookupGroup`] (see [`builder`]). **Traits only** — no adapters live
//!   in `builder.rs`.
//! - **Task #3**: constraint-path adapter over `LiftedAirBuilder` (see [`constraint`]).
//! - **Task #11**: Amendment A rework — [`LookupChallenges`] (see [`challenges`]) replaces the old
//!   `trace::Challenges` inside the adapter; encoding switches to precomputed per-bus prefixes;
//!   [`LookupAir`] gains `num_bus_ids` alongside `num_columns` / `max_message_width`.
//! - **Task #4**: prover-path adapter over concrete field rows.
//! - **Task #5**: blanket-impl [`LookupMessage`] for the existing `*Msg` structs in `logup_msg.rs`.
//! - **Task #12**: Amendment B — [`LookupMessage::encode`] collapses the scratch buffer. All
//!   adapters strip their `scratch` fields; message encoding moves inline into each struct's
//!   `encode` method; bus IDs live in the new [`bus_id`] sub-module.
//! - **Task #6** *(this task)*: canary port — the zero-sized [`MidenLookupAir`] (see [`miden_air`])
//!   stands up the first concrete `LookupAir<LB>` implementor, wiring the block-hash queue bus
//!   (`BUS_BLOCK_HASH_TABLE`) through the closure-based API. Task #7 adds the other 7 buses.

pub mod builder;
pub mod bus_id;
mod buses;
pub mod challenges;
pub mod constraint;
#[cfg(test)]
pub mod dual_builder;
pub mod message;
pub mod miden_air;
pub mod prover;

pub use builder::{EncodedLookupGroup, LookupBatch, LookupBuilder, LookupColumn, LookupGroup};
#[expect(
    unused_imports,
    reason = "Re-exported for Task #7 bus ports; Task #6 consumes it via `use super::bus_id::NUM_BUS_IDS;` directly."
)]
pub use bus_id::NUM_BUS_IDS;
pub use challenges::LookupChallenges;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "Consumed only by the Task #6 degree-budget test until Task #8 wires ProcessorAir::eval to it."
    )
)]
pub use constraint::ConstraintLookupBuilder;
#[cfg(test)]
pub use dual_builder::{DualBuilder, GroupMismatch};
pub use message::LookupMessage;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "Consumed only by the Task #6 degree-budget test until Task #8 wires ProcessorAir::eval to it."
    )
)]
pub use miden_air::MidenLookupAir;
#[expect(
    unused_imports,
    reason = "Re-exported for Task #8 aux-trace builder; no intra-crate consumer yet."
)]
pub use prover::ProverLookupBuilder;

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
/// - [`num_columns()`](Self::num_columns) must match the number of
///   [`LookupBuilder::column`](builder::LookupBuilder::column) calls issued from
///   [`eval`](Self::eval) — the adapter advances its internal column index each time the closure
///   returns and will panic (or produce undefined constraints) on a mismatch.
/// - [`max_message_width()`](Self::max_message_width) must be ≥ the widest payload any message in
///   the AIR emits. It counts **only** contiguous payload slots — the bus identifier is handled
///   separately through the precomputed bus-prefix table.
/// - [`num_bus_ids()`](Self::num_bus_ids) must be ≥ the largest bus ID any message in the AIR
///   emits, plus one; the adapter precomputes exactly that many bus prefixes and indexes into the
///   table with `bus_id as usize`. Task #6 reports [`bus_id::NUM_BUS_IDS`] from this method.
pub trait LookupAir<LB: LookupBuilder> {
    /// Number of permutation columns this argument occupies.
    fn num_columns(&self) -> usize;

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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Only called from the Task #6 degree-budget test until Task #8 wires the live eval path."
        )
    )]
    fn eval(&self, builder: &mut LB);
}
