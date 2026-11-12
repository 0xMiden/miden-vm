//! Physical lookup-column emitters for the Miden VM's LogUp argument.
//!
//! The Miden VM's LogUp buses are emitted across 8 columns — most host a single bus, but
//! several host two or more linearly-independent buses sharing one running accumulator via
//! distinct `bus_prefix[bus]` additive bases (see per-bus module docs for the merges).
//! Each emitter opens one [`miden_stark::lookup::LookupBuilder::next_column`] closure and fixes
//! group placement, column degree, and per-row fraction capacity. AEAD and Merkle logic lives in
//! [`super::operations`]; these emitters call it inside the appropriate column groups.
//!
//! ## Shared merge rules
//!
//! A [`miden_stark::lookup::LookupColumn::group`] assumes its top-level entries are mutually
//! exclusive, so the column degree is the max over active branches. Simultaneous fractions belong
//! in a [`miden_stark::lookup::LookupGroup::batch`] with an explicit degree. If two interaction
//! families are not mutually exclusive, they must be emitted as sibling groups; sibling groups
//! compose product-wise and increase the column degree accordingly.
//!
//! Some columns merge multiple bus families into one group. This is valid only when their
//! row selectors are mutually exclusive. Each bus still has its own `bus_prefix[bus]`.
//!
//! The emitters are routed per-AIR:
//! - [`super::main_air::MainLookupAir`] for the main-trace columns, driven by
//!   [`crate::vm::CoreAir`]'s `LookupAir` impl.
//! - [`super::chiplet_air::emit_chiplet_lookup_columns`] for the chiplet-trace columns, driven by
//!   [`crate::vm::ChipletsAir`]'s `LookupAir` impl.
//! - [`crate::vm::constraints::eidos_compression::lookup`] for the standalone Eidos compression
//!   columns, driven by [`crate::vm::EidosCompressionAir`]'s `LookupAir` impl.
//! - [`crate::vm::constraints::and8_lookup`] for the fixed byte-table columns, driven by
//!   [`crate::vm::And8LookupAir`]'s `LookupAir` impl.
//!
//! ## Shared precompute contexts
//!
//! The main-trace and chiplet-trace contexts live next to their respective LookupAirs:
//! - [`super::main_air::MainBusContext`]: two-row window plus the shared [`LookupOpFlags`] instance
//!   consumed by the 4 main-trace emitters.
//! - [`super::chiplet_air::ChipletBusContext`]: two-row window plus the shared
//!   [`ChipletActiveFlags`](crate::vm::constraints::chiplets::selectors::ChipletActiveFlags)
//!   snapshot consumed by the 4 chiplet-trace emitters.
//!
//! Each context is built once per `eval` through an extension-trait hook
//! ([`super::main_air::MainLookupBuilder::build_op_flags`] /
//! [`super::chiplet_air::ChipletLookupBuilder::build_chiplet_active`]). Prover-side
//! implementations can override those hooks with boolean fast paths without changing
//! emitter code. Chiplet membership is decoded centrally by
//! [`crate::vm::constraints::chiplets::selectors`].

pub(in crate::vm::constraints::lookup) mod block_hash_and_op_group;
pub(in crate::vm::constraints::lookup) mod block_stack_and_range_logcap;
pub(in crate::vm::constraints::lookup) mod chiplet_requests;
pub(in crate::vm::constraints::lookup) mod chiplet_responses;
pub(in crate::vm::constraints::lookup) mod hash_kernel;
pub(in crate::vm::constraints::lookup) mod hasher_returns;
pub(in crate::vm::constraints::lookup) mod lookup_op_flags;
pub(in crate::vm::constraints::lookup) mod stack_overflow;
pub(in crate::vm::constraints::lookup) mod wiring;

pub(in crate::vm::constraints::lookup) use lookup_op_flags::LookupOpFlags;
