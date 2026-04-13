//! Per-bus emitters for the Miden VM's [`super::MidenLookupAir`].
//!
//! Splits the Miden VM's 8 LogUp buses into one file each. Each emitter is a crate-private
//! `pub(in crate::constraints::lookup) fn emit_*` that opens a single
//! [`super::super::LookupBuilder::column`] closure and describes the bus's interactions via
//! [`super::super::LookupColumn::group`] or
//! [`super::super::LookupColumn::group_with_cached_encoding`]. The emitters are routed
//! through [`super::MidenLookupAir::eval`] in the order M1..M5, C1..C3 so the column indices
//! line up with the legacy `enforce_main` / `enforce_chiplet` layout.
//!
//! ## Dead-code suppression
//!
//! Until Task #8 wires `ProcessorAir::eval` into `MidenLookupAir::eval`, the only live
//! consumer of these emitters is the `miden_lookup_air_degree_within_budget` test in
//! [`super::miden_air`]. In lib-only builds every `emit_*` function, every per-bus helper
//! struct (`CreqCtx` / `CrespCtx`), and every per-bus constant (`S_START`, `ACE_OFFSET`,
//! etc.) is transitively dead. Each individual bus file carries its own
//! `#![cfg_attr(not(test), expect(dead_code, …))]` attribute to silence those warnings in
//! lib mode without masking them in test mode.

pub(in crate::constraints::lookup) mod block_hash_and_op_group;
pub(in crate::constraints::lookup) mod block_stack;
pub(in crate::constraints::lookup) mod chiplet_requests;
pub(in crate::constraints::lookup) mod chiplet_responses;
pub(in crate::constraints::lookup) mod hash_kernel;
pub(in crate::constraints::lookup) mod range_logcap;
pub(in crate::constraints::lookup) mod wiring;
