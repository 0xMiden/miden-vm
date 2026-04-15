//! Restored chiplet-bus tests.
//!
//! Each submodule exercises a single chiplet (bitwise, hasher, memory) by verifying:
//! - the main-trace structure of the chiplet segment,
//! - the per-row deltas of the `CHIPLET_REQUESTS` (M3) and `CHIPLET_RESPONSES` (C1) aux
//!   columns against hand-constructed `LookupMessage` instances, and
//! - the closure of both columns at program end (balanced request/response pairs must
//!   telescope to zero).
//!
//! Shared harness + column constants live in [`super::lookup_harness`].

mod bitwise;
