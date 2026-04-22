//! Restored chiplet-bus tests.
//!
//! Each submodule exercises a single chiplet (bitwise, hasher, memory) by verifying that every
//! expected `LookupMessage` interaction appears in the prover-path push bag for its row (subset
//! semantics; column-blind). Closure of each bus is not asserted here — the verifier enforces
//! that at prove+verify time.
//!
//! Shared harness lives in [`super::lookup_harness`].

mod bitwise;
mod hasher;
mod memory;
