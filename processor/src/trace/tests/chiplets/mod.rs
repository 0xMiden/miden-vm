//! Chiplet-bus tests (bitwise, hasher, memory).
//!
//! Each submodule drives a small program against the relevant chiplet and asserts that every
//! chiplet-request (`-1` push) the constraints expect, and every chiplet-response (`+1` push)
//! the chiplet emits, shows up in the prover's `(mult, denom)` bag at the right row. The
//! subset matcher in [`super::lookup_harness`] is column-blind, so a test passes regardless
//! of which aux column the framework routes a given bus message onto.
//!
//! Tests pair the subset match with explicit cardinality guardrails (e.g. "exactly 2 HOUT
//! adds") so a silent-pass bug — extra emissions, missing emissions, or the matcher ignoring
//! a whole category — fails structurally rather than just by shape.

mod bitwise;
mod hasher;
mod memory;
