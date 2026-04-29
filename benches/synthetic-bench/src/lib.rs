//! Synthetic benchmark generator for VM-level proving regression tests.
//!
//! Given a snapshot of per-component trace row counts captured by an external producer,
//! this crate calibrates a small catalog of MASM snippets against the current VM, solves
//! for iteration counts, emits a synthetic program, and verifies that the program lands
//! in the target core/chiplets padded brackets.
//!
//! The snapshot schema has two tiers:
//! - `trace`: hard totals (`core_rows`, `chiplets_rows`, `range_rows`)
//! - `shape`: advisory per-chiplet breakdown used by the solver
//!
//! See `README.md` for design rationale.

pub mod calibrator;
pub mod snapshot;
pub mod snippets;
pub mod solver;
pub mod verifier;
