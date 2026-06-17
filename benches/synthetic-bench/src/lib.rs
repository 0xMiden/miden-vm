//! Synthetic benchmark generator for VM-level proving regression tests.
//!
//! Given a snapshot of per-component trace row counts captured by an external producer,
//! this crate calibrates a small catalog of MASM snippets against the current VM, solves
//! for iteration counts, emits a synthetic program, and verifies that the program lands
//! in the target dynamic AIR padded brackets.
//!
//! The snapshot schema has two tiers:
//! - `trace`: hard dynamic AIR totals (`core_rows`, `chiplets_rows`,
//!   `blakeg_compression_rows`)
//! - `trace.chiplets_shape`: advisory per-chiplet breakdown used by the solver
//!
//! For compatibility with older producer snapshots, the loader uses
//! `trace.chiplets_shape.hasher_rows` when `blakeg_compression_rows` is absent.
//!
//! See `README.md` for design rationale.

pub mod calibrator;
pub mod snapshot;
pub mod snippets;
pub mod solver;
pub mod verifier;
