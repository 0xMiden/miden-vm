//! Pure synthetic benchmark data model and program-generation logic.
//!
//! This crate deliberately avoids depending on the VM, processor, Criterion, or CodSpeed. The
//! benchmark harness crate owns calibration and measurement against the real VM.

pub mod snapshot;
pub mod snippets;
pub mod solver;
pub mod verifier;
