//! Runtime circuit representation for the precompile relation.
//!
//! Circuit construction lives in `crate::compiler::precompiles` with the `compiler` feature.

pub use miden_ace::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Per-AIR trace regions are padded to this width before concatenation.
pub const LMCS_ALIGNMENT: usize = 8;
