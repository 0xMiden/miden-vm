//! Runtime circuit representation for the precompile relation.
//!
//! Circuit construction is available in `crate::compiler::precompiles` when the `compiler`
//! feature is enabled.

pub use miden_ace_codegen::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Per-AIR trace regions are padded to this width before concatenation.
pub const LMCS_ALIGNMENT: usize = 8;
