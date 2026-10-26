//! Runtime circuit representation and optional compiler for the precompile relation.

#[cfg(feature = "compiler")]
mod compiler;

#[cfg(feature = "compiler")]
pub use compiler::{
    build_canonical_precompile_ace_circuit, build_pvm_recursive_verifier_ace_circuit,
};
pub use miden_ace_codegen::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Per-AIR trace regions are padded to this width before concatenation.
pub const LMCS_ALIGNMENT: usize = 8;
