#[cfg(feature = "compiler")]
use miden_ace::{AceCircuit, AceError, LayoutKind};
#[cfg(feature = "compiler")]
use miden_core::field::QuadFelt;

#[cfg(feature = "compiler")]
use crate::precompiles::relation::CapturedPvmRelation;

/// Per-AIR trace regions are padded to this width before concatenation.
pub const LMCS_ALIGNMENT: usize = 8;

/// Builds the canonical precompile chiplet ACE circuit.
#[cfg(feature = "compiler")]
pub fn build_canonical_precompile_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    CapturedPvmRelation::new()?.compile()?.build_circuit(LayoutKind::Masm)
}

// RECURSIVE VERIFIER CIRCUIT
// ================================================================================================

pub use miden_ace::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// Callers needing the circuit for multiple proofs should cache the encoded result.
#[cfg(feature = "compiler")]
pub fn build_pvm_recursive_verifier_ace_circuit() -> Result<PvmRecursiveAceCircuit, AceError> {
    let encoded = build_canonical_precompile_ace_circuit()?.to_ace()?;
    encoded.try_into()
}
