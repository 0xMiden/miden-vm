//! Symbolic circuit construction for the authored precompile relation.

use miden_ace_codegen::{AceCircuit, AceError, LayoutKind};
use miden_core::field::QuadFelt;

use super::PvmRecursiveAceCircuit;
use crate::precompiles::relation::CapturedPvmRelation;

/// Builds the canonical precompile chiplet ACE circuit.
pub fn build_canonical_precompile_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    CapturedPvmRelation::new()?.compile()?.build_circuit(LayoutKind::Masm)
}

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// Callers needing the circuit for multiple proofs should cache the encoded result.
pub fn build_pvm_recursive_verifier_ace_circuit() -> Result<PvmRecursiveAceCircuit, AceError> {
    let encoded = build_canonical_precompile_ace_circuit()?.to_ace()?;
    encoded.try_into()
}
