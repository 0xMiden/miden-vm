use alloc::vec::Vec;

use miden_ace_codegen::{AceConfig, AceError, LayoutKind};
use miden_core::{Felt, Word};

use super::multi_air::build_multi_air_ace_circuit_for_order;
use crate::ProofOrder;

/// ACE codegen settings used by the recursive verifier's MASM evaluator.
const RECURSIVE_VERIFIER_ACE_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    num_vlpi_groups: 1,
    layout: LayoutKind::Masm,
};

/// Encoded recursive-verifier ACE circuit and the metadata consumed by MASM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveAceCircuit {
    /// Number of ACE READ variables.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Encoded instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Hash of `instructions`; used as the registry leaf and advice-map key.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

/// Builds and encodes the recursive-verifier ACE circuit for one proof order.
pub fn build_recursive_verifier_ace_circuit(
    order: &ProofOrder,
) -> Result<RecursiveAceCircuit, AceError> {
    let circuit = build_multi_air_ace_circuit_for_order::<miden_core::field::QuadFelt>(
        RECURSIVE_VERIFIER_ACE_CONFIG,
        order,
    )?;
    let encoded = circuit.to_ace()?;
    let instructions = encoded.instructions();
    let stream_len = encoded.size_in_felt();
    if stream_len != instructions.len() {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "ACE circuit stream length ({stream_len}) does not match instruction count ({})",
                instructions.len()
            ),
        });
    }
    if !stream_len.is_multiple_of(8) {
        return Err(AceError::InvalidInputLayout {
            message: "ACE circuit stream must be 8-felt aligned for adv_pipe".into(),
        });
    }

    Ok(RecursiveAceCircuit {
        num_inputs: encoded.num_vars(),
        num_eval_gates: encoded.num_eval_rows(),
        stream_len,
        commitment: encoded.circuit_hash(),
        instructions: instructions.to_vec(),
    })
}
