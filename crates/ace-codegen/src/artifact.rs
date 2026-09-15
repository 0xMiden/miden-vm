//! Encoded circuit artifacts shared by recursive verifier relations.

use miden_core::{Felt, Word, field::QuadFelt};

use crate::{AceCircuit, InputLayout};

/// Encoded recursive-verifier circuit with its READ layout and MASM metadata.
///
/// One aligned instruction segment is authenticated by `commitment`. Keeping the layout with
/// that segment lets artifact generators derive memory regions from the same circuit build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveCircuit {
    /// Number of ACE READ variables, including encoded constants and padding.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Encoded instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Eidos digest of the full instruction stream.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
    /// Layout of the external READ inputs used to compile this circuit.
    pub input_layout: InputLayout,
}

impl RecursiveCircuit {
    /// Encode a compiler-owned circuit and retain the layout used to build it.
    pub fn from_circuit(circuit: AceCircuit<QuadFelt>) -> Self {
        let encoded = circuit.to_ace();
        Self {
            num_inputs: encoded.num_vars(),
            num_eval_gates: encoded.num_eval_rows(),
            stream_len: encoded.size_in_felt(),
            commitment: encoded.circuit_hash(),
            instructions: encoded.instructions().to_vec(),
            input_layout: circuit.layout().clone(),
        }
    }
}
