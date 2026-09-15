//! Encoded circuit artifacts shared by recursive verifier relations.

use miden_core::{Felt, Word, field::QuadFelt};

use crate::{AceCircuit, EncodedCircuit, InputLayout};

/// Encoded recursive-verifier circuit with its originating READ layout and cached commitment.
///
/// The encoding owns the instruction stream and its counts. Immutable access keeps the cached
/// commitment tied to those bytes, while artifact generators derive memory regions from the
/// layout of the same circuit build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveCircuit {
    encoded: EncodedCircuit,
    layout: InputLayout,
    commitment: Word,
}

impl RecursiveCircuit {
    /// Encode a compiler-owned circuit and retain the layout used to build it.
    pub fn from_circuit(circuit: AceCircuit<QuadFelt>) -> Self {
        let encoded = circuit.to_ace();
        let commitment = encoded.circuit_hash();
        Self {
            encoded,
            layout: circuit.layout,
            commitment,
        }
    }

    /// Encoded instruction stream and its READ/EVAL dimensions.
    pub fn encoded(&self) -> &EncodedCircuit {
        &self.encoded
    }

    /// Layout of the external READ inputs used to compile this circuit.
    pub fn layout(&self) -> &InputLayout {
        &self.layout
    }

    /// Cached Eidos digest of the full instruction stream.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Transfer the committed instruction stream into an advice-map entry without copying it.
    pub fn into_advice_entry(self) -> (Word, Vec<Felt>) {
        (self.commitment, self.encoded.into_instructions())
    }
}
