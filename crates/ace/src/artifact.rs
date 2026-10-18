//! Compiler-owned encoding, originating READ layout and cached instruction commitment.

use miden_core::{Felt, Word};
use miden_crypto::field::ExtensionField;

use crate::{AceCircuit, EncodedCircuit, InputLayout, RecursiveAceCircuit};

/// One compiled circuit and the layout from which its external READ inputs were emitted.
///
/// Immutable access keeps the cached commitment tied to the encoded bytes. This artifact is
/// available only with `compiler`; production relations load canonical precompiled bytes.
#[derive(Clone, Debug)]
pub struct CompiledCircuit {
    encoded: EncodedCircuit,
    layout: InputLayout,
    commitment: Word,
}

impl CompiledCircuit {
    /// Encode a compiler-owned circuit, moving its layout and caching its commitment.
    pub fn from_circuit<EF: ExtensionField<Felt>>(circuit: AceCircuit<EF>) -> Self {
        let encoded = circuit.to_ace();
        let commitment = encoded.circuit_hash();
        Self {
            encoded,
            layout: circuit.layout,
            commitment,
        }
    }

    pub fn encoded(&self) -> &EncodedCircuit {
        &self.encoded
    }

    pub fn layout(&self) -> &InputLayout {
        &self.layout
    }

    pub fn commitment(&self) -> Word {
        self.commitment
    }
}

impl From<CompiledCircuit> for RecursiveAceCircuit {
    fn from(compiled: CompiledCircuit) -> Self {
        Self::from_committed(compiled.encoded, compiled.commitment)
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::QuadFelt;

    use super::*;
    use crate::{DagBuilder, InputCounts, InputKey, emit_circuit};

    #[test]
    fn compiled_layout_and_commitment_follow_the_owned_stream() {
        let layout = InputLayout::new_masm(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 2,
            num_randomness: 2,
            num_quotient_chunks: 1,
        });
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let root = builder.sub(a, b);
        let compiled = CompiledCircuit::from_circuit(emit_circuit(&builder.build(root), layout));
        let decoded =
            EncodedCircuit::from_canonical_bytes(&compiled.encoded().to_canonical_bytes())
                .expect("compiler output must pass the independent external codec");
        assert_eq!(decoded.num_inputs(), compiled.layout().total_inputs);
        assert_eq!(decoded.circuit_hash(), compiled.commitment());
        let instructions = compiled.encoded().instructions().as_ptr();
        let recursive = RecursiveAceCircuit::from(compiled);
        assert_eq!(recursive.instructions.as_ptr(), instructions, "conversion moves the stream");
        assert_eq!(recursive.instructions, decoded.instructions());
        assert_eq!(recursive.commitment, decoded.circuit_hash());
    }
}
