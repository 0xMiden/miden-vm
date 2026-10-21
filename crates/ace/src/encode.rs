//! ACE circuit encoding for the chiplet format.
//!
//! Encoding rules:
//! - The READ section stores extension-field (EF) elements; each EF occupies two base-field
//!   elements.
//! - Each ACE READ row consumes two EF elements (four base-field elements or a `Word`).
//! - The EVAL section stores one operation per row, encoded as a single base-field element.
//!
//! The encoded stream concatenates constants (EF) followed by operations
//! (base-field), then pads to an `adv_pipe` block boundary.

use alloc::vec::Vec;

use miden_crypto::{Felt, Word, hash::eidos::Eidos};

use crate::AceError;

#[cfg(feature = "compiler")]
mod compiler;
#[cfg(all(test, feature = "compiler"))]
pub(crate) use compiler::StreamGeometry;

// NOTE: `num_vars`/`num_const_nodes` count extension-field (EF) nodes, while the
// instruction stream (`instructions.len()`) is measured in base field elements.

/// Number of base field elements per extension field element.
const BASE_FELTS_PER_EF: usize = crate::EXT_DEGREE;
/// Number of EF nodes read per ACE READ row (two EF per row).
const ACE_READ_ROW_EF_NODES: usize = 2;
/// Instruction stream padding unit in base felts (adv_pipe block size), so that
/// the constants+ops stream can be read in aligned chunks.
pub(crate) const ADV_PIPE_BLOCK_FELTS: usize = 8;
/// Encoded ACE circuit ready for chiplet consumption.
///
/// This packs the circuit into the chiplet instruction stream and exposes
/// helpers for stream sizing. `num_vars` counts extension-field nodes
/// (inputs + constants + padding). `num_ops` and `num_eval_rows` count
/// base-field operation rows (including padding ops).
#[derive(Debug, Clone)]
pub struct EncodedCircuit {
    num_vars: usize,
    num_ops: usize,
    instructions: Vec<Felt>,
}

/// Encoded recursive-verifier circuit and the metadata consumed by MASM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveAceCircuit {
    /// Number of ACE READ variables, including constants and padding.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Eidos commitment authenticating the complete instruction stream.
    pub commitment: Word,
    /// Encoded instructions consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

impl TryFrom<EncodedCircuit> for RecursiveAceCircuit {
    type Error = AceError;

    fn try_from(encoded: EncodedCircuit) -> Result<Self, Self::Error> {
        let stream_len = encoded.size_in_felt();
        if !stream_len.is_multiple_of(ADV_PIPE_BLOCK_FELTS) {
            return Err(AceError::InvalidInputLayout {
                message: "ACE circuit stream must be 8-felt aligned for adv_pipe".into(),
            });
        }
        Ok(Self {
            num_inputs: encoded.num_vars(),
            num_eval_gates: encoded.num_eval_rows(),
            stream_len,
            commitment: encoded.circuit_hash(),
            instructions: encoded.instructions,
        })
    }
}

impl EncodedCircuit {
    /// Number of ACE READ rows (two EF nodes per row).
    pub fn num_read_rows(&self) -> usize {
        self.num_vars() / ACE_READ_ROW_EF_NODES
    }

    /// Number of rows needed to evaluate operations (one op per base-field row).
    pub fn num_eval_rows(&self) -> usize {
        self.num_ops
    }

    /// Total number of variable slots (inputs + constants + padding), counted in EF nodes.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Number of input slots in the READ section.
    pub fn num_inputs(&self) -> usize {
        self.num_vars - self.num_constants()
    }

    /// Number of constants encoded into the circuit stream, counted in EF nodes.
    pub fn num_constants(&self) -> usize {
        (self.instructions.len() - self.num_ops) / BASE_FELTS_PER_EF
    }

    /// Total number of nodes (inputs + constants + ops).
    pub fn num_nodes(&self) -> usize {
        self.num_vars + self.num_ops
    }

    /// Raw instruction stream (constants + ops).
    pub fn instructions(&self) -> &[Felt] {
        &self.instructions
    }

    /// Instruction stream length in base field elements.
    pub fn size_in_felt(&self) -> usize {
        self.instructions.len()
    }

    /// Eidos digest of the whole instruction stream.
    ///
    /// This single value is the circuit's commitment: the advice-map key under which the
    /// recursive verifier streams the instructions, and the value it checks against the
    /// compiled-in circuit digest.
    pub fn circuit_hash(&self) -> Word {
        Eidos::hash_elements(self.instructions())
    }
}
