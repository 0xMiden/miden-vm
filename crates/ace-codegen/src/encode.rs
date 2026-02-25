//! ACE circuit encoding for the chiplet format.
//!
//! Encoding rules:
//! - The READ section stores extension-field (EF) elements; each EF occupies two base-field
//!   elements.
//! - Each ACE READ row consumes two EF elements (four base-field elements or a `Word`).
//! - The EVAL section stores one operation per row, encoded as a single base-field element.
//!
//! The encoded stream concatenates constants (EF) followed by operations
//! (base-field), then pads to an `adv_pipe`` block boundary.

use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

use crate::{
    AceError,
    circuit::{AceCircuit, AceNode, AceOp, AceOpNode},
};

// NOTE: `num_vars`/`num_const_nodes` count extension-field (EF) nodes, while the
// instruction stream (`instructions.len()`) is measured in base field elements.

/// ACE chiplet expects quadratic extension elements.
const EXPECTED_EXTENSION_DEGREE: usize = 2;
/// Number of base field elements per extension field element.
const BASE_FELTS_PER_EF: usize = EXPECTED_EXTENSION_DEGREE;
/// Number of EF nodes read per ACE READ row (two EF per row).
const ACE_READ_ROW_EF_NODES: usize = 2;
/// Constants are padded to an even number of EF nodes (full READ rows).
const CONST_EF_ALIGN: usize = 2;
/// Instruction stream padding unit in base felts (adv_pipe block size), so that
/// the constants+ops stream can be read in aligned chunks.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Encoded ACE circuit ready for chiplet consumption.
///
/// This packs the circuit into the chiplet instruction stream and exposes
/// helpers for stream sizing.
#[derive(Debug, Clone)]
pub struct EncodedCircuit {
    num_vars: usize,
    num_ops: usize,
    instructions: Vec<Felt>,
}

impl EncodedCircuit {
    /// Number of ACE READ rows (two EF nodes per row).
    pub fn num_read_rows(&self) -> usize {
        self.num_vars() / ACE_READ_ROW_EF_NODES
    }

    /// Number of rows needed to evaluate operations (one op per row).
    pub fn num_eval_rows(&self) -> usize {
        self.num_ops
    }

    /// Total number of variable slots (inputs + constants + padding).
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Number of input slots in the READ section.
    pub fn num_inputs(&self) -> usize {
        self.num_vars - self.num_constants()
    }

    /// Number of constants encoded into the circuit stream.
    pub fn num_constants(&self) -> usize {
        (self.instructions.len() - self.num_ops) / ACE_READ_ROW_EF_NODES
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

    /// Poseidon2 digest of the instruction stream.
    pub fn circuit_hash(&self) -> Word {
        Poseidon2::hash_elements(self.instructions())
    }
}

impl<EF> AceCircuit<EF>
where
    EF: PrimeCharacteristicRing + BasedVectorSpace<Felt> + Copy + Eq + std::hash::Hash,
{
    /// Encode the circuit into the ACE chiplet format.
    pub fn to_ace(&self) -> Result<EncodedCircuit, AceError> {
        const MAX_NODE_ID: u64 = (1 << 30) - 1;

        if EF::DIMENSION != EXPECTED_EXTENSION_DEGREE {
            return Err(AceError::InvalidExtensionDegree {
                expected: EXPECTED_EXTENSION_DEGREE,
                got: EF::DIMENSION,
            });
        }
        if !self.layout.total_inputs.is_multiple_of(ACE_READ_ROW_EF_NODES) {
            return Err(AceError::InvalidInputLayout {
                message: "ACE READ layout must be aligned to two EF nodes (use LayoutKind::Masm or pad inputs)"
                    .to_string(),
            });
        }

        let num_input_nodes = self.layout.total_inputs;
        let num_const_nodes = self.constants.len().next_multiple_of(CONST_EF_ALIGN);
        let num_op_nodes = self.operations.len();

        // Constants are serialized as EF elements (2 base felts per EF).
        let num_const_felts = num_const_nodes * BASE_FELTS_PER_EF;
        let num_op_felts = num_op_nodes;
        // The instruction stream is measured in base felts:
        // - constants are EF-encoded (2 base felts each)
        // - ops are 1 base felt each
        let len_circuit = num_const_felts + num_op_felts;
        let len_circuit_padded = len_circuit.next_multiple_of(ADV_PIPE_BLOCK_FELTS);

        let num_padding_felts = len_circuit_padded - len_circuit;
        let num_padding_nodes = num_padding_felts;
        let num_nodes = num_input_nodes + num_const_nodes + num_op_nodes + num_padding_nodes;

        assert!(num_nodes as u64 <= MAX_NODE_ID, "more than 2^30 nodes");

        let mut instructions = Vec::with_capacity(len_circuit_padded);
        for constant in &self.constants {
            let coeffs = constant.as_basis_coefficients_slice();
            instructions.push(coeffs[0]);
            instructions.push(coeffs[1]);
        }
        instructions.resize(num_const_felts, Felt::ZERO);

        let node_id = |node: AceNode| -> u64 {
            let input_start = num_nodes - 1;
            let constants_start = input_start - num_input_nodes;
            let ops_start = constants_start - num_const_nodes;

            match node {
                AceNode::Input(idx) => input_start.checked_sub(idx),
                AceNode::Constant(idx) => constants_start.checked_sub(idx),
                AceNode::Operation(idx) => ops_start.checked_sub(idx),
            }
            .expect("invalid node index") as u64
        };

        let op_tag = |op: AceOp| -> u64 {
            match op {
                AceOp::Sub => 0,
                AceOp::Mul => 1,
                AceOp::Add => 2,
            }
        };

        let encode_operation = |op: &AceOpNode| {
            // Pack as: lhs_id + rhs_id * 2^30 + op_tag * 2^60.
            const RHS_NODE_OFFSET: u64 = 1 << 30;
            const OP_TAG_OFFSET: u64 = 1 << 60;
            let lhs_id = node_id(op.lhs);
            let rhs_id = node_id(op.rhs);
            let tag = op_tag(op.op);
            Felt::new(lhs_id + rhs_id * RHS_NODE_OFFSET + tag * OP_TAG_OFFSET)
        };

        for op in &self.operations {
            instructions.push(encode_operation(op));
        }

        let mut last_node_index = self.operations.len().saturating_sub(1);
        while instructions.len() < len_circuit_padded {
            let last_node = AceNode::Operation(last_node_index);
            let dummy_op = AceOpNode {
                op: AceOp::Mul,
                lhs: last_node,
                rhs: last_node,
            };
            instructions.push(encode_operation(&dummy_op));
            last_node_index += 1;
        }

        let num_vars = num_input_nodes + num_const_nodes;
        let num_ops = num_op_nodes + num_padding_nodes;
        Ok(EncodedCircuit { num_vars, num_ops, instructions })
    }

    /// Return true if inputs/constants/ops satisfy chiplet padding rules:
    /// - inputs/constants are aligned to full READ rows (EF nodes)
    /// - constants+ops stream is aligned to adv_pipe blocks (base felts)
    pub fn is_padded(&self) -> bool {
        if !self.layout.total_inputs.is_multiple_of(ACE_READ_ROW_EF_NODES) {
            return false;
        }
        if !self.constants.len().is_multiple_of(CONST_EF_ALIGN) {
            return false;
        }
        let const_felts = self.constants.len() * BASE_FELTS_PER_EF;
        let op_felts = self.operations.len();
        (const_felts + op_felts).is_multiple_of(ADV_PIPE_BLOCK_FELTS)
    }
}
