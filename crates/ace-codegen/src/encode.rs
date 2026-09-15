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

use miden_core::{Felt, Word, crypto::hash::Eidos};
use miden_crypto::field::ExtensionField;

use crate::circuit::{AceCircuit, AceNode, AceOp, AceOpNode};

// NOTE: `num_vars`/`num_const_nodes` count extension-field (EF) nodes, while the
// instruction stream (`instructions.len()`) is measured in base field elements.

/// Number of base field elements per extension field element.
const BASE_FELTS_PER_EF: usize = crate::EXT_DEGREE;
/// Number of EF nodes read per ACE READ row (two EF per row).
const ACE_READ_ROW_EF_NODES: usize = 2;
/// Constants are padded to an even number of EF nodes (full READ rows).
const CONST_EF_ALIGN: usize = 2;
/// Instruction stream padding unit in base felts (adv_pipe block size), so that
/// the constants+ops stream can be read in aligned chunks.
const ADV_PIPE_BLOCK_FELTS: usize = 8;
/// Maximum number of circuit nodes accepted by the ACE runtime.
///
/// Packed node ids occupy 30 bits, but `eval_circuit` requires the total number of READ and EVAL
/// nodes to be strictly less than `2^30`.
const MAX_NUM_ACE_NODES: usize = (1 << 30) - 1;

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

/// Node-id bases and operation packing for one encoded circuit shape.
///
/// The chiplet numbers nodes downward from `num_nodes - 1`: inputs first, then constants,
/// then operations.
#[derive(Debug, Clone, Copy)]
struct StreamGeometry {
    input_start: usize,
    constants_start: usize,
    ops_start: usize,
}

impl StreamGeometry {
    /// Derive the bases from UNPADDED counts, applying the chiplet padding rules:
    /// constants are rounded up to full READ rows and the constants+ops stream is padded
    /// to whole `adv_pipe` blocks. The single authority for this arithmetic: `to_ace` derives
    /// every node id from here rather than repeating the padding rules inline.
    fn from_counts(num_inputs: usize, num_constants: usize, num_ops: usize) -> Self {
        assert!(num_ops > 0, "ACE circuit has no operations to encode");
        assert!(
            num_inputs.is_multiple_of(ACE_READ_ROW_EF_NODES),
            "ACE READ layout must be aligned to two EF nodes (use LayoutKind::Masm or pad inputs)"
        );
        let num_constants = num_constants
            .checked_next_multiple_of(CONST_EF_ALIGN)
            .expect("ACE constant padding overflow");
        let const_felts = num_constants
            .checked_mul(BASE_FELTS_PER_EF)
            .expect("ACE constant stream length overflow");
        let stream_felts = const_felts
            .checked_add(num_ops)
            .and_then(|len| len.checked_next_multiple_of(ADV_PIPE_BLOCK_FELTS))
            .expect("ACE instruction stream padding overflow");
        let num_ops = stream_felts - const_felts;
        let num_nodes = num_inputs
            .checked_add(num_constants)
            .and_then(|num_vars| num_vars.checked_add(num_ops))
            .expect("ACE circuit node count overflow");
        assert!(
            num_nodes <= MAX_NUM_ACE_NODES,
            "ACE circuit has {num_nodes} nodes, must be less than 2^30"
        );

        let input_start = num_nodes - 1;
        let constants_start = input_start - num_inputs;
        let ops_start = constants_start - num_constants;
        Self { input_start, constants_start, ops_start }
    }

    /// Number of constant nodes (EF), including READ-row padding.
    fn num_const_nodes(&self) -> usize {
        self.constants_start - self.ops_start
    }

    /// Number of operations, including the trailing block padding.
    fn num_padded_ops(&self) -> usize {
        self.ops_start + 1
    }

    fn node_id(&self, node: AceNode) -> u64 {
        let id = match node {
            AceNode::Input(idx) => self.input_start.checked_sub(idx),
            AceNode::Constant(idx) => self.constants_start.checked_sub(idx),
            AceNode::Operation(idx) => self.ops_start.checked_sub(idx),
        }
        .unwrap_or_else(|| panic!("ACE circuit node index out of range: {node:?}"));
        id as u64
    }

    /// Pack one operation as `lhs_id + rhs_id * 2^30 + op_tag * 2^60`.
    fn encode_operation(&self, op: &AceOpNode) -> Felt {
        const RHS_NODE_OFFSET: u64 = 1 << 30;
        const OP_TAG_OFFSET: u64 = 1 << 60;
        let tag = match op.op {
            AceOp::Sub => 0,
            AceOp::Mul => 1,
            AceOp::Add => 2,
        };
        let lhs_id = self.node_id(op.lhs);
        let rhs_id = self.node_id(op.rhs);
        Felt::new_unchecked(lhs_id + rhs_id * RHS_NODE_OFFSET + tag * OP_TAG_OFFSET)
    }
}

impl<EF> AceCircuit<EF>
where
    EF: ExtensionField<Felt>,
{
    /// Encode the circuit into the ACE chiplet format.
    ///
    /// Panics if the READ layout is unaligned, the circuit exceeds the node bound, or its
    /// root is not the final operation.
    pub fn to_ace(&self) -> EncodedCircuit {
        let num_input_nodes = self.layout.total_inputs;
        let num_op_nodes = self.operations.len();
        let geometry =
            StreamGeometry::from_counts(num_input_nodes, self.constants.len(), num_op_nodes);
        assert_eq!(
            self.root,
            AceNode::Operation(num_op_nodes - 1),
            "ACE circuit root must be the last operation before padding"
        );

        // The instruction stream is measured in base felts:
        // - constants are EF-encoded (2 base felts each)
        // - ops are 1 base felt each
        let num_const_nodes = geometry.num_const_nodes();
        let num_const_felts = num_const_nodes * BASE_FELTS_PER_EF;
        let len_circuit_padded = num_const_felts + geometry.num_padded_ops();

        let mut instructions = Vec::with_capacity(len_circuit_padded);
        for constant in &self.constants {
            let coeffs = constant.as_basis_coefficients_slice();
            instructions.push(coeffs[0]);
            instructions.push(coeffs[1]);
        }
        instructions.resize(num_const_felts, Felt::ZERO);

        for op in &self.operations {
            instructions.push(geometry.encode_operation(op));
        }

        // The ACE chiplet checks the last EVAL row. Padding preserves zero-ness by repeatedly
        // squaring the current root, so the unpadded root must be the last emitted operation.
        let mut last_node_index = num_op_nodes - 1;
        while instructions.len() < len_circuit_padded {
            let last_node = AceNode::Operation(last_node_index);
            let dummy_op = AceOpNode {
                op: AceOp::Mul,
                lhs: last_node,
                rhs: last_node,
            };
            instructions.push(geometry.encode_operation(&dummy_op));
            last_node_index += 1;
        }

        let num_vars = num_input_nodes + num_const_nodes;
        let num_ops = geometry.num_padded_ops();
        EncodedCircuit { num_vars, num_ops, instructions }
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

#[cfg(test)]
mod tests {
    use super::StreamGeometry;

    #[test]
    fn stream_geometry_enforces_the_node_id_packing_bound() {
        // Valid streams have an even node count because READ and EVAL rows are word-aligned.
        // Thus, 2^30 - 2 is the largest realizable shape below the runtime's strict 2^30 bound.
        StreamGeometry::from_counts((1 << 30) - 8, 2, 4);
        assert!(
            std::panic::catch_unwind(|| {
                StreamGeometry::from_counts((1 << 30) - 6, 2, 4);
            })
            .is_err()
        );
    }
}
