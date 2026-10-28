//! Compiler-side ACE stream construction and node packing.

use alloc::{format, string::ToString, vec::Vec};

use miden_crypto::{Felt, field::ExtensionField};

use crate::{
    AceError,
    compiler::circuit::{AceCircuit, AceNode, AceOp, AceOpNode},
    encode::{ACE_READ_ROW_EF_NODES, ADV_PIPE_BLOCK_FELTS, BASE_FELTS_PER_EF, EncodedCircuit},
    instruction::{MAX_ID, encode_instruction},
};

/// Constants are padded to an even number of EF nodes (full READ rows).
pub(crate) const CONST_EF_ALIGN: usize = 2;

/// Maximum number of circuit nodes accepted by the ACE runtime.
///
/// Packed node ids occupy 30 bits, but `eval_circuit` requires the total number of READ and EVAL
/// nodes to be strictly less than `2^30`.
const MAX_NUM_ACE_NODES: usize = MAX_ID as usize;

/// Node-id bases and operation packing for one encoded circuit shape.
///
/// The chiplet numbers nodes downward from `num_nodes - 1`: inputs first, then constants,
/// then operations.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamGeometry {
    input_start: usize,
    constants_start: usize,
    ops_start: usize,
}

impl StreamGeometry {
    /// Derive the bases from UNPADDED counts, applying the chiplet padding rules:
    /// constants are rounded up to full READ rows and the constants+ops stream is padded
    /// to whole `adv_pipe` blocks. The single authority for this arithmetic: `to_ace` derives
    /// every node id from here rather than repeating the padding rules inline.
    pub(crate) fn from_counts(num_inputs: usize, num_constants: usize, num_ops: usize) -> Self {
        let num_const_nodes = num_constants.next_multiple_of(CONST_EF_ALIGN);
        let const_felts = num_const_nodes * BASE_FELTS_PER_EF;
        let num_ops_padded =
            (const_felts + num_ops).next_multiple_of(ADV_PIPE_BLOCK_FELTS) - const_felts;
        Self::new(num_inputs, num_const_nodes, num_ops_padded)
    }

    /// Derive the bases from the final (padded) node counts.
    fn new(num_inputs: usize, num_constants: usize, num_ops: usize) -> Self {
        let num_nodes = num_inputs + num_constants + num_ops;
        let input_start = num_nodes - 1;
        let constants_start = input_start - num_inputs;
        let ops_start = constants_start - num_constants;
        Self { input_start, constants_start, ops_start }
    }

    /// Number of input nodes in the READ section.
    fn num_inputs(&self) -> usize {
        self.input_start - self.constants_start
    }

    /// Number of constant nodes (EF), including READ-row padding.
    pub(crate) fn num_const_nodes(&self) -> usize {
        self.constants_start - self.ops_start
    }

    /// Number of operations, including the trailing block padding.
    pub(crate) fn num_padded_ops(&self) -> usize {
        self.ops_start + 1
    }

    /// Total nodes these bases were derived from.
    fn num_nodes(&self) -> usize {
        self.input_start + 1
    }

    /// Reject shapes the ACE chiplet cannot consume: READ layouts that do not fill whole
    /// rows, and node counts beyond the id-packing bound.
    pub(crate) fn validate(&self) -> Result<(), AceError> {
        if !self.num_inputs().is_multiple_of(ACE_READ_ROW_EF_NODES) {
            return Err(AceError::InvalidInputLayout {
                message: "ACE READ layout must be aligned to two EF nodes (use LayoutKind::Masm or pad inputs)"
                    .to_string(),
            });
        }
        if self.num_nodes() > MAX_NUM_ACE_NODES {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "ACE circuit has {} nodes, must be less than 2^30",
                    self.num_nodes()
                ),
            });
        }
        Ok(())
    }

    fn node_id(&self, node: AceNode) -> Result<u32, AceError> {
        let id = match node {
            AceNode::Input(idx) => self.input_start.checked_sub(idx),
            AceNode::Constant(idx) => self.constants_start.checked_sub(idx),
            AceNode::Operation(idx) => self.ops_start.checked_sub(idx),
        }
        .ok_or_else(|| AceError::InvalidInputLayout {
            message: format!("ACE circuit node index out of range: {node:?}"),
        })?;
        u32::try_from(id).map_err(|_| AceError::InvalidInputLayout {
            message: format!("ACE circuit node index out of range: {node:?}"),
        })
    }

    /// Pack one operation as `lhs_id + rhs_id * 2^30 + op_tag * 2^60`.
    pub(crate) fn encode_operation(&self, op: &AceOpNode) -> Result<Felt, AceError> {
        let lhs_id = self.node_id(op.lhs)?;
        let rhs_id = self.node_id(op.rhs)?;
        encode_instruction(lhs_id, rhs_id, op.op).ok_or_else(|| AceError::InvalidInputLayout {
            message: "ACE circuit node ID exceeds the 30-bit instruction field".into(),
        })
    }
}

impl<EF> AceCircuit<EF>
where
    EF: ExtensionField<Felt>,
{
    /// Encode the circuit into the ACE chiplet format.
    pub fn to_ace(&self) -> Result<EncodedCircuit, AceError> {
        let num_input_nodes = self.layout.total_inputs;
        let num_op_nodes = self.operations.len();
        if num_op_nodes == 0 {
            return Err(AceError::InvalidInputLayout {
                message: "ACE circuit has no operations to encode".to_string(),
            });
        }
        if self.root != AceNode::Operation(num_op_nodes - 1) {
            return Err(AceError::InvalidInputLayout {
                message: "ACE circuit root must be the last operation before padding".to_string(),
            });
        }

        let geometry =
            StreamGeometry::from_counts(num_input_nodes, self.constants.len(), num_op_nodes);
        geometry.validate()?;

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
            instructions.push(geometry.encode_operation(op)?);
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
            instructions.push(geometry.encode_operation(&dummy_op)?);
            last_node_index += 1;
        }

        let num_vars = num_input_nodes + num_const_nodes;
        let num_ops = geometry.num_padded_ops();
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
