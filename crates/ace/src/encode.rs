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

use miden_core::{Felt, Word, crypto::hash::Eidos};
#[cfg(feature = "compiler")]
use miden_crypto::field::ExtensionField;

use crate::AceError;
#[cfg(feature = "compiler")]
use crate::circuit::{AceCircuit, AceNode, AceOp, AceOpNode};

// NOTE: `num_vars`/`num_const_nodes` count extension-field (EF) nodes, while the
// instruction stream (`instructions.len()`) is measured in base field elements.

/// Number of base field elements per extension field element.
const BASE_FELTS_PER_EF: usize = crate::EXT_DEGREE;
/// Number of EF nodes read per ACE READ row (two EF per row).
const ACE_READ_ROW_EF_NODES: usize = 2;
/// Constants are padded to an even number of EF nodes (full READ rows).
pub(crate) const CONST_EF_ALIGN: usize = 2;
/// Instruction stream padding unit in base felts (adv_pipe block size), so that
/// the constants+ops stream can be read in aligned chunks.
pub(crate) const ADV_PIPE_BLOCK_FELTS: usize = 8;
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
#[derive(Debug, Clone, Eq, PartialEq)]
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

impl From<EncodedCircuit> for RecursiveAceCircuit {
    fn from(encoded: EncodedCircuit) -> Self {
        // Private fields and all constructors guarantee the complete stream's alignment.
        let commitment = encoded.circuit_hash();
        Self::from_committed(encoded, commitment)
    }
}

impl RecursiveAceCircuit {
    pub(crate) fn from_committed(encoded: EncodedCircuit, commitment: Word) -> Self {
        Self {
            num_inputs: encoded.num_vars(),
            num_eval_gates: encoded.num_eval_rows(),
            stream_len: encoded.size_in_felt(),
            commitment,
            instructions: encoded.instructions,
        }
    }
}

impl EncodedCircuit {
    /// Validate the portable READ/EVAL and stream-length metadata without decoding instructions.
    /// Full instruction validation and authentication remain separate operations.
    pub fn validate_shape(
        num_vars: usize,
        num_ops: usize,
        stream_len: usize,
    ) -> Result<(), AceError> {
        Self::checked_shape(num_vars, num_ops, stream_len).map(|_| ())
    }

    fn checked_shape(
        num_vars: usize,
        num_ops: usize,
        stream_len: usize,
    ) -> Result<(usize, usize), AceError> {
        let invalid = |message: &str| AceError::InvalidInputLayout { message: message.into() };
        if num_vars == 0 || !num_vars.is_multiple_of(ACE_READ_ROW_EF_NODES) {
            return Err(invalid("ACE READ variables must be nonzero and aligned to two EF nodes"));
        }
        if num_ops == 0 || !num_ops.is_multiple_of(4) {
            return Err(invalid("ACE EVAL rows must be nonzero and aligned to four instructions"));
        }
        let num_nodes = num_vars
            .checked_add(num_ops)
            .filter(|&count| count <= MAX_NUM_ACE_NODES)
            .ok_or_else(|| invalid("ACE circuit must have fewer than 2^30 nodes"))?;
        let const_felts = stream_len
            .checked_sub(num_ops)
            .filter(|count| count.is_multiple_of(BASE_FELTS_PER_EF * CONST_EF_ALIGN))
            .ok_or_else(|| invalid("ACE constant stream must contain complete READ rows"))?;
        if const_felts / BASE_FELTS_PER_EF > num_vars {
            return Err(invalid("ACE constant count exceeds READ variables"));
        }
        if !stream_len.is_multiple_of(ADV_PIPE_BLOCK_FELTS) {
            return Err(invalid("ACE circuit stream must be 8-felt aligned for adv_pipe"));
        }
        Ok((num_nodes, const_felts))
    }

    /// Reconstruct an encoded stream without invoking AIR capture or circuit compilation.
    ///
    /// The shape must satisfy the VM encoding's READ/EVAL and advice-block alignment rules.
    /// Every instruction must reference only a preceding READ or EVAL wire. This checks the
    /// stream format; a caller still authenticates the relation's deliberately accepted digest.
    pub fn from_parts(
        num_vars: usize,
        num_ops: usize,
        instructions: Vec<Felt>,
    ) -> Result<Self, AceError> {
        let (num_nodes, const_felts) = Self::checked_shape(num_vars, num_ops, instructions.len())?;
        for (index, &instruction) in instructions[const_felts..].iter().enumerate() {
            let (left, right, _) = crate::instruction::decode_instruction(instruction)
                .ok_or(AceError::InvalidInstruction)?;
            let output_id = num_ops - index - 1;
            if [left, right]
                .iter()
                .any(|&id| id as usize <= output_id || id as usize >= num_nodes)
            {
                return Err(AceError::UnavailableWire);
            }
        }
        Ok(Self { num_vars, num_ops, instructions })
    }

    /// Canonical staged-artifact encoding, independent of host field representation.
    ///
    /// Version 1 consists of `MIDACE\0\x01`, then three little-endian `u32`s (READ variables,
    /// EVAL rows, stream length), followed by canonical little-endian `u64` field elements.
    /// This envelope is not part of proof transport or the Eidos commitment; the commitment
    /// continues to cover exactly the instruction field elements.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20 + self.instructions.len() * 8);
        bytes.extend_from_slice(b"MIDACE\0\x01");
        for count in [self.num_vars, self.num_ops, self.instructions.len()] {
            bytes.extend_from_slice(
                &u32::try_from(count).expect("ACE format count fits u32").to_le_bytes(),
            );
        }
        for instruction in &self.instructions {
            bytes.extend_from_slice(&instruction.as_canonical_u64().to_le_bytes());
        }
        bytes
    }

    /// Decode a canonical staged-artifact stream, rejecting trailing and noncanonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AceError> {
        let invalid = |message: &str| AceError::InvalidInputLayout { message: message.into() };
        if bytes.len() < 20 || &bytes[..8] != b"MIDACE\0\x01" {
            return Err(invalid("unsupported or truncated ACE artifact header"));
        }
        let count = |offset| {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("header size checked"))
                as usize
        };
        let num_vars = count(8);
        let num_ops = count(12);
        let stream_len = count(16);
        let expected_len = stream_len.checked_mul(8).and_then(|len| len.checked_add(20));
        if expected_len != Some(bytes.len()) {
            return Err(invalid("ACE artifact length does not match stream length"));
        }
        let instructions = bytes[20..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|&chunk| {
                let value = u64::from_le_bytes(chunk);
                Felt::new(value)
                    .map_err(|_| invalid("ACE artifact contains a noncanonical field element"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_parts(num_vars, num_ops, instructions)
    }

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
#[cfg(feature = "compiler")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamGeometry {
    input_start: usize,
    constants_start: usize,
    ops_start: usize,
}

#[cfg(feature = "compiler")]
impl StreamGeometry {
    /// Derive the bases from UNPADDED counts, applying the chiplet padding rules:
    /// constants are rounded up to full READ rows and the constants+ops stream is padded
    /// to whole `adv_pipe` blocks. The single authority for this arithmetic: `to_ace` derives
    /// every node id from here rather than repeating the padding rules inline.
    pub(crate) fn from_counts(num_inputs: usize, num_constants: usize, num_ops: usize) -> Self {
        assert!(num_ops > 0, "ACE circuit has no operations to encode");
        assert!(
            num_inputs > 0 && num_inputs.is_multiple_of(ACE_READ_ROW_EF_NODES),
            "ACE READ layout must be nonzero and aligned to two EF nodes"
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
            .and_then(|vars| vars.checked_add(num_ops))
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
    pub(crate) fn num_const_nodes(&self) -> usize {
        self.constants_start - self.ops_start
    }

    /// Number of operations, including the trailing block padding.
    pub(crate) fn num_padded_ops(&self) -> usize {
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
    pub(crate) fn encode_operation(&self, op: &AceOpNode) -> Felt {
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

#[cfg(feature = "compiler")]
impl<EF> AceCircuit<EF>
where
    EF: ExtensionField<Felt>,
{
    /// Encode the circuit into the ACE chiplet format.
    ///
    /// Panics on compiler layout, root, extension-degree or packing invariant violations.
    pub fn to_ace(&self) -> EncodedCircuit {
        assert_eq!(EF::DIMENSION, BASE_FELTS_PER_EF, "ACE encoding requires a quadratic extension");
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
mod artifact_tests {
    use super::*;

    fn encoded_sample() -> EncodedCircuit {
        let mut instructions = vec![Felt::new_unchecked(9 + (8 << 30))];
        for previous in (1u64..=7).rev() {
            instructions.push(Felt::new_unchecked(previous + (previous << 30) + (1 << 60)));
        }
        EncodedCircuit::from_parts(2, 8, instructions).expect("valid sequential stream")
    }

    #[test]
    fn canonical_artifact_has_explicit_little_endian_header_and_fields() {
        let encoded = encoded_sample();
        let bytes = encoded.to_canonical_bytes();
        assert_eq!(&bytes[..20], b"MIDACE\0\x01\x02\0\0\0\x08\0\0\0\x08\0\0\0");
        assert_eq!(&bytes[20..28], &[9, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&bytes[28..36], &[7, 0, 0, 192, 1, 0, 0, 16]);
        let decoded = EncodedCircuit::from_canonical_bytes(&bytes).expect("canonical artifact");
        assert_eq!(decoded, encoded);
        let recursive = RecursiveAceCircuit::from(decoded);
        assert_eq!(recursive.num_inputs, 2);
        assert_eq!(recursive.num_eval_gates, 8);
        assert_eq!(recursive.commitment, Eidos::hash_elements(encoded.instructions()));
    }

    #[test]
    fn canonical_artifact_rejects_version_trailing_length_and_noncanonical_fields() {
        let bytes = encoded_sample().to_canonical_bytes();
        for prefix in [0usize, 7, 19, bytes.len() - 1] {
            assert!(EncodedCircuit::from_canonical_bytes(&bytes[..prefix]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid[7] = 2;
        assert!(EncodedCircuit::from_canonical_bytes(&invalid).is_err());
        invalid = bytes.clone();
        invalid.push(0);
        assert!(EncodedCircuit::from_canonical_bytes(&invalid).is_err());
        invalid = bytes.clone();
        invalid[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(EncodedCircuit::from_canonical_bytes(&invalid).is_err());
        invalid = bytes;
        invalid[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(EncodedCircuit::from_canonical_bytes(&invalid).is_err());
    }

    #[test]
    fn runtime_shape_validation_rejects_future_wires_and_misaligned_streams() {
        let sample = encoded_sample();
        let mut instructions = sample.instructions().to_vec();
        instructions[0] = Felt::new_unchecked(7 + (8 << 30));
        assert!(matches!(
            EncodedCircuit::from_parts(2, 8, instructions),
            Err(AceError::UnavailableWire)
        ));
        assert!(EncodedCircuit::from_parts(1, 8, sample.instructions().to_vec()).is_err());
        assert!(EncodedCircuit::from_parts(2, 7, sample.instructions().to_vec()).is_err());
        assert!(EncodedCircuit::from_parts(2, 8, vec![Felt::ZERO; 12]).is_err());
        assert!(EncodedCircuit::from_parts(1 << 30, 8, sample.instructions().to_vec()).is_err());
        let mut instructions = sample.instructions().to_vec();
        instructions[0] = Felt::new_unchecked(3 << 60);
        assert!(matches!(
            EncodedCircuit::from_parts(2, 8, instructions),
            Err(AceError::InvalidInstruction)
        ));
        let mut instructions = sample.instructions().to_vec();
        instructions[0] = Felt::new_unchecked(10 + (8 << 30));
        assert!(matches!(
            EncodedCircuit::from_parts(2, 8, instructions),
            Err(AceError::UnavailableWire)
        ));
    }
}

#[cfg(all(test, feature = "compiler"))]
mod compiler_invariant_tests {
    use super::*;

    #[test]
    fn packing_geometry_rejects_overflow_before_allocation() {
        for (inputs, constants, ops) in [
            (2, usize::MAX, 1),
            (2, usize::MAX / 2 + 1, 1),
            (2, 0, usize::MAX),
            (usize::MAX - 1, 2, 4),
            (1, 0, 1),
            (2, 0, 0),
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    StreamGeometry::from_counts(inputs, constants, ops)
                })
                .is_err(),
                "invalid packing shape ({inputs}, {constants}, {ops})"
            );
        }
    }

    #[test]
    #[should_panic(expected = "ACE encoding requires a quadratic extension")]
    fn encoding_rejects_a_nonquadratic_field() {
        let layout = crate::InputLayout::new_masm(crate::InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 0,
            num_randomness: 2,
            num_quotient_chunks: 1,
        });
        let circuit = AceCircuit::<Felt> {
            layout,
            constants: vec![],
            operations: vec![],
            root: AceNode::Input(0),
        };
        circuit.to_ace();
    }
}
