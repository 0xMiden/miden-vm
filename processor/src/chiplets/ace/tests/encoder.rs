use crate::chiplets::ace::encoded_circuit::Op;
use crate::chiplets::ace::tests::circuit::{Circuit, CircuitLayout, Instruction, NodeID};
use crate::math::FieldElement;
use crate::{Felt, QuadFelt};
use std::prelude::rust_2024::Vec;
use crate::chiplets::ace::encoded_circuit::EncodedCircuit;

#[derive(Debug)]
pub enum EncodingError {
    InvalidLayout,
}

impl EncodedCircuit {

    /// Try to create an `EncodedCircuit` from a given circuit. The circuit is expected to
    /// evaluate to zero, as the resulting encoded circuit is padded with squaring operations.
    /// - The number of nodes should not exceed `MAX_ID` to ensure IDs can be correctly encoded
    ///
    /// # Panic
    /// Panics if the circuit is not in the right format (i.e. the instructions are not properly
    /// ordered).
    pub fn try_from_circuit(circuit: &Circuit) -> Result<Self, EncodingError> {
        // Get the layout of the padded circuit
        let layout = circuit.layout().padded();

        // Ensure all node IDs can be encoded in 30 bits
        if layout.num_nodes() > EncodedCircuit::MAX_ID as usize {
            return Err(EncodingError::InvalidLayout);
        }

        // Encoded circuit contains constants followed by instructions.
        // Constants are mapped to `QuadFelt`s represented by two `Felt`s.
        // Instructions are mapped to a single `Felt`.
        let circuit_size = 2 * layout.num_constants + layout.num_instructions;

        let mut encoded_circuit = Vec::with_capacity(circuit_size);

        // Add constants encoded as `QuadFelt`s
        encoded_circuit
            .extend(circuit.constants.iter().flat_map(|c| QuadFelt::from(*c).to_base_elements()));
        // Pad with zero constants.
        let encoded_constants_size = 2 * layout.num_constants;
        encoded_circuit.resize(encoded_constants_size, Felt::ZERO);

        // Encode the instructions to single `Felt`s, reversing the ids.
        // It is safe to unwrap the encoded instruction as we assume the circuit was constructed
        // correctly.
        let encoded_instructions_iter = circuit.instructions.iter().map(|instruction| {
            Self::encode_instruction(instruction, &layout).expect("Invalid instruction")
        });
        // Add the encoded instructions to the circuit
        encoded_circuit.extend(encoded_instructions_iter);

        // Add instructions squaring the final value. Since we care about the output being 0,
        // this has no effect. Moreover, it avoids having to know the index of the zero constant.
        let mut last_eval_node_index = circuit.instructions.len() - 1;
        while encoded_circuit.len() < circuit_size {
            let last_eval_node = NodeID::Eval(last_eval_node_index);
            let square_last_instruction = Instruction {
                node_l: last_eval_node,
                node_r: last_eval_node,
                op: Op::Mul,
            };
            let encoded_instruction =
                Self::encode_instruction(&square_last_instruction, &layout).unwrap();
            encoded_circuit.push(encoded_instruction);
            last_eval_node_index += 1;
        }
        debug_assert_eq!(last_eval_node_index, layout.num_instructions - 1);

        Ok(Self {
            num_vars: layout.num_vars(),
            num_eval: layout.num_instructions,
            encoded_circuit,
        })
    }

    // INSTRUCTION ENCODING

    /// Encode an instruction as a `Felt`, packed as
    /// `[ id_l (30 bits) || id_r (30 bits) || op (2 bits) ]`,
    /// where `id_{l, r}` are is the index of the node in the graph, reversed
    /// with regard to the total number of nodes.
    pub fn encode_instruction(instruction: &Instruction, layout: &CircuitLayout) -> Option<Felt> {
        if layout.num_nodes() > EncodedCircuit::MAX_ID as usize {
            return None;
        }

        let id_l = layout.encoded_node_id(&instruction.node_l)?;
        let id_r = layout.encoded_node_id(&instruction.node_r)?;

        let op = match instruction.op {
            Op::Sub => 0,
            Op::Mul => 1,
            Op::Add => 2,
        };

        let encoded = id_l as u64 + ((id_r as u64) << Self::ID_BITS) + (op << (2 * Self::ID_BITS));
        Some(Felt::new(encoded))
    }
}

impl CircuitLayout {
    /// Same as `node_to_index`, but reverses the index relative to `num_nodes`.
    ///
    /// For example, the first input node has `id = layout.num_nodes() - 1`
    /// and the last instruction produces a node with `id = 0`.
    pub(crate) fn encoded_node_id(&self, node: &NodeID) -> Option<u32> {
        let id = self.node_index(node)?;
        Some((self.num_nodes() - 1 - id) as u32)
    }

    /// Returns the layout of the padded circuit satisfying the following alignment properties
    /// - Number of inputs and constants are multiples of 2, ensuring the memory regions containing
    ///   them are each word aligned, as each word contains two variables.
    /// - The size of the circuit is double-word aligned to allow efficient un-hashing
    /// - The number of instructions are also word-aligned.
    fn padded(&self) -> Self {
        // Inputs are padded to next multiple of 2 so they can be word-aligned, since each word
        // contains two inputs.
        // TODO(@adr1anh): does it makes sense to double-word align?
        let num_inputs = self.num_inputs.next_multiple_of(2);

        // The circuit size must be double-word aligned for more efficient hashing.
        // We pad instructions to 4 to minimize number of eval rows,
        // and add more constants to reach a padding of 8.
        let num_instructions = self.num_instructions.next_multiple_of(4);
        let padded_circuit_size = (2 * self.num_constants + num_instructions).next_multiple_of(8);
        let num_constants = (padded_circuit_size - num_instructions) / 2;
        Self {
            num_inputs,
            num_constants,
            num_instructions,
        }
    }
}
