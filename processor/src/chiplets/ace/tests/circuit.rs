use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt};

use super::*;

/// A `Circuit` is a DAG representing a multivariate polynomial over its inputs.
/// The nodes are laid out linearly, starting with the leaves and ending with the evaluation.
///
/// The constructor and invariants ensure that all instructions reference nodes whose index is
/// in-bounds and cannot reference nodes produced by subsequent instructions.
/// This ensures the circuit can be evaluated in a single pass over the instructions.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Circuit {
    pub num_inputs: usize,
    pub constants: Vec<Felt>,
    pub instructions: Vec<Instruction>,
}

/// A `NodeID` is the index of a node in the evaluation graph, depending on its type.
/// - `Input` when it is a leaf, and its value is a variable in the circuit,
/// - `Const` when it is a leaf, and its value is a constant of the circuit,
/// - `Eval` when it is a node with two incoming edges to which an `Op` is applied.
///
/// The graph is interpreted as a vector of `n_i + n_c + n_e` values, with their kinds encoded as
/// `[Input(0), ..., Input(n_i - 1), Const(0), ..., Const(n_c - 1), Eval(0), ..., Eval(n_e - 1)]`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum NodeID {
    Input(usize),
    Const(usize),
    Eval(usize),
}

/// An `Instruction` indicating how the next `Eval` node should be computed, given existing `Node`s.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Instruction {
    pub node_l: NodeID,
    pub node_r: NodeID,
    pub op: Op,
}

#[derive(Debug)]
pub enum CircuitError {
    LayoutInvalid,
    InstructionMalformed,
    InputsWrongNumber,
}

/// Layout of a circuit representing the number of different `Node`s of each type.
pub struct CircuitLayout {
    pub num_inputs: usize,
    pub num_constants: usize,
    pub num_instructions: usize,
}

impl Circuit {
    /// Creates a new circuit given the expected number of nodes, the constants and instructions
    /// to be evaluated to obtain the result.
    ///
    /// Returns an error if
    /// - The circuit contains no instructions
    /// - An instruction references a node whose index would be after the one created by it.
    pub fn new(
        num_inputs: usize,
        constants: Vec<Felt>,
        instructions: Vec<Instruction>,
    ) -> Result<Self, CircuitError> {
        let layout = CircuitLayout {
            num_inputs,
            num_constants: constants.len(),
            num_instructions: instructions.len(),
        };

        // Circuit must contain at least one instruction
        if instructions.is_empty() {
            return Err(CircuitError::LayoutInvalid);
        }

        // Ensure all instructions reference valid nodes and allow sequential evaluation
        for (instruction_idx, instruction) in instructions.iter().enumerate() {
            // Get the overall index of the node produced by this instruction
            let eval_node = NodeID::Eval(instruction_idx);

            // Check that each input node index is valid for this layout
            // and precedes the evaluation node
            let valid_node = |node: NodeID| layout.contains_node(&node) && node < eval_node;

            if !(valid_node(instruction.node_l) && valid_node(instruction.node_r)) {
                return Err(CircuitError::InstructionMalformed);
            }
        }

        Ok(Self { num_inputs, constants, instructions })
    }

    /// Given a list of inputs, computes the evaluation of the circuit.
    pub fn evaluate(&self, inputs: &[QuadFelt]) -> Result<QuadFelt, CircuitError> {
        let layout = self.layout();
        if inputs.len() != layout.num_inputs {
            return Err(CircuitError::InputsWrongNumber);
        }

        let mut nodes = Vec::with_capacity(layout.num_nodes());
        nodes.extend(inputs.iter().copied());
        nodes.extend(self.constants.iter().map(|c| QuadFelt::from(*c)));

        for instruction in &self.instructions {
            let id_l = layout.node_index(&instruction.node_l).expect("TODO");
            let v_l = *nodes.get(id_l).expect("TODO");

            let id_r = layout.node_index(&instruction.node_r).expect("TODO");
            let v_r = *nodes.get(id_r).expect("TODO");

            let v_out = match instruction.op {
                Op::Sub => v_l - v_r,
                Op::Mul => v_l * v_r,
                Op::Add => v_l + v_r,
            };
            nodes.push(v_out);
        }

        // Safe to unwrap since there are
        Ok(*nodes.last().unwrap())
    }

    /// Returns the layout of the circuit.
    pub fn layout(&self) -> CircuitLayout {
        CircuitLayout {
            num_inputs: self.num_inputs,
            num_constants: self.constants.len(),
            num_instructions: self.instructions.len(),
        }
    }
}

impl CircuitLayout {
    /// Returns the total number of variables (inputs and constants) in the circuit.
    pub fn num_vars(&self) -> usize {
        self.num_inputs + self.num_constants
    }

    /// Returns the total number of `Node`s required to represent the evaluation graph of the
    /// circuit.
    pub fn num_nodes(&self) -> usize {
        self.num_vars() + self.num_instructions
    }

    /// Checks if a `NodeID` is in-bounds relative to this layout.
    pub fn contains_node(&self, node: &NodeID) -> bool {
        match *node {
            NodeID::Input(id) => id < self.num_inputs,
            NodeID::Const(id) => id < self.num_constants,
            NodeID::Eval(id) => id < self.num_instructions,
        }
    }

    /// Given a circuit `NodeID`, returns the index it would be at in the list of all nodes
    /// in the circuit evaluation graph.
    pub fn node_index(&self, node: &NodeID) -> Option<usize> {
        if !self.contains_node(node) {
            return None;
        }
        let id = match *node {
            NodeID::Input(id) => id,
            NodeID::Const(id) => id + self.num_inputs,
            NodeID::Eval(id) => id + self.num_vars(),
        };
        Some(id)
    }
}
