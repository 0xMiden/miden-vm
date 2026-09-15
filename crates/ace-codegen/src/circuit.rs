//! ACE circuit emission for the DAG IR.
//!
//! The emitted circuit is a flat list of inputs, constants, and arithmetic
//! ops that matches the ACE chiplet execution model.

use std::collections::HashMap;

use miden_crypto::field::Field;

use crate::{
    InputLayout,
    dag::{AceDag, NodeKind},
};

/// Arithmetic operations supported by the ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AceOp {
    Add,
    Sub,
    Mul,
}

/// Nodes in the emitted ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AceNode {
    Input(usize),
    Constant(usize),
    Operation(usize),
}

/// Operation node in the ACE circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AceOpNode {
    pub op: AceOp,
    pub lhs: AceNode,
    pub rhs: AceNode,
}

/// Emitted ACE circuit with layout and operation list.
///
/// This is the off-VM representation used by tests and tools.
#[derive(Debug, Clone)]
pub struct AceCircuit<EF> {
    pub(crate) layout: InputLayout,
    pub(crate) constants: Vec<EF>,
    pub(crate) operations: Vec<AceOpNode>,
    pub(crate) root: AceNode,
}

impl<EF: Field> AceCircuit<EF> {
    /// Return the input layout for this circuit.
    pub fn layout(&self) -> &InputLayout {
        &self.layout
    }

    /// Evaluate the circuit against the provided input vector.
    ///
    /// Panics if the input length does not match the circuit layout.
    pub fn eval(&self, inputs: &[EF]) -> EF {
        assert_eq!(inputs.len(), self.layout.total_inputs, "ACE input length mismatch");
        let mut op_values = vec![EF::ZERO; self.operations.len()];
        for (idx, op) in self.operations.iter().enumerate() {
            let lhs = self.node_value(op.lhs, inputs, &op_values);
            let rhs = self.node_value(op.rhs, inputs, &op_values);
            op_values[idx] = match op.op {
                AceOp::Add => lhs + rhs,
                AceOp::Sub => lhs - rhs,
                AceOp::Mul => lhs * rhs,
            };
        }
        self.node_value(self.root, inputs, &op_values)
    }

    /// Total number of nodes (inputs + constants + ops).
    pub fn num_nodes(&self) -> usize {
        self.layout.total_inputs + self.constants.len() + self.operations.len()
    }

    fn node_value(&self, node: AceNode, inputs: &[EF], op_values: &[EF]) -> EF {
        match node {
            AceNode::Input(index) => inputs[index],
            AceNode::Constant(index) => self.constants[index],
            AceNode::Operation(index) => op_values[index],
        }
    }
}

/// Emit an ACE circuit from the DAG and input layout.
///
/// Panics if the layout is inconsistent or omits a DAG input.
pub fn emit_circuit<EF>(dag: &AceDag<EF>, layout: InputLayout) -> AceCircuit<EF>
where
    EF: Field,
{
    layout.validate();

    let mut constants = Vec::new();
    let mut constant_map = HashMap::<EF, usize>::new();
    let mut operations = Vec::new();
    // The DAG is topologically ordered, so each operand is already in this growing map.
    let mut node_map = Vec::with_capacity(dag.nodes().len());

    for node in dag.nodes() {
        let ace_node = match node {
            NodeKind::Input(key) => {
                let input_idx = layout
                    .index(*key)
                    .unwrap_or_else(|| panic!("missing input key in layout: {key:?}"));
                AceNode::Input(input_idx)
            },
            NodeKind::Constant(value) => {
                let const_idx = *constant_map.entry(*value).or_insert_with(|| {
                    constants.push(*value);
                    constants.len() - 1
                });
                AceNode::Constant(const_idx)
            },
            NodeKind::Add(a, b) => {
                let lhs = node_map[a.index()];
                let rhs = node_map[b.index()];
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Add, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Sub(a, b) => {
                let lhs = node_map[a.index()];
                let rhs = node_map[b.index()];
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Sub, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Mul(a, b) => {
                let lhs = node_map[a.index()];
                let rhs = node_map[b.index()];
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Mul, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Neg(a) => {
                let rhs = node_map[a.index()];
                let zero = *constant_map.entry(EF::ZERO).or_insert_with(|| {
                    constants.push(EF::ZERO);
                    constants.len() - 1
                });
                let op_idx = operations.len();
                operations.push(AceOpNode {
                    op: AceOp::Sub,
                    lhs: AceNode::Constant(zero),
                    rhs,
                });
                AceNode::Operation(op_idx)
            },
        };
        node_map.push(ace_node);
    }

    let root = node_map[dag.root().index()];
    AceCircuit { layout, constants, operations, root }
}
