//! ACE circuit emission for the DAG IR.
//!
//! The emitted circuit is a flat list of inputs, constants, and arithmetic
//! ops that matches the ACE chiplet execution model.

use alloc::vec::Vec;
#[cfg(feature = "compiler")]
use std::collections::HashMap;

use miden_crypto::field::Field;

use crate::InputLayout;
#[cfg(feature = "compiler")]
use crate::dag::{AceDag, NodeId, NodeKind};

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
    /// Panics if the input length differs from the compiler-owned layout. This evaluator
    /// returns the selected root, independently of the encoded runtime's padding operations.
    pub fn eval(&self, inputs: &[EF]) -> EF {
        assert_eq!(inputs.len(), self.layout.total_inputs, "ACE input length must match layout");
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
/// Panics if an authored DAG input is absent from the layout.
#[cfg(feature = "compiler")]
pub fn emit_circuit<EF>(dag: &AceDag<EF>, layout: InputLayout) -> AceCircuit<EF>
where
    EF: Field,
{
    layout.validate();

    let mut constants = Vec::new();
    let mut constant_map = HashMap::<EF, usize>::new();
    let mut operations = Vec::new();
    let mut node_map: Vec<Option<AceNode>> = vec![None; dag.nodes().len()];

    for (idx, node) in dag.nodes().iter().enumerate() {
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
                let lhs = lookup_node(&node_map, *a);
                let rhs = lookup_node(&node_map, *b);
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Add, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Sub(a, b) => {
                let lhs = lookup_node(&node_map, *a);
                let rhs = lookup_node(&node_map, *b);
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Sub, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Mul(a, b) => {
                let lhs = lookup_node(&node_map, *a);
                let rhs = lookup_node(&node_map, *b);
                let op_idx = operations.len();
                operations.push(AceOpNode { op: AceOp::Mul, lhs, rhs });
                AceNode::Operation(op_idx)
            },
            NodeKind::Neg(a) => {
                let rhs = lookup_node(&node_map, *a);
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
        node_map[idx] = Some(ace_node);
    }

    let root = lookup_node(&node_map, dag.root());
    AceCircuit { layout, constants, operations, root }
}

#[cfg(feature = "compiler")]
fn lookup_node(map: &[Option<AceNode>], id: NodeId) -> AceNode {
    map[id.index()].expect("ACE DAG nodes must be topologically ordered")
}

#[cfg(test)]
mod runtime_tests {
    use miden_core::{Felt, field::QuadFelt};
    use miden_crypto::field::PrimeCharacteristicRing;

    use super::*;
    use crate::InputCounts;

    #[test]
    fn off_vm_evaluation_returns_selected_root_even_with_later_operations() {
        let layout = InputLayout::new(InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 2,
            num_randomness: 2,
            num_quotient_chunks: 1,
        });
        let circuit = AceCircuit {
            layout,
            constants: vec![],
            operations: vec![
                AceOpNode {
                    op: AceOp::Sub,
                    lhs: AceNode::Input(0),
                    rhs: AceNode::Input(1),
                },
                AceOpNode {
                    op: AceOp::Mul,
                    lhs: AceNode::Input(0),
                    rhs: AceNode::Input(1),
                },
            ],
            root: AceNode::Operation(0),
        };
        let mut inputs = vec![QuadFelt::ZERO; circuit.layout.total_inputs];
        inputs[0] = QuadFelt::from(Felt::from_u32(3));
        inputs[1] = QuadFelt::from(Felt::from_u32(5));
        assert_eq!(circuit.eval(&inputs), QuadFelt::from(-Felt::from_u32(2)));
    }
}
