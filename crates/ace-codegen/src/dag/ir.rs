use crate::layout::InputKey;

/// Identifier for a node in the DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub(super) usize);

impl NodeId {
    /// Return the underlying node index.
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Node kinds in the DAG.
///
/// These nodes mirror the verifier expression tree after lowering:
/// inputs are read via `InputKey`, constants are lifted into the DAG, and
/// arithmetic nodes capture the evaluation order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKind<EF> {
    /// Layout-addressable input (public, OOD, aux, etc.).
    Input(InputKey),
    /// Constant extension-field value.
    Constant(EF),
    /// Addition node.
    Add(NodeId, NodeId),
    /// Subtraction node.
    Sub(NodeId, NodeId),
    /// Multiplication node.
    Mul(NodeId, NodeId),
    /// Negation node (modeled as 0 - x when emitting ops).
    Neg(NodeId),
}

/// Precomputed periodic column data for DAG construction.
#[derive(Debug, Clone)]
pub struct PeriodicColumnData<EF> {
    /// Maximum periodic column length (used to align powers).
    pub max_len: usize,
    /// Per-column coefficient vectors (highest-degree first).
    pub coeffs: Vec<Vec<EF>>,
}

impl<EF> PeriodicColumnData<EF> {
    /// Number of periodic columns.
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }
}

/// A built DAG with a designated root.
#[derive(Debug)]
pub struct AceDag<EF> {
    /// Topologically ordered nodes.
    pub nodes: Vec<NodeKind<EF>>,
    /// Root node of the verifier equation.
    pub root: NodeId,
}
