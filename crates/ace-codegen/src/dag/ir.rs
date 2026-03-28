use core::sync::atomic::{AtomicUsize, Ordering};

use miden_crypto::{
    field::TwoAdicField,
    stark::dft::{NaiveDft, TwoAdicSubgroupDft},
};

use crate::layout::InputKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct DagId(usize);

impl DagId {
    pub(crate) fn fresh() -> Self {
        static NEXT_DAG_ID: AtomicUsize = AtomicUsize::new(0);

        Self(NEXT_DAG_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// Identifier for a node in the DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    pub(super) dag_id: DagId,
    pub(super) index: usize,
}

impl NodeId {
    /// Return the underlying node index.
    pub const fn index(self) -> usize {
        self.index
    }

    pub(super) const fn in_dag(index: usize, dag_id: DagId) -> Self {
        Self { dag_id, index }
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
    /// Per-column coefficient vectors (highest-degree first).
    coeffs: Vec<Vec<EF>>,
}

impl<EF> PeriodicColumnData<EF> {
    /// Convert periodic columns (evaluations) into coefficient form for DAG building.
    ///
    /// Applies an inverse DFT so the DAG can evaluate them at `z_k` inside the circuit.
    pub fn from_periodic_columns<F>(periodic_columns: Vec<Vec<F>>) -> Self
    where
        F: TwoAdicField,
        EF: From<F>,
    {
        if periodic_columns.is_empty() {
            return Self { coeffs: Vec::new() };
        }

        let dft = NaiveDft;
        let mut coeffs = Vec::with_capacity(periodic_columns.len());
        for col in periodic_columns {
            assert!(!col.is_empty(), "periodic column must not be empty");
            assert!(col.len().is_power_of_two(), "periodic column length must be a power of two");
            let values = dft.idft(col);
            let coeff_row = values.into_iter().map(EF::from).collect();
            coeffs.push(coeff_row);
        }

        Self { coeffs }
    }

    /// Number of periodic columns.
    pub fn num_columns(&self) -> usize {
        self.coeffs.len()
    }

    /// Maximum periodic column length (used to align powers).
    pub fn max_period(&self) -> usize {
        self.coeffs.iter().map(|c| c.len()).max().unwrap_or(0)
    }

    /// Iterate over the per-column coefficient vectors.
    pub fn columns(&self) -> &[Vec<EF>] {
        &self.coeffs
    }
}

/// A built DAG with a designated root.
#[derive(Debug)]
pub struct AceDag<EF> {
    dag_id: DagId,
    /// Topologically ordered nodes.
    pub nodes: Vec<NodeKind<EF>>,
    /// Root node of the verifier equation.
    pub root: NodeId,
}

/// Exported DAG data that preserves the source DAG id across imports.
#[derive(Debug, Clone)]
pub struct DagSnapshot<EF> {
    nodes: Vec<NodeKind<EF>>,
    root: NodeId,
    source_dag_id: DagId,
}

impl<EF> AceDag<EF> {
    pub(crate) fn from_parts(dag_id: DagId, nodes: Vec<NodeKind<EF>>, root: NodeId) -> Self {
        Self { dag_id, nodes, root }
    }

    pub(crate) fn nodes(&self) -> &[NodeKind<EF>] {
        &self.nodes
    }

    pub(crate) fn into_nodes(self) -> Vec<NodeKind<EF>> {
        self.nodes
    }

    pub(crate) fn dag_id(&self) -> DagId {
        self.dag_id
    }

    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Consume the DAG and return an exported snapshot that can be re-imported later.
    pub fn into_snapshot(self) -> DagSnapshot<EF> {
        DagSnapshot {
            nodes: self.nodes,
            root: self.root,
            source_dag_id: self.dag_id,
        }
    }

    /// Clone the DAG into an exported snapshot that can be re-imported later.
    pub fn snapshot(&self) -> DagSnapshot<EF>
    where
        EF: Clone,
    {
        DagSnapshot {
            nodes: self.nodes.clone(),
            root: self.root,
            source_dag_id: self.dag_id,
        }
    }
}

impl<EF> DagSnapshot<EF> {
    /// Topologically ordered nodes.
    pub fn nodes(&self) -> &[NodeKind<EF>] {
        &self.nodes
    }

    /// Root node of the verifier equation.
    pub fn root(&self) -> NodeId {
        self.root
    }

    pub(super) fn into_parts(self) -> (DagId, Vec<NodeKind<EF>>, NodeId) {
        (self.source_dag_id, self.nodes, self.root)
    }
}
