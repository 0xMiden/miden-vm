use miden_crypto::{
    field::TwoAdicField,
    stark::dft::{NaiveDft, TwoAdicSubgroupDft},
};

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
    /// Topologically ordered nodes.
    pub nodes: Vec<NodeKind<EF>>,
    /// Root node of the verifier equation.
    pub root: NodeId,
}

impl<EF: Clone> AceDag<EF> {
    /// Remove unreachable nodes and compact the node vector.
    ///
    /// After compaction, `nodes` contains only nodes reachable from `root`,
    /// in the same topological order. All `NodeId` references are remapped
    /// to reflect the new contiguous indices.
    pub fn compact(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }

        // Mark reachable nodes via DFS from root.
        let mut reachable = vec![false; n];
        let mut stack = vec![self.root.0];
        while let Some(idx) = stack.pop() {
            if reachable[idx] {
                continue;
            }
            reachable[idx] = true;
            match &self.nodes[idx] {
                NodeKind::Add(a, b) | NodeKind::Sub(a, b) | NodeKind::Mul(a, b) => {
                    stack.push(a.0);
                    stack.push(b.0);
                },
                NodeKind::Neg(a) => {
                    stack.push(a.0);
                },
                NodeKind::Input(_) | NodeKind::Constant(_) => {},
            }
        }

        // Build old-to-new index remapping.
        let mut remap = vec![0usize; n];
        let mut new_len = 0usize;
        for i in 0..n {
            if reachable[i] {
                remap[i] = new_len;
                new_len += 1;
            }
        }

        // Early exit if nothing was removed.
        if new_len == n {
            return;
        }

        // Build compacted node vec with remapped ids.
        let mut new_nodes = Vec::with_capacity(new_len);
        for (i, node) in self.nodes.iter().enumerate() {
            if !reachable[i] {
                continue;
            }
            let remapped = match node {
                NodeKind::Input(k) => NodeKind::Input(*k),
                NodeKind::Constant(v) => NodeKind::Constant(v.clone()),
                NodeKind::Add(a, b) => NodeKind::Add(NodeId(remap[a.0]), NodeId(remap[b.0])),
                NodeKind::Sub(a, b) => NodeKind::Sub(NodeId(remap[a.0]), NodeId(remap[b.0])),
                NodeKind::Mul(a, b) => NodeKind::Mul(NodeId(remap[a.0]), NodeId(remap[b.0])),
                NodeKind::Neg(a) => NodeKind::Neg(NodeId(remap[a.0])),
            };
            new_nodes.push(remapped);
        }

        self.nodes = new_nodes;
        self.root = NodeId(remap[self.root.0]);
    }
}
