use miden_crypto::stark::{
    dft::{NaiveDft, TwoAdicSubgroupDft},
    field::TwoAdicField,
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
