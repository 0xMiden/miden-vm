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

/// A nonzero evaluation-domain value of a periodic column, together with the
/// doubling-basis twiddle powers needed to evaluate its Lagrange contribution
/// at an arbitrary point `x` via `value * Π_i (1 + twiddle[i] * x^(2^i))`.
///
/// This is the sparse dual of the dense monomial-basis coefficients: an IDFT
/// turns a sparse evaluation vector into dense coefficients, but the Lagrange
/// form stays sparse in the number of nonzero evaluations.
#[derive(Debug, Clone)]
pub(crate) struct SparseTerm<EF> {
    /// The evaluation-domain value, pre-scaled by the domain-size inverse.
    pub(crate) scaled_value: EF,
    /// `omega^(-j * 2^i)` for `i = 0..log2(period)`, where `j` is this term's domain index.
    pub(crate) twiddles: Vec<EF>,
}

/// The in-circuit evaluation form chosen for a single periodic column.
///
/// The cheaper of the two representations is selected from the column values when
/// the data is built; the lowering emits nodes for whichever form each column carries.
#[derive(Debug, Clone)]
pub(crate) enum PeriodicColumn<EF> {
    /// Dense monomial-basis coefficients (highest-degree first) for Horner evaluation.
    Dense(Vec<EF>),
    /// Sparse Lagrange-form nonzero terms, tagged with the column period, for
    /// division-free doubling-product evaluation.
    Sparse {
        period: usize,
        terms: Vec<SparseTerm<EF>>,
    },
}

impl<EF> PeriodicColumn<EF> {
    /// The column period (its evaluation-domain length).
    pub(crate) fn period(&self) -> usize {
        match self {
            Self::Dense(coeffs) => coeffs.len(),
            Self::Sparse { period, .. } => *period,
        }
    }
}

/// Precomputed periodic column data for DAG construction.
#[derive(Debug, Clone)]
pub struct PeriodicColumnData<EF> {
    /// The chosen evaluation form for each periodic column.
    columns: Vec<PeriodicColumn<EF>>,
}

impl<EF> PeriodicColumnData<EF> {
    /// Convert periodic columns (evaluations) into their cheaper in-circuit form.
    ///
    /// Each column is lowered to whichever of two representations yields the smaller
    /// circuit: dense monomial-basis coefficients (via an inverse DFT) evaluated by
    /// Horner, or a sparse Lagrange form over the column's nonzero evaluations. The
    /// choice depends only on the column values, so it is fixed at construction.
    pub fn from_periodic_columns<F>(periodic_columns: Vec<Vec<F>>) -> Self
    where
        F: TwoAdicField,
        EF: From<F>,
    {
        let mut columns = Vec::with_capacity(periodic_columns.len());
        for col in periodic_columns {
            assert!(!col.is_empty(), "periodic column must not be empty");
            assert!(col.len().is_power_of_two(), "periodic column length must be a power of two");

            let period = col.len();
            let log_len = period.ilog2() as usize;
            let terms = sparse_terms::<F, EF>(&col);

            // Dense Horner costs 2 ops per (nonzero-leading) coefficient. Sparse Lagrange
            // costs `3 * log_len` ops per nonzero evaluation to build its doubling product,
            // plus one combining op per term less one shared across the column. Keep
            // whichever form yields the smaller circuit.
            let dense_ops = 2 * period.saturating_sub(1);
            let sparse_ops = terms.len() * (3 * log_len) + terms.len().saturating_sub(1);

            let column = if terms.is_empty() || sparse_ops < dense_ops {
                PeriodicColumn::Sparse { period, terms }
            } else {
                let coeffs = NaiveDft.idft(col).into_iter().map(EF::from).collect();
                PeriodicColumn::Dense(coeffs)
            };
            columns.push(column);
        }

        Self { columns }
    }

    /// Number of periodic columns.
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Maximum periodic column length (used to align powers).
    pub fn max_period(&self) -> usize {
        self.columns.iter().map(PeriodicColumn::period).max().unwrap_or(0)
    }

    /// Iterate over the per-column chosen representations.
    pub(crate) fn columns(&self) -> &[PeriodicColumn<EF>] {
        &self.columns
    }
}

/// Build the sparse Lagrange-form terms for one periodic column's nonzero evaluations.
///
/// For a column of length `P = 2^m` with evaluation-domain generator `omega`, the
/// coefficient-form value at a point `x` equals
/// `(1/P) * sum_j v_j * D(x * omega^(-j))`, where `D(t) = sum_{k=0}^{P-1} t^k`. This
/// is the same identity underlying the dense IDFT + Horner path, reordered so terms
/// with `v_j == 0` drop out entirely and `D` is computed division-free via the
/// doubling product `D(t) = Π_{i=0}^{m-1} (1 + t^(2^i))`.
fn sparse_terms<F, EF>(col: &[F]) -> Vec<SparseTerm<EF>>
where
    F: TwoAdicField,
    EF: From<F>,
{
    let log_len = col.len().ilog2();
    let omega_inv = F::two_adic_generator(log_len as usize).inverse();

    let mut domain_size = F::ZERO;
    for _ in 0..col.len() {
        domain_size += F::ONE;
    }
    let p_inv = domain_size.inverse();

    let mut omega_inv_pow = F::ONE;
    let mut terms = Vec::new();
    for &v in col {
        if v != F::ZERO {
            let mut twiddles = Vec::with_capacity(log_len as usize);
            let mut base = omega_inv_pow;
            for _ in 0..log_len {
                twiddles.push(EF::from(base));
                base *= base;
            }
            terms.push(SparseTerm {
                scaled_value: EF::from(v * p_inv),
                twiddles,
            });
        }
        omega_inv_pow *= omega_inv;
    }
    terms
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
}

impl<EF: Clone> AceDag<EF> {
    /// Remove nodes unreachable from `root` and compact the node vector.
    ///
    /// After compaction, `nodes` contains only nodes reachable from `root`, in the same
    /// relative order. All `NodeId` references, including `root`, are remapped to the new
    /// contiguous indices.
    pub fn compact(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }

        let mut reachable = vec![false; n];
        let mut stack = vec![self.root.index()];
        while let Some(idx) = stack.pop() {
            if reachable[idx] {
                continue;
            }
            reachable[idx] = true;
            match &self.nodes[idx] {
                NodeKind::Add(a, b) | NodeKind::Sub(a, b) | NodeKind::Mul(a, b) => {
                    stack.push(a.index());
                    stack.push(b.index());
                },
                NodeKind::Neg(a) => {
                    stack.push(a.index());
                },
                NodeKind::Input(_) | NodeKind::Constant(_) => {},
            }
        }

        let mut remap = vec![0usize; n];
        let mut new_len = 0usize;
        for i in 0..n {
            if reachable[i] {
                remap[i] = new_len;
                new_len += 1;
            }
        }

        if new_len == n {
            return;
        }

        let dag_id = self.dag_id;
        let remap_id = |id: NodeId| NodeId::in_dag(remap[id.index()], dag_id);

        let mut new_nodes = Vec::with_capacity(new_len);
        for (i, node) in self.nodes.iter().enumerate() {
            if !reachable[i] {
                continue;
            }
            let remapped = match node {
                NodeKind::Input(k) => NodeKind::Input(*k),
                NodeKind::Constant(v) => NodeKind::Constant(v.clone()),
                NodeKind::Add(a, b) => NodeKind::Add(remap_id(*a), remap_id(*b)),
                NodeKind::Sub(a, b) => NodeKind::Sub(remap_id(*a), remap_id(*b)),
                NodeKind::Mul(a, b) => NodeKind::Mul(remap_id(*a), remap_id(*b)),
                NodeKind::Neg(a) => NodeKind::Neg(remap_id(*a)),
            };
            new_nodes.push(remapped);
        }

        self.nodes = new_nodes;
        self.root = remap_id(self.root);
    }
}

impl<EF> DagSnapshot<EF> {
    /// Root node of the verifier equation.
    pub fn root(&self) -> NodeId {
        self.root
    }

    pub(super) fn into_parts(self) -> (DagId, Vec<NodeKind<EF>>, NodeId) {
        (self.source_dag_id, self.nodes, self.root)
    }
}
