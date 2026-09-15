use core::sync::atomic::{AtomicUsize, Ordering};

use miden_crypto::{
    field::TwoAdicField,
    stark::dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft},
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

/// Domain indices sharing one coefficient in a basis-combined periodic column.
#[derive(Debug, Clone)]
pub(crate) struct BasisClass<EF> {
    pub(crate) coefficient: EF,
    pub(crate) indices: Vec<usize>,
}

/// Constants defining the Lagrange basis of an order-`period` subgroup.
///
/// `L_j(x) = roots[j] * period_inv * Π_{k != j} (x - roots[k])`, with `roots[k] = omega^k`: the
/// omitted denominator `Π_{k != j} (omega^j - omega^k)` is the derivative of `x^period - 1` at
/// `omega^j`, which equals `period * omega^(-j)`.
#[derive(Debug, Clone)]
pub(crate) struct LagrangeBasis<EF> {
    pub(crate) roots: Vec<EF>,
    pub(crate) period_inv: EF,
}

impl<EF> LagrangeBasis<EF> {
    fn new<F>(period: usize) -> Self
    where
        F: TwoAdicField,
        EF: From<F>,
    {
        let omega = F::two_adic_generator(period.ilog2() as usize);
        let mut domain_size = F::ZERO;
        for _ in 0..period {
            domain_size += F::ONE;
        }
        let mut roots = Vec::with_capacity(period);
        let mut root = F::ONE;
        for _ in 0..period {
            roots.push(EF::from(root));
            root *= omega;
        }
        Self {
            roots,
            period_inv: EF::from(domain_size.inverse()),
        }
    }
}

/// The in-circuit evaluation form chosen for a single periodic column.
///
/// The cheapest representation is selected from the column values when the data is built; the
/// lowering emits nodes for whichever form each column carries.
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
    /// `offset + Σ coefficient * Σ_{j in indices} L_j` over the Lagrange basis of the column
    /// period, which every column of that period shares. Because the basis sums to one, a
    /// dominant value may become the offset, leaving only the other domain points to sum.
    Basis {
        period: usize,
        basis: LagrangeBasis<EF>,
        offset: EF,
        classes: Vec<BasisClass<EF>>,
    },
}

impl<EF> PeriodicColumn<EF> {
    /// The column period (its evaluation-domain length).
    pub(crate) fn period(&self) -> usize {
        match self {
            Self::Dense(coeffs) => coeffs.len(),
            Self::Sparse { period, .. } | Self::Basis { period, .. } => *period,
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
    /// Convert periodic columns (evaluations) into their cheapest in-circuit form.
    ///
    /// Each column is first lowered to whichever of two standalone representations yields the
    /// smaller circuit: dense monomial-basis coefficients (via an inverse DFT) evaluated by
    /// Horner, or a sparse Lagrange form over the column's nonzero evaluations. Columns of one
    /// period may instead share that period's Lagrange basis, whose fixed cost is paid
    /// once; a period adopts the basis only when its columns' combined savings exceed that cost.
    /// The choice depends only on the column values, so it is fixed at construction.
    pub fn from_periodic_columns<F>(periodic_columns: Vec<Vec<F>>) -> Self
    where
        F: TwoAdicField,
        EF: From<F>,
    {
        let dft = Radix2DFTSmallBatch::<F>::default();
        let mut columns = Vec::with_capacity(periodic_columns.len());
        let mut basis_costs = Vec::with_capacity(periodic_columns.len());
        for col in &periodic_columns {
            assert!(!col.is_empty(), "periodic column must not be empty");
            assert!(col.len().is_power_of_two(), "periodic column length must be a power of two");

            let period = col.len();
            let log_len = period.ilog2() as usize;
            let terms = sparse_terms::<F, EF>(col);

            // Dense Horner costs 2 ops per (nonzero-leading) coefficient. Sparse Lagrange
            // costs `3 * log_len` ops per nonzero evaluation to build its doubling product,
            // plus one combining op per term less one shared across the column. Keep
            // whichever form yields the smaller circuit.
            let dense_ops = 2 * period.saturating_sub(1);
            let sparse_ops = terms.len() * (3 * log_len) + terms.len().saturating_sub(1);
            let standalone_felts = if terms.is_empty() || sparse_ops < dense_ops {
                sparse_ops + CONSTANT_FELTS * (terms.len() + log_len)
            } else {
                dense_ops + CONSTANT_FELTS * period
            };

            let column = if terms.is_empty() || sparse_ops < dense_ops {
                PeriodicColumn::Sparse { period, terms }
            } else {
                let coeffs = dft.idft(col.clone()).into_iter().map(EF::from).collect();
                PeriodicColumn::Dense(coeffs)
            };
            columns.push(column);
            basis_costs.push(basis_column_cost(col).map(|cost| (cost, standalone_felts)));
        }

        // A period adopts the shared basis when the columns that are cheaper over it save more
        // than the basis itself costs. Other columns keep their standalone form.
        let mut periods: Vec<usize> = periodic_columns.iter().map(Vec::len).collect();
        periods.sort_unstable();
        periods.dedup();
        for period in periods {
            let savings: usize = periodic_columns
                .iter()
                .zip(&basis_costs)
                .filter(|(col, _)| col.len() == period)
                .filter_map(|(_, cost)| *cost)
                .map(|(basis, standalone)| standalone.saturating_sub(basis))
                .sum();
            if period < 2 || savings <= basis_overhead_felts(period) {
                continue;
            }
            for ((column, col), cost) in columns.iter_mut().zip(&periodic_columns).zip(&basis_costs)
            {
                if col.len() != period {
                    continue;
                }
                if let Some((basis, standalone)) = cost
                    && basis < standalone
                {
                    let (offset, classes) = basis_combination(col);
                    *column = PeriodicColumn::Basis {
                        period,
                        basis: LagrangeBasis::new::<F>(period),
                        offset: EF::from(offset),
                        classes: classes
                            .into_iter()
                            .map(|(coefficient, indices)| BasisClass {
                                coefficient: EF::from(coefficient),
                                indices,
                            })
                            .collect(),
                    };
                }
            }
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

/// Base-field elements encoding one extension-field constant in the instruction stream.
const CONSTANT_FELTS: usize = 2;

/// Stream cost of a period's Lagrange basis: one subtraction per domain point, prefix and suffix
/// product chains, one product and one root scaling per basis element, and one constant per
/// domain point plus the inverse period.
fn basis_overhead_felts(period: usize) -> usize {
    5 * period + CONSTANT_FELTS * (period + 1)
}

/// Chooses how a column combines basis elements: either every nonzero value class with its value
/// as coefficient, or, since the basis sums to one, the dominant nonzero value `d` as the offset
/// with every other class (including zeros) weighted by `value - d`. Returns the cheaper form as
/// `(offset, [(coefficient, indices)])`, classes ordered by first index and zero coefficients
/// omitted.
fn basis_combination<F: TwoAdicField>(col: &[F]) -> (F, Vec<(F, Vec<usize>)>) {
    let mut classes: Vec<(F, Vec<usize>)> = Vec::new();
    for (index, &value) in col.iter().enumerate() {
        match classes.iter_mut().find(|(class_value, _)| *class_value == value) {
            Some((_, indices)) => indices.push(index),
            None => classes.push((value, vec![index])),
        }
    }

    let direct: Vec<(F, Vec<usize>)> =
        classes.iter().filter(|(value, _)| *value != F::ZERO).cloned().collect();
    let dominant = classes
        .iter()
        .filter(|(value, _)| *value != F::ZERO)
        .max_by_key(|(_, indices)| indices.len())
        .map(|(value, _)| *value);
    let Some(dominant) = dominant else {
        return (F::ZERO, direct);
    };
    let complemented: Vec<(F, Vec<usize>)> = classes
        .iter()
        .filter(|(value, _)| *value != dominant)
        .map(|(value, indices)| (*value - dominant, indices.clone()))
        .collect();

    if combination_cost(dominant, &complemented) < combination_cost(F::ZERO, &direct) {
        (dominant, complemented)
    } else {
        (F::ZERO, direct)
    }
}

/// Stream cost of `offset + Σ coefficient * Σ L_j`: one addition per basis element and class
/// after the first, one addition for a nonzero offset, and one scaling plus a constant for each
/// coefficient other than one or minus one.
fn combination_cost<F: TwoAdicField>(offset: F, classes: &[(F, Vec<usize>)]) -> usize {
    let elements: usize = classes.iter().map(|(_, indices)| indices.len()).sum();
    let mut constants: Vec<F> = Vec::new();
    let mut scalings = 0;
    for (coefficient, _) in classes {
        if *coefficient != F::ONE && *coefficient != -F::ONE {
            scalings += 1;
            if !constants.contains(coefficient) {
                constants.push(*coefficient);
            }
        }
    }
    let offset_felts = if offset == F::ZERO { 0 } else { 1 + CONSTANT_FELTS };
    elements.saturating_sub(1) + scalings + CONSTANT_FELTS * constants.len() + offset_felts
}

/// Stream cost of combining a column over its period's basis. Returns `None` for constant
/// columns, which never need a basis.
fn basis_column_cost<F: TwoAdicField>(col: &[F]) -> Option<usize> {
    if col.len() < 2 {
        return None;
    }
    let (offset, classes) = basis_combination(col);
    Some(combination_cost(offset, &classes))
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
    /// contiguous indices. When any node is removed, the DAG also takes a fresh `dag_id`,
    /// so `NodeId`s issued before compaction fail provenance checks instead of silently
    /// resolving to whichever node now occupies their old index.
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

        let dag_id = DagId::fresh();
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
        self.dag_id = dag_id;
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
