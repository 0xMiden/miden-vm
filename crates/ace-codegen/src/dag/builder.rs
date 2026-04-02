use std::collections::HashMap;

use miden_crypto::field::Field;

use super::ir::{DagId, DagSnapshot, NodeId, NodeKind};
use crate::layout::InputKey;

/// A hash-consed DAG builder.
///
/// The builder de-duplicates identical subexpressions to keep the circuit
/// compact and deterministic.
#[derive(Debug)]
pub struct DagBuilder<EF> {
    dag_id: DagId,
    nodes: Vec<NodeKind<EF>>,
    cache: HashMap<NodeKind<EF>, NodeId>,
    imported_dag: Option<ImportedDag>,
}

impl<EF> DagBuilder<EF>
where
    EF: Field,
{
    /// Create an empty, hash-consed DAG builder.
    pub fn new() -> Self {
        Self {
            dag_id: DagId::fresh(),
            nodes: Vec::new(),
            cache: HashMap::new(),
            imported_dag: None,
        }
    }

    /// Resume building from existing nodes using the published 0.23.0 API shape.
    ///
    /// Imported node ids are rebased onto the new builder, and ids from the source DAG
    /// are accepted only when that provenance is encoded in the node graph itself.
    pub fn from_nodes(nodes: Vec<NodeKind<EF>>) -> Self {
        let imported_dag = infer_dag_id(&nodes)
            .map(|source_dag_id| ImportedDag { source_dag_id, imported_len: nodes.len() });
        let dag_id = DagId::fresh();
        let nodes = rebase_nodes(nodes, dag_id);

        Self::from_existing_nodes(dag_id, nodes, imported_dag)
    }

    /// Resume building from an exported snapshot.
    ///
    /// This preserves the original DAG id even when the imported nodes are all leaves.
    pub fn from_snapshot(snapshot: DagSnapshot<EF>) -> Self {
        let (source_dag_id, nodes, _) = snapshot.into_parts();
        let dag_id = DagId::fresh();
        let imported_dag = Some(ImportedDag { source_dag_id, imported_len: nodes.len() });
        let nodes = rebase_nodes(nodes, dag_id);

        Self::from_existing_nodes(dag_id, nodes, imported_dag)
    }

    /// Resume building from an existing DAG.
    ///
    /// Rebuilds the deduplication cache so that subsequent operations reuse
    /// existing subexpressions.
    pub fn from_dag(dag: super::AceDag<EF>) -> Self {
        let dag_id = dag.dag_id();
        Self::from_existing_nodes(dag_id, dag.into_nodes(), None)
    }

    fn from_existing_nodes(
        dag_id: DagId,
        nodes: Vec<NodeKind<EF>>,
        imported_dag: Option<ImportedDag>,
    ) -> Self {
        let cache = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), NodeId::in_dag(i, dag_id)))
            .collect();
        Self { dag_id, nodes, cache, imported_dag }
    }

    /// Consume the builder and return its node list.
    pub fn into_nodes(self) -> Vec<NodeKind<EF>> {
        self.nodes
    }

    /// Consume the builder and return a DAG with the provided root.
    pub fn build(self, root: NodeId) -> super::AceDag<EF> {
        let root = self.resolve_id(root, "DAG root must refer to a node built by this DagBuilder");

        super::AceDag::from_parts(self.dag_id, self.nodes, root)
    }

    /// Add an input node.
    pub fn input(&mut self, key: InputKey) -> NodeId {
        self.intern(NodeKind::Input(key))
    }

    /// Add a constant node.
    pub fn constant(&mut self, value: EF) -> NodeId {
        self.intern(NodeKind::Constant(value))
    }

    /// Add an addition node (with constant folding).
    pub fn add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let a = self.resolve_node(a);
        let b = self.resolve_node(b);
        if let (Some(x), Some(y)) = (self.const_value(a), self.const_value(b)) {
            return self.constant(x + y);
        }
        if self.is_zero(a) {
            return b;
        }
        if self.is_zero(b) {
            return a;
        }
        let (l, r) = if a <= b { (a, b) } else { (b, a) };
        self.intern(NodeKind::Add(l, r))
    }

    /// Add a subtraction node (with constant folding).
    pub fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let a = self.resolve_node(a);
        let b = self.resolve_node(b);
        if let (Some(x), Some(y)) = (self.const_value(a), self.const_value(b)) {
            return self.constant(x - y);
        }
        if self.is_zero(b) {
            return a;
        }
        self.intern(NodeKind::Sub(a, b))
    }

    /// Add a multiplication node (with constant folding).
    pub fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let a = self.resolve_node(a);
        let b = self.resolve_node(b);
        if let (Some(x), Some(y)) = (self.const_value(a), self.const_value(b)) {
            return self.constant(x * y);
        }
        if self.is_zero(a) || self.is_zero(b) {
            return self.constant(EF::ZERO);
        }
        if self.is_one(a) {
            return b;
        }
        if self.is_one(b) {
            return a;
        }
        let (l, r) = if a <= b { (a, b) } else { (b, a) };
        self.intern(NodeKind::Mul(l, r))
    }

    /// Add a negation node (with constant folding).
    pub fn neg(&mut self, a: NodeId) -> NodeId {
        let a = self.resolve_node(a);
        if let Some(x) = self.const_value(a) {
            return self.constant(-x);
        }
        self.intern(NodeKind::Neg(a))
    }

    fn const_value(&self, id: NodeId) -> Option<EF> {
        match self.nodes.get(id.index())? {
            NodeKind::Constant(v) => Some(*v),
            _ => None,
        }
    }

    fn is_zero(&self, id: NodeId) -> bool {
        self.const_value(id).is_some_and(|v| v == EF::ZERO)
    }

    fn is_one(&self, id: NodeId) -> bool {
        self.const_value(id).is_some_and(|v| v == EF::ONE)
    }

    fn resolve_node(&self, id: NodeId) -> NodeId {
        self.resolve_id(id, "DAG node must come from this DagBuilder")
    }

    fn intern(&mut self, node: NodeKind<EF>) -> NodeId {
        if let Some(id) = self.cache.get(&node) {
            return *id;
        }
        let id = NodeId::in_dag(self.nodes.len(), self.dag_id);
        self.nodes.push(node.clone());
        self.cache.insert(node, id);
        id
    }

    fn resolve_id(&self, id: NodeId, message: &str) -> NodeId {
        assert!(id.index() < self.nodes.len(), "{message}");

        if id.dag_id == self.dag_id {
            return id;
        }

        if let Some(imported) = &self.imported_dag
            && imported.source_dag_id == id.dag_id
            && id.index() < imported.imported_len
        {
            return NodeId::in_dag(id.index(), self.dag_id);
        }

        panic!("{message}");
    }
}

fn infer_dag_id<EF>(nodes: &[NodeKind<EF>]) -> Option<DagId> {
    nodes.iter().find_map(|node| match node {
        NodeKind::Add(a, _) | NodeKind::Sub(a, _) | NodeKind::Mul(a, _) | NodeKind::Neg(a) => {
            Some(a.dag_id)
        },
        NodeKind::Input(_) | NodeKind::Constant(_) => None,
    })
}

fn rebase_nodes<EF>(nodes: Vec<NodeKind<EF>>, dag_id: DagId) -> Vec<NodeKind<EF>> {
    nodes
        .into_iter()
        .map(|node| match node {
            NodeKind::Input(key) => NodeKind::Input(key),
            NodeKind::Constant(value) => NodeKind::Constant(value),
            NodeKind::Add(a, b) => NodeKind::Add(rebase_node(a, dag_id), rebase_node(b, dag_id)),
            NodeKind::Sub(a, b) => NodeKind::Sub(rebase_node(a, dag_id), rebase_node(b, dag_id)),
            NodeKind::Mul(a, b) => NodeKind::Mul(rebase_node(a, dag_id), rebase_node(b, dag_id)),
            NodeKind::Neg(a) => NodeKind::Neg(rebase_node(a, dag_id)),
        })
        .collect()
}

fn rebase_node(id: NodeId, dag_id: DagId) -> NodeId {
    NodeId::in_dag(id.index(), dag_id)
}

#[derive(Debug, Clone)]
struct ImportedDag {
    source_dag_id: DagId,
    imported_len: usize,
}

impl<EF> Default for DagBuilder<EF>
where
    EF: Field,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, field::QuadFelt};

    use super::DagBuilder;
    use crate::layout::InputKey;

    fn felt(value: u64) -> QuadFelt {
        QuadFelt::from(Felt::new(value))
    }

    #[test]
    #[should_panic(expected = "DAG root must refer to a node built by this DagBuilder")]
    fn build_rejects_same_index_root_from_another_builder() {
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign_root = foreign_builder.constant(felt(1));

        let mut builder = DagBuilder::<QuadFelt>::new();
        builder.constant(felt(1));

        let _ = builder.build(foreign_root);
    }

    #[test]
    #[should_panic(expected = "DAG node must come from this DagBuilder")]
    fn add_rejects_foreign_node() {
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(2));

        let mut builder = DagBuilder::<QuadFelt>::new();
        let local = builder.constant(felt(1));

        let _ = builder.add(local, foreign);
    }

    #[test]
    #[should_panic(expected = "DAG node must come from this DagBuilder")]
    fn sub_rejects_foreign_node() {
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(2));

        let mut builder = DagBuilder::<QuadFelt>::new();
        let local = builder.constant(felt(1));

        let _ = builder.sub(local, foreign);
    }

    #[test]
    #[should_panic(expected = "DAG node must come from this DagBuilder")]
    fn mul_rejects_foreign_node() {
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(2));

        let mut builder = DagBuilder::<QuadFelt>::new();
        let local = builder.constant(felt(1));

        let _ = builder.mul(local, foreign);
    }

    #[test]
    #[should_panic(expected = "DAG node must come from this DagBuilder")]
    fn neg_rejects_foreign_node() {
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(2));

        let mut builder = DagBuilder::<QuadFelt>::new();
        let _ = builder.constant(felt(1));

        let _ = builder.neg(foreign);
    }

    #[test]
    fn from_dag_preserves_node_ownership() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.constant(felt(1));
        let dag = builder.build(a);
        let root = dag.root();

        let mut rebuilt = DagBuilder::from_dag(dag);
        let b = rebuilt.constant(felt(2));
        let sum = rebuilt.add(root, b);

        let rebuilt_dag = rebuilt.build(sum);
        assert_eq!(rebuilt_dag.root().index(), sum.index());
    }

    #[test]
    fn from_nodes_accepts_published_root_shape() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Gamma);
        let b = builder.constant(felt(2));
        let root = builder.add(a, b);
        let dag = builder.build(root);

        let mut rebuilt = DagBuilder::from_nodes(dag.nodes.clone());
        let c = rebuilt.constant(felt(3));
        let sum = rebuilt.add(dag.root, c);

        let rebuilt_dag = rebuilt.build(sum);
        assert_eq!(rebuilt_dag.root().index(), sum.index());
    }

    #[test]
    fn from_nodes_accepts_leaf_only_root_shape() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.constant(felt(1));
        let dag = builder.build(a);

        let root = dag.root();
        let mut rebuilt = DagBuilder::from_snapshot(dag.into_snapshot());
        let b = rebuilt.constant(felt(2));
        let sum = rebuilt.add(root, b);

        let rebuilt_dag = rebuilt.build(sum);
        assert_eq!(rebuilt_dag.root().index(), sum.index());
    }

    #[test]
    fn from_snapshot_accepts_leaf_only_root_after_source_dag_is_dropped() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.constant(felt(1));
        let snapshot = builder.build(a).into_snapshot();
        let root = snapshot.root();

        let mut rebuilt = DagBuilder::from_snapshot(snapshot);
        let b = rebuilt.constant(felt(2));
        let sum = rebuilt.add(root, b);

        let rebuilt_dag = rebuilt.build(sum);
        assert_eq!(rebuilt_dag.root().index(), sum.index());
    }

    #[test]
    #[should_panic(expected = "DAG node must come from this DagBuilder")]
    fn from_nodes_rejects_foreign_node_from_another_builder() {
        let mut source_builder = DagBuilder::<QuadFelt>::new();
        let a = source_builder.input(InputKey::Gamma);
        let b = source_builder.constant(felt(2));
        let root = source_builder.add(a, b);
        let dag = source_builder.build(root);

        let mut rebuilt = DagBuilder::from_nodes(dag.nodes.clone());
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(3));

        let _ = rebuilt.add(dag.root, foreign);
    }

    #[test]
    #[should_panic(expected = "DAG root must refer to a node built by this DagBuilder")]
    fn from_nodes_rejects_foreign_root_from_another_builder() {
        let mut source_builder = DagBuilder::<QuadFelt>::new();
        let a = source_builder.input(InputKey::Gamma);
        let b = source_builder.constant(felt(2));
        let root = source_builder.add(a, b);
        let dag = source_builder.build(root);

        let rebuilt = DagBuilder::from_nodes(dag.nodes.clone());
        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(3));

        let _ = rebuilt.build(foreign);
    }

    #[test]
    #[should_panic(expected = "DAG root must refer to a node built by this DagBuilder")]
    fn from_nodes_leaf_only_rejects_foreign_root_before_any_imported_id() {
        let mut source_builder = DagBuilder::<QuadFelt>::new();
        let source = source_builder.constant(felt(1));
        let dag = source_builder.build(source);

        let rebuilt = DagBuilder::from_nodes(dag.nodes.clone());
        let _ = rebuilt.build(dag.root);
    }

    #[test]
    #[should_panic(expected = "DAG root must refer to a node built by this DagBuilder")]
    fn from_snapshot_leaf_only_rejects_foreign_root() {
        let mut source_builder = DagBuilder::<QuadFelt>::new();
        let source = source_builder.constant(felt(1));
        let snapshot = source_builder.build(source).into_snapshot();

        let mut foreign_builder = DagBuilder::<QuadFelt>::new();
        let foreign = foreign_builder.constant(felt(3));
        let foreign_dag = foreign_builder.build(foreign);

        let rebuilt = DagBuilder::from_snapshot(snapshot);
        let _ = rebuilt.build(foreign_dag.root);
    }
}
