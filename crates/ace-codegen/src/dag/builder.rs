use std::collections::HashMap;

use p3_field::PrimeCharacteristicRing;

use super::ir::{NodeId, NodeKind};
use crate::layout::InputKey;

/// A hash-consed DAG builder.
///
/// The builder de-duplicates identical subexpressions to keep the circuit
/// compact and deterministic.
#[derive(Debug)]
pub struct DagBuilder<EF> {
    nodes: Vec<NodeKind<EF>>,
    cache: HashMap<NodeKind<EF>, NodeId>,
}

impl<EF> DagBuilder<EF>
where
    EF: PrimeCharacteristicRing + Copy + Eq + std::hash::Hash,
{
    /// Create an empty, hash-consed DAG builder.
    pub fn new() -> Self {
        Self { nodes: Vec::new(), cache: HashMap::new() }
    }

    /// Consume the builder and return its node list.
    pub fn into_nodes(self) -> Vec<NodeKind<EF>> {
        self.nodes
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

    fn intern(&mut self, node: NodeKind<EF>) -> NodeId {
        if let Some(id) = self.cache.get(&node) {
            return *id;
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(node.clone());
        self.cache.insert(node, id);
        id
    }
}

impl<EF> Default for DagBuilder<EF>
where
    EF: PrimeCharacteristicRing + Copy + Eq + std::hash::Hash,
{
    fn default() -> Self {
        Self::new()
    }
}
