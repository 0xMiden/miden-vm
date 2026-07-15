//! The hash-consed constraint expression graph.
//!
//! Nodes are interned by typed structural keys, with ids assigned densely in
//! first-encounter order — so id order is topological: children precede parents.
//!
//! Ids are internal to the IR (invariant 2 in the crate docs): deterministic, but
//! not part of any artifact contract. Backends that feed digest-visible interning
//! (the ACE `DagBuilder`) define their own traversal order over this graph.

use std::collections::{HashMap, hash_map::Entry};

/// Graph node identifier; assigned densely in first-encounter (= topological) order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// Position of this node in [`Graph::iter`] order.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Field operation performed by a [`Node::Op`] node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    Add,
    Sub,
    Mul,
    /// Negation — the only unary operation.
    Neg,
}

/// Whether a node evaluates in the base field or the extension field.
///
/// Base-field subexpressions stay in base arithmetic and enter extension
/// expressions only through an explicit [`Leaf::ExtBase`] boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Base,
    Ext,
}

/// Leaf sources, mirroring the constraint evaluator's inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leaf {
    /// Main trace column at row offset 0 (current) or 1 (next).
    Main { offset: usize, index: usize },
    /// Public value.
    Public(usize),
    /// Periodic column value.
    Periodic(usize),
    /// First-row selector.
    IsFirst,
    /// Last-row selector.
    IsLast,
    /// Transition selector.
    IsTransition,
    /// Base-field constant (canonical representation).
    BaseConst(u64),
    /// Aux trace column at row offset 0 (current) or 1 (next).
    Aux { offset: usize, index: usize },
    /// Random challenge.
    Challenge(usize),
    /// Permutation boundary value.
    PermValue(usize),
    /// Extension-field constant (canonical basis coefficients).
    ExtConst([u64; 2]),
    /// A base-class subtree used inside an extension expression; the lift into
    /// the extension happens at the wrapper's use sites.
    ExtBase(NodeId),
}

/// A graph node: a leaf input or a field operation over earlier nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf(Leaf),
    Op {
        class: Class,
        op: OpKind,
        x: NodeId,
        /// `None` exactly when `op` is [`OpKind::Neg`].
        y: Option<NodeId>,
    },
}

/// Structural identity key for hash-consing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Leaf(Leaf),
    Op {
        class: Class,
        op: OpKind,
        x: NodeId,
        y: Option<NodeId>,
    },
}

/// Interning builder for a [`Graph`].
///
/// Captures may share one builder: structurally identical expressions intern to
/// identical ids regardless of which capture reached them first, so structural
/// equality of two evaluators reduces to comparing per-constraint root ids.
///
/// The interning methods are crate-internal ([`NodeId`]s are positional, so an id
/// from another builder could silently alias the wrong node); graphs are built
/// through `ir::capture`.
#[derive(Default)]
pub struct GraphBuilder {
    nodes: Vec<Node>,
    interner: HashMap<Key, NodeId>,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes interned so far.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Intern a leaf, returning the id of its unique node.
    pub(crate) fn leaf(&mut self, leaf: Leaf) -> NodeId {
        if let Leaf::ExtBase(inner) = leaf {
            debug_assert!(inner.index() < self.nodes.len(), "ExtBase wraps a foreign node id");
        }
        self.intern(Key::Leaf(leaf), Node::Leaf(leaf)).0
    }

    /// Intern an operation over already-interned children, returning `(id, fresh)`
    /// where `fresh` is false when an identical node already existed.
    ///
    /// `y` must be `None` exactly when `op` is [`OpKind::Neg`].
    pub(crate) fn op(
        &mut self,
        class: Class,
        op: OpKind,
        x: NodeId,
        y: Option<NodeId>,
    ) -> (NodeId, bool) {
        debug_assert_eq!(matches!(op, OpKind::Neg), y.is_none(), "Neg is unary; the rest binary");
        debug_assert!(x.index() < self.nodes.len(), "operand x is a foreign node id");
        debug_assert!(
            y.is_none_or(|y| y.index() < self.nodes.len()),
            "operand y is a foreign node id"
        );
        self.intern(Key::Op { class, op, x, y }, Node::Op { class, op, x, y })
    }

    /// Finish building and freeze into an immutable [`Graph`].
    pub fn freeze(self) -> Graph {
        Graph { nodes: self.nodes }
    }

    fn intern(&mut self, key: Key, node: Node) -> (NodeId, bool) {
        let next = NodeId(u32::try_from(self.nodes.len()).expect("more than u32::MAX nodes"));
        match self.interner.entry(key) {
            Entry::Occupied(e) => (*e.get(), false),
            Entry::Vacant(v) => {
                v.insert(next);
                self.nodes.push(node);
                (next, true)
            },
        }
    }
}

/// An immutable, hash-consed constraint expression graph.
///
/// Node ids are dense and topological (children precede parents), so a single
/// forward pass over [`Graph::iter`] visits every node after its operands.
#[derive(Debug, PartialEq, Eq)]
pub struct Graph {
    nodes: Vec<Node>,
}

impl Graph {
    pub fn builder() -> GraphBuilder {
        GraphBuilder::new()
    }

    pub fn node(&self, id: NodeId) -> Node {
        self.nodes[id.index()]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Iterate `(id, node)` in topological (interning) order.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, Node)> + '_ {
        self.nodes.iter().enumerate().map(|(i, n)| (NodeId(i as u32), *n))
    }

    /// The evaluation class of `id`.
    ///
    /// [`Leaf::ExtBase`] reports the class of the subtree it wraps (base);
    /// consumers decide how to realize the lift.
    pub fn class(&self, id: NodeId) -> Class {
        match self.node(id) {
            Node::Op { class, .. } => class,
            Node::Leaf(leaf) => match leaf {
                Leaf::Aux { .. } | Leaf::Challenge(_) | Leaf::PermValue(_) | Leaf::ExtConst(_) => {
                    Class::Ext
                },
                Leaf::ExtBase(inner) => self.class(inner),
                _ => Class::Base,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_dedupes_structurally() {
        let mut b = Graph::builder();
        let a = b.leaf(Leaf::Main { offset: 0, index: 3 });
        let a2 = b.leaf(Leaf::Main { offset: 0, index: 3 });
        assert_eq!(a, a2);

        let c = b.leaf(Leaf::BaseConst(7));
        let (s1, fresh1) = b.op(Class::Base, OpKind::Add, a, Some(c));
        let (s2, fresh2) = b.op(Class::Base, OpKind::Add, a, Some(c));
        assert_eq!(s1, s2);
        assert!(fresh1);
        assert!(!fresh2);

        // Same operands, different op — and same op, different class: distinct
        // nodes. (An ext op over base operands is not a well-formed capture shape,
        // but the key must still discriminate on class.)
        let (m, _) = b.op(Class::Base, OpKind::Mul, a, Some(c));
        let (me, _) = b.op(Class::Ext, OpKind::Mul, a, Some(c));
        assert_ne!(s1, m);
        assert_ne!(m, me);
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn ids_are_dense_and_topological() {
        let mut b = Graph::builder();
        let x = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let y = b.leaf(Leaf::Main { offset: 1, index: 0 });
        let (d, _) = b.op(Class::Base, OpKind::Sub, y, Some(x));
        b.op(Class::Base, OpKind::Neg, d, None);
        let g = b.freeze();

        assert_eq!(g.len(), 4);
        for (id, node) in g.iter() {
            if let Node::Op { x, y, .. } = node {
                assert!(x < id);
                if let Some(y) = y {
                    assert!(y < id);
                }
            }
        }
        assert_eq!(
            g.node(d),
            Node::Op {
                class: Class::Base,
                op: OpKind::Sub,
                x: y,
                y: Some(x)
            }
        );
    }

    #[test]
    fn class_of_ext_base_is_the_wrapped_class() {
        let mut b = Graph::builder();
        let base = b.leaf(Leaf::Periodic(0));
        let wrapped = b.leaf(Leaf::ExtBase(base));
        let ch = b.leaf(Leaf::Challenge(0));
        let (prod, _) = b.op(Class::Ext, OpKind::Mul, wrapped, Some(ch));
        let g = b.freeze();

        assert_eq!(g.class(base), Class::Base);
        assert_eq!(g.class(wrapped), Class::Base);
        assert_eq!(g.class(ch), Class::Ext);
        assert_eq!(g.class(prod), Class::Ext);
    }
}
