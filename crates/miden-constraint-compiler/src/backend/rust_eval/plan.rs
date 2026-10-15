//! Rust-only, typed evaluation choices. The captured graph remains authoritative
//! for ACE and constraint metadata; this plan only changes arithmetic scheduling.

use crate::ir::{CapturedConstraints, Class, Graph, Leaf, Node, NodeId, OpKind};

// Bound array sizes and live ranges. Longer sums retain a materialized prefix.
const MAX_TERMS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DotKind {
    Same,
    Scalar,
    Mixed,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Coefficient {
    Node(NodeId),
    Scalar(u64),
    One,
}

#[derive(Debug)]
pub(super) enum Piece {
    Node(NodeId),
    Dot {
        kind: DotKind,
        pairs: Vec<(NodeId, Coefficient)>,
    },
}

#[derive(Debug)]
pub(super) enum Rewrite {
    Square(NodeId),
    Scalar {
        value: NodeId,
        scalar: u64,
        op: OpKind,
        reversed: bool,
    },
    Factor {
        common: NodeId,
        scalar: Option<u64>,
        left: NodeId,
        right: NodeId,
    },
    Sum(Vec<Piece>),
}

pub(super) struct Plan<'g> {
    graph: &'g Graph,
    uses: Vec<usize>,
}

impl<'g> Plan<'g> {
    pub fn new(graph: &'g Graph, constraints: &CapturedConstraints) -> Self {
        let mut uses = vec![0; graph.len()];
        for (_, node) in graph.iter() {
            match node {
                Node::Op { x, y, .. } => {
                    uses[x.index()] += 1;
                    if let Some(y) = y {
                        uses[y.index()] += 1;
                    }
                },
                Node::Leaf(Leaf::ExtBase(inner)) => uses[inner.index()] += 1,
                _ => {},
            }
        }
        for root in constraints.base_roots.iter().chain(&constraints.ext_roots) {
            uses[root.index()] += 1;
        }
        Self { graph, uses }
    }

    fn constant(&self, id: NodeId) -> Option<u64> {
        match self.graph.node(id) {
            Node::Leaf(Leaf::BaseConst(c)) => Some(c),
            Node::Leaf(Leaf::ExtBase(inner)) => self.constant(inner),
            _ => None,
        }
    }

    fn product(&self, id: NodeId) -> Option<(NodeId, NodeId)> {
        match self.graph.node(id) {
            Node::Op { op: OpKind::Mul, x, y: Some(y), .. }
                if self.uses[id.index()] == 1 && x != y =>
            {
                Some((x, y))
            },
            _ => None,
        }
    }

    // Only Add is associative here. In particular, never flatten subtraction,
    // cancel selector factors, or use bounded-integer facts about trace limbs.
    fn terms(&self, id: NodeId, class: Class, root: bool, out: &mut Vec<NodeId>) {
        if out.len() >= MAX_TERMS {
            out.push(id);
            return;
        }
        match self.graph.node(id) {
            Node::Op { class: c, op: OpKind::Add, x, y: Some(y) }
                if c == class && (root || self.uses[id.index()] == 1) =>
            {
                self.terms(x, class, false, out);
                self.terms(y, class, false, out);
            },
            _ => out.push(id),
        }
    }

    fn pair(&self, id: NodeId, class: Class, kind: DotKind) -> Option<(NodeId, Coefficient)> {
        let product = self.product(id);
        match kind {
            DotKind::Scalar if class == Class::Base => {
                if let Some((x, y)) = product {
                    if let Some(c) = self.constant(x) {
                        return Some((y, Coefficient::Scalar(c)));
                    }
                    if let Some(c) = self.constant(y) {
                        return Some((x, Coefficient::Scalar(c)));
                    }
                    return None;
                }
                Some((id, Coefficient::Scalar(1)))
            },
            DotKind::Mixed if class == Class::Ext => {
                if let Some((x, y)) = product {
                    return match (self.graph.class(x), self.graph.class(y)) {
                        (Class::Ext, Class::Base) => Some((x, Coefficient::Node(y))),
                        (Class::Base, Class::Ext) => Some((y, Coefficient::Node(x))),
                        _ => None,
                    };
                }
                (self.graph.class(id) == Class::Ext).then_some((id, Coefficient::One))
            },
            DotKind::Same => {
                let (x, y) = product?;
                (self.graph.class(x) == class && self.graph.class(y) == class)
                    .then_some((x, Coefficient::Node(y)))
            },
            _ => None,
        }
    }

    fn pieces(&self, terms: &[NodeId], class: Class) -> Vec<Piece> {
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < terms.len() {
            let mut selected = None;
            for kind in [DotKind::Scalar, DotKind::Mixed, DotKind::Same] {
                let pairs: Vec<_> =
                    terms[start..].iter().map_while(|&id| self.pair(id, class, kind)).collect();
                // Unit terms allow beta^0*x and non-product prefixes, but a dot
                // must consume a real, single-use multiplication to be useful.
                if pairs.len() >= 2
                    && terms[start..start + pairs.len()]
                        .iter()
                        .any(|&id| self.product(id).is_some())
                {
                    selected = Some((kind, pairs));
                    break;
                }
            }
            if let Some((kind, pairs)) = selected {
                start += pairs.len();
                pieces.push(Piece::Dot { kind, pairs });
            } else {
                pieces.push(Piece::Node(terms[start]));
                start += 1;
            }
        }
        pieces
    }

    pub fn rewrite(&self, id: NodeId) -> Option<Rewrite> {
        let Node::Op { class, op, x, y: Some(y) } = self.graph.node(id) else {
            return None;
        };
        if op == OpKind::Mul && x == y {
            return Some(Rewrite::Square(x));
        }
        if class == Class::Base {
            if let Some(scalar) = self.constant(y) {
                return Some(Rewrite::Scalar { value: x, scalar, op, reversed: false });
            }
            if let Some(scalar) = self.constant(x) {
                return Some(Rewrite::Scalar { value: y, scalar, op, reversed: true });
            }
        }
        if op != OpKind::Add {
            return None;
        }
        if let (Some((a, b)), Some((c, d))) = (self.product(x), self.product(y)) {
            for (common, left, other, right) in
                [(a, b, c, d), (a, b, d, c), (b, a, c, d), (b, a, d, c)]
            {
                if common == other
                    && self.graph.class(common) == class
                    && self.graph.class(left) == class
                    && self.graph.class(right) == class
                {
                    return Some(Rewrite::Factor {
                        common,
                        scalar: self.constant(common),
                        left,
                        right,
                    });
                }
            }
        }
        let mut terms = Vec::new();
        self.terms(id, class, true, &mut terms);
        if terms.len() > MAX_TERMS {
            // Keep a shared/materialized prefix and try its descendants later.
            terms = vec![x, y];
        }
        let pieces = self.pieces(&terms, class);
        if terms.len() >= 4 || pieces.iter().any(|p| matches!(p, Piece::Dot { .. })) {
            Some(Rewrite::Sum(pieces))
        } else {
            None
        }
    }
}
