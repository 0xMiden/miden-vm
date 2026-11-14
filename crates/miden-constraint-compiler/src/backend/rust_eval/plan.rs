//! Rust-only, typed evaluation choices. The captured graph remains authoritative
//! for ACE and constraint metadata; this plan only changes arithmetic scheduling.

use super::index::ExpressionIndex;
use crate::ir::{Class, OpKind};
use miden_stark::air::symbolic::ExprView;

// Bound array sizes and live ranges. Longer sums retain a materialized prefix.
pub(super) const MAX_TERMS: usize = 16;
// Reserve array/gather dots for larger regions. Tiny cases keep arithmetic
// explicit, including small scalar scalings and packed multiplies.
const MIN_DOT_TERMS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DotKind {
    Same,
    Scalar,
    Mixed,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Coefficient {
    Node(usize),
    Scalar(u64),
    One,
}

#[derive(Debug)]
pub(super) enum Piece {
    Node(usize),
    Dot {
        kind: DotKind,
        pairs: Vec<(usize, Coefficient)>,
    },
}

#[derive(Debug)]
pub(super) enum Rewrite {
    Square(usize),
    Scalar {
        value: usize,
        scalar: u64,
        op: OpKind,
        reversed: bool,
    },
    Factor {
        common: usize,
        scalar: Option<u64>,
        left: usize,
        right: usize,
    },
    Sum(Vec<Piece>),
}

/// The class of an arithmetic result: extension if either operand is.
pub(super) fn join(a: Class, b: Class) -> Class {
    if a == Class::Ext { a } else { b }
}

pub(super) struct Plan<'g, 'a> {
    graph: &'g ExpressionIndex<'a>,
    uses: Vec<usize>,
}

impl<'g, 'a> Plan<'g, 'a> {
    pub fn new(graph: &'g ExpressionIndex<'a>, materialized: &[usize]) -> Self {
        let mut uses = vec![0; graph.len()];
        for id in 0..graph.len() {
            for &child in graph.children(id) {
                uses[child] += 1;
            }
        }
        for &(root, _) in &graph.roots {
            uses[root] += 1;
        }
        for &id in materialized {
            uses[id] = uses[id].max(2);
        }
        Self { graph, uses }
    }

    fn constant(&self, id: usize) -> Option<u64> {
        self.graph.constant(id)
    }

    fn operation(&self, id: usize) -> Option<(Class, OpKind, usize, Option<usize>)> {
        let op = match self.graph.node(id).view() {
            ExprView::Add { .. } => OpKind::Add,
            ExprView::Sub { .. } => OpKind::Sub,
            ExprView::Mul { .. } => OpKind::Mul,
            ExprView::Neg { .. } => OpKind::Neg,
            // Explicit structured calls are opaque to scalar pattern recovery.
            _ => return None,
        };
        let inputs = self.graph.children(id);
        Some((self.graph.class(id), op, inputs[0], inputs.get(1).copied()))
    }

    fn product(&self, id: usize) -> Option<(usize, usize)> {
        match self.operation(id) {
            Some((_, OpKind::Mul, x, Some(y))) if self.uses[id] == 1 && x != y => Some((x, y)),
            _ => None,
        }
    }

    // Only Add is associative here. In particular, never flatten subtraction,
    // cancel selector factors, or use bounded-integer facts about trace limbs.
    fn terms(&self, id: usize, class: Class, root: bool, out: &mut Vec<usize>) {
        if out.len() >= MAX_TERMS {
            out.push(id);
            return;
        }
        match self.operation(id) {
            Some((c, OpKind::Add, x, Some(y))) if c == class && (root || self.uses[id] == 1) => {
                self.terms(x, class, false, out);
                self.terms(y, class, false, out);
            },
            _ => out.push(id),
        }
    }

    fn pair(&self, id: usize, class: Class, kind: DotKind) -> Option<(usize, Coefficient)> {
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
                    return match (self.graph.value_class(x), self.graph.value_class(y)) {
                        (Class::Ext, Class::Base) => Some((x, Coefficient::Node(y))),
                        (Class::Base, Class::Ext) => Some((y, Coefficient::Node(x))),
                        _ => None,
                    };
                }
                (self.graph.class(id) == Class::Ext).then_some((id, Coefficient::One))
            },
            DotKind::Same => {
                let (x, y) = product?;
                (self.graph.value_class(x) == class && self.graph.value_class(y) == class)
                    .then_some((x, Coefficient::Node(y)))
            },
            _ => None,
        }
    }

    fn pieces(&self, terms: &[usize], class: Class) -> Vec<Piece> {
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < terms.len() {
            let mut selected = None;
            for kind in [DotKind::Scalar, DotKind::Mixed, DotKind::Same] {
                let pairs: Vec<_> =
                    terms[start..].iter().map_while(|&id| self.pair(id, class, kind)).collect();
                // Unit terms allow beta^0*x and non-product prefixes, but a dot
                // must consume a real, single-use multiplication to be useful.
                if pairs.len() >= MIN_DOT_TERMS
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

    pub fn rewrite(&self, id: usize) -> Option<Rewrite> {
        let Some((class, op, x, Some(y))) = self.operation(id) else {
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
                let sum = join(self.graph.value_class(left), self.graph.value_class(right));
                if common == other && join(self.graph.value_class(common), sum) == class {
                    return Some(Rewrite::Factor {
                        common,
                        scalar: self.constant(common).filter(|_| class == Class::Base),
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
