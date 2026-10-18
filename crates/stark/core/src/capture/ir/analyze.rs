//! Analyses over the constraint graph.

use alloc::vec::Vec;

use super::{
    CapturedConstraints,
    graph::{Class, Graph, Leaf, Node, OpKind},
};
use crate::air::ConstraintDegrees;

/// Raw symbolic degree multiples for one captured AIR, split by assertion class.
///
/// Matches `ConstraintDegrees::from_air`: trace columns, periodic values and first/last
/// selectors have degree 1; transition selectors, public inputs, challenges and boundary
/// values have degree 0. Lifting a base expression preserves its degree. An empty class
/// has degree 0. This is not the trace-size-aware quotient bound and does not apply an
/// AIR's advisory degree hint.
pub fn constraint_degrees(graph: &Graph, constraints: &CapturedConstraints) -> ConstraintDegrees {
    let mut degrees: Vec<usize> = Vec::with_capacity(graph.len());
    for (_, node) in graph.iter() {
        let degree = match node {
            Node::Leaf(
                Leaf::Preprocessed { .. }
                | Leaf::Main { .. }
                | Leaf::Periodic(_)
                | Leaf::IsFirst
                | Leaf::IsLast
                | Leaf::Aux { .. },
            ) => 1,
            Node::Leaf(Leaf::ExtBase(inner)) => degrees[inner.index()],
            Node::Leaf(_) => 0,
            Node::Op { op, x, y, .. } => {
                let x = degrees[x.index()];
                match op {
                    OpKind::Neg => x,
                    OpKind::Add | OpKind::Sub => x.max(degrees[y.unwrap().index()]),
                    OpKind::Mul => x
                        .checked_add(degrees[y.unwrap().index()])
                        .expect("captured constraint degree overflow"),
                }
            },
        };
        degrees.push(degree);
    }
    ConstraintDegrees {
        base: constraints.base_roots.iter().map(|id| degrees[id.index()]).max().unwrap_or(0),
        ext: constraints.ext_roots.iter().map(|id| degrees[id.index()]).max().unwrap_or(0),
    }
}

/// Field-operation counts, split by kind.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpCounts {
    pub add: usize,
    pub sub: usize,
    pub mul: usize,
    pub neg: usize,
}

impl OpCounts {
    pub fn total(&self) -> usize {
        self.add + self.sub + self.mul + self.neg
    }

    pub(crate) fn bump(&mut self, op: OpKind) {
        match op {
            OpKind::Add => self.add += 1,
            OpKind::Sub => self.sub += 1,
            OpKind::Mul => self.mul += 1,
            OpKind::Neg => self.neg += 1,
        }
    }
}

/// Count the unique (hash-consed) ops in `graph`, as `(base, ext)`.
///
/// This is what a CSE'd evaluator executes — each op node once. Counts cover the
/// whole graph: for per-AIR numbers, capture each AIR into its own builder.
pub fn op_counts(graph: &Graph) -> (OpCounts, OpCounts) {
    let mut base = OpCounts::default();
    let mut ext = OpCounts::default();
    for (_, node) in graph.iter() {
        if let Node::Op { class, op, .. } = node {
            match class {
                Class::Base => base.bump(op),
                Class::Ext => ext.bump(op),
            }
        }
    }
    (base, ext)
}

#[cfg(test)]
mod tests {
    use super::{super::graph::Leaf, *};

    #[test]
    fn op_counts_split_by_class_over_unique_nodes() {
        let mut b = Graph::builder();
        let x = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let ch = b.leaf(Leaf::Challenge(0));
        let (s, _) = b.op(Class::Base, OpKind::Add, x, Some(x));
        b.op(Class::Base, OpKind::Add, x, Some(x)); // dedupes: no new node
        let xe = b.leaf(Leaf::ExtBase(s));
        b.op(Class::Ext, OpKind::Mul, xe, Some(ch));
        let g = b.freeze();

        let (base, ext) = op_counts(&g);
        assert_eq!(base, OpCounts { add: 1, sub: 0, mul: 0, neg: 0 });
        assert_eq!(ext, OpCounts { add: 0, sub: 0, mul: 1, neg: 0 });
    }
}
