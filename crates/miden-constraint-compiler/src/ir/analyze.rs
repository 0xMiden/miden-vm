//! Analyses over the constraint graph.

use super::graph::{Class, Graph, Node, OpKind};

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
