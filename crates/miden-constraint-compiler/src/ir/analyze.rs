//! Analyses over the constraint graph.

use alloc::{vec, vec::Vec};

use super::graph::{Class, Graph, Leaf, Node, NodeId, OpKind};

/// Classifies expressions whose inputs are limited to constants and challenges.
///
/// This is a structural dependency analysis: it includes constant expressions and does not
/// simplify cancellations. Public inputs and permutation boundary values are excluded because
/// evaluating them requires inputs beyond the challenge slice.
pub(crate) struct ChallengeDependencies {
    challenge_only: Vec<bool>,
}

impl ChallengeDependencies {
    /// Analyze every node in `graph`, visiting operands before their users.
    pub fn new(graph: &Graph) -> Self {
        let mut challenge_only = vec![false; graph.len()];
        for (id, node) in graph.iter() {
            challenge_only[id.index()] = match node {
                Node::Leaf(Leaf::BaseConst(_) | Leaf::ExtConst(_) | Leaf::Challenge(_)) => true,
                Node::Leaf(Leaf::ExtBase(inner)) => challenge_only[inner.index()],
                Node::Op { x, y, .. } => {
                    challenge_only[x.index()] && y.is_none_or(|y| challenge_only[y.index()])
                },
                _ => false,
            };
        }
        Self { challenge_only }
    }

    /// Whether `id` depends only on constants and challenges.
    ///
    /// `id` must belong to the graph used to construct this analysis.
    pub fn is_challenge_only(&self, id: NodeId) -> bool {
        self.challenge_only[id.index()]
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
    use super::*;

    #[test]
    fn challenge_dependencies_propagate_through_constants_lifts_and_operations() {
        let mut b = Graph::builder();
        let constant = b.leaf(Leaf::BaseConst(3));
        let (base_neg, _) = b.op(Class::Base, OpKind::Neg, constant, None);
        let lifted = b.leaf(Leaf::ExtBase(base_neg));
        let ext_constant = b.leaf(Leaf::ExtConst([5, 0]));
        let challenge = b.leaf(Leaf::Challenge(1));
        let (product, _) = b.op(Class::Ext, OpKind::Mul, lifted, Some(challenge));
        let (sum, _) = b.op(Class::Ext, OpKind::Add, product, Some(ext_constant));
        b.op(Class::Ext, OpKind::Neg, sum, None);
        let graph = b.freeze();
        let dependencies = ChallengeDependencies::new(&graph);
        for (id, _) in graph.iter() {
            assert!(dependencies.is_challenge_only(id), "{id:?}");
        }
    }

    #[test]
    fn challenge_dependencies_exclude_other_inputs_even_when_they_cancel() {
        let mut b = Graph::builder();
        let challenge = b.leaf(Leaf::Challenge(0));
        let mut dependent = Vec::new();
        for leaf in [
            Leaf::Main { offset: 0, index: 0 },
            Leaf::Main { offset: 1, index: 0 },
            Leaf::Aux { offset: 0, index: 0 },
            Leaf::Preprocessed { offset: 0, index: 0 },
            Leaf::Public(0),
            Leaf::Periodic(0),
            Leaf::PermValue(0),
            Leaf::IsFirst,
            Leaf::IsLast,
            Leaf::IsTransition,
        ] {
            let input = b.leaf(leaf);
            let (left, _) = b.op(Class::Ext, OpKind::Mul, input, Some(challenge));
            let (right, _) = b.op(Class::Ext, OpKind::Mul, challenge, Some(input));
            dependent.extend([input, left, right]);
        }
        let public = b.leaf(Leaf::Public(0));
        let (cancelled, _) = b.op(Class::Base, OpKind::Sub, public, Some(public));
        let (neg, _) = b.op(Class::Base, OpKind::Neg, cancelled, None);
        dependent.extend([cancelled, neg]);
        dependent.push(b.leaf(Leaf::ExtBase(public)));
        let graph = b.freeze();
        let dependencies = ChallengeDependencies::new(&graph);
        for id in dependent {
            assert!(!dependencies.is_challenge_only(id), "{id:?}");
        }
    }

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
