//! Analyses over the constraint graph: op counting and gate grouping.

use std::collections::HashMap;

use super::graph::{Class, Graph, Node, NodeId, OpKind};

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

/// Gate grouping over constraint roots: assign each mul-root to its most-shared
/// factor. Returns `(groups, ungated)` where each group is
/// `(gate id, members [(local constraint index, inner id)])` with two or more
/// members, and `ungated` holds `(local index, root id)` for everything else.
///
/// Grouping exploits `sum_j a_j * (s * E_j) = s * sum_j a_j * E_j`, which is
/// bit-exact (field addition is associative). A gate product that is also a shared
/// subexpression of other constraints stays live regardless, so grouping only
/// removes the muls of products nothing else uses.
#[allow(clippy::type_complexity)]
pub fn gate_groups(
    graph: &Graph,
    roots: &[NodeId],
) -> (Vec<(NodeId, Vec<(usize, NodeId)>)>, Vec<(usize, NodeId)>) {
    let mut factor_counts: HashMap<NodeId, usize> = HashMap::new();
    for &r in roots {
        if let Some((x, y)) = graph.mul_children(r) {
            *factor_counts.entry(x).or_default() += 1;
            *factor_counts.entry(y).or_default() += 1;
        }
    }
    let mut groups: Vec<(NodeId, Vec<(usize, NodeId)>)> = Vec::new();
    let mut index_of: HashMap<NodeId, usize> = HashMap::new();
    let mut ungated: Vec<(usize, NodeId)> = Vec::new();
    for (j, &r) in roots.iter().enumerate() {
        let Some((x, y)) = graph.mul_children(r) else {
            ungated.push((j, r));
            continue;
        };
        let (gate, inner) = if factor_counts[&x] >= factor_counts[&y] {
            (x, y)
        } else {
            (y, x)
        };
        let gi = *index_of.entry(gate).or_insert_with(|| {
            groups.push((gate, Vec::new()));
            groups.len() - 1
        });
        groups[gi].1.push((j, inner));
    }
    let (kept, single): (Vec<_>, Vec<_>) = groups.into_iter().partition(|(_, m)| m.len() >= 2);
    for (_, members) in single {
        let (j, _) = members[0];
        ungated.push((j, roots[j]));
    }
    ungated.sort_unstable();
    (kept, ungated)
}

#[cfg(test)]
mod tests {
    use super::{super::graph::Leaf, *};

    /// Roots `s*a`, `s*b`, `t*a`, `c`: factor counts are s=2, a=2, t=1, b=1, so the
    /// first two group under `s` (`s*a` ties s-vs-a and keeps its left factor), the
    /// third picks `a` but stays a singleton (folded into ungated), and `c` is not
    /// a mul at all.
    #[test]
    fn gate_groups_pick_most_shared_factor_and_cover_roots() {
        let mut b = Graph::builder();
        let s = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let t = b.leaf(Leaf::Main { offset: 0, index: 1 });
        let a = b.leaf(Leaf::Main { offset: 0, index: 2 });
        let bb = b.leaf(Leaf::Main { offset: 0, index: 3 });
        let c = b.leaf(Leaf::Main { offset: 0, index: 4 });
        let (sa, _) = b.op(Class::Base, OpKind::Mul, s, Some(a));
        let (sb, _) = b.op(Class::Base, OpKind::Mul, s, Some(bb));
        let (ta, _) = b.op(Class::Base, OpKind::Mul, t, Some(a));
        let roots = [sa, sb, ta, c];
        let g = b.freeze();

        let (groups, ungated) = gate_groups(&g, &roots);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, s);
        assert_eq!(groups[0].1, vec![(0, a), (1, bb)]);
        assert_eq!(ungated, vec![(2, ta), (3, c)]);

        let covered: usize = groups.iter().map(|(_, m)| m.len()).sum::<usize>() + ungated.len();
        assert_eq!(covered, roots.len());
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
