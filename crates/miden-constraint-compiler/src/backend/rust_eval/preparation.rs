//! Selects challenge-only results to share across native row evaluations.

use crate::ir::{CapturedConstraints, ChallengeDependencies, Class, Graph, Leaf, Node, NodeId};

/// One cache layout shared by preparation and row emission for a captured AIR.
///
/// Select reachable extension operations whose results feed expressions requiring other inputs
/// or are assertion roots themselves. Intermediate results stay local to preparation. Leaves
/// and base operations receive no cache slots.
pub(super) struct PreparationPlan<'g> {
    graph: &'g Graph,
    terms: Vec<NodeId>,
    slots: Vec<Option<usize>>,
    challenge_count: usize,
}

impl<'g> PreparationPlan<'g> {
    pub(super) fn new(graph: &'g Graph, constraints: &CapturedConstraints) -> Self {
        let dependencies = ChallengeDependencies::new(graph);
        let mut needed = vec![false; graph.len()];
        let mut pending = Vec::new();
        let mut visit = |id: NodeId, pending: &mut Vec<NodeId>| {
            if !needed[id.index()] {
                needed[id.index()] = true;
                pending.push(id);
            }
        };
        for &root in constraints.base_roots.iter().chain(&constraints.ext_roots) {
            visit(root, &mut pending);
        }
        while let Some(id) = pending.pop() {
            if dependencies.is_challenge_only(id) {
                // Its operands are also challenge-only, so this path has no further boundary.
                continue;
            }
            let children = match graph.node(id) {
                Node::Op { x, y, .. } => [Some(x), y],
                Node::Leaf(Leaf::ExtBase(inner)) => [Some(inner), None],
                _ => [None, None],
            };
            for child in children.into_iter().flatten() {
                visit(child, &mut pending);
            }
        }

        // Assign slots in graph order, independently of the root traversal order.
        let mut terms = Vec::new();
        let mut slots = vec![None; graph.len()];
        let mut challenge_count = 0;
        for (id, node) in graph.iter() {
            if needed[id.index()]
                && dependencies.is_challenge_only(id)
                && matches!(node, Node::Op { class: Class::Ext, .. })
            {
                slots[id.index()] = Some(terms.len());
                terms.push(id);
            }
            if let Node::Leaf(Leaf::Challenge(index)) = node {
                challenge_count = challenge_count.max(index + 1);
            }
        }
        Self { graph, terms, slots, challenge_count }
    }

    pub(super) fn graph(&self) -> &'g Graph {
        self.graph
    }

    pub(super) fn terms(&self) -> &[NodeId] {
        &self.terms
    }

    pub(super) fn slot(&self, id: NodeId) -> Option<usize> {
        self.slots[id.index()]
    }

    pub(super) fn challenge_count(&self) -> usize {
        self.challenge_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{GraphBuilder, OpCounts, OpKind};

    fn constraints(base_roots: Vec<NodeId>, ext_roots: Vec<NodeId>) -> CapturedConstraints {
        CapturedConstraints {
            base_global_indices: (0..base_roots.len()).collect(),
            ext_global_indices: (base_roots.len()..base_roots.len() + ext_roots.len()).collect(),
            base_roots,
            ext_roots,
            naive_base: OpCounts::default(),
            naive_ext: OpCounts::default(),
        }
    }

    #[test]
    fn slots_cover_live_boundaries_in_graph_order() {
        let mut b = GraphBuilder::new();
        let beta = b.leaf(Leaf::Challenge(1));
        let (square, _) = b.op(Class::Ext, OpKind::Mul, beta, Some(beta));
        let (cube, _) = b.op(Class::Ext, OpKind::Mul, square, Some(beta));
        let (unused, _) = b.op(Class::Ext, OpKind::Mul, cube, Some(beta));
        let (neg, _) = b.op(Class::Ext, OpKind::Neg, beta, None);
        let main = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let aux = b.leaf(Leaf::Aux { offset: 0, index: 0 });
        let (first, _) = b.op(Class::Ext, OpKind::Mul, cube, Some(main));
        let (second, _) = b.op(Class::Ext, OpKind::Mul, cube, Some(aux));
        let (third, _) = b.op(Class::Ext, OpKind::Mul, neg, Some(aux));
        let graph = b.freeze();
        let plan = PreparationPlan::new(&graph, &constraints(vec![], vec![third, second, first]));

        assert_eq!(plan.terms(), [cube, neg]);
        assert_eq!(plan.slot(cube), Some(0));
        assert_eq!(plan.slot(neg), Some(1));
        for id in [beta, square, unused, main, aux, first, second, third] {
            assert_eq!(plan.slot(id), None, "{id:?}");
        }
        assert_eq!(plan.challenge_count(), 2);
    }

    #[test]
    fn challenge_only_assertions_cache_extension_operations() {
        let mut b = GraphBuilder::new();
        let constant = b.leaf(Leaf::BaseConst(3));
        let (base, _) = b.op(Class::Base, OpKind::Neg, constant, None);
        let lifted = b.leaf(Leaf::ExtBase(base));
        let ext_constant = b.leaf(Leaf::ExtConst([7, 0]));
        let (ext_neg, _) = b.op(Class::Ext, OpKind::Neg, ext_constant, None);
        let beta = b.leaf(Leaf::Challenge(0));
        let (square, _) = b.op(Class::Ext, OpKind::Mul, beta, Some(beta));
        let (cube, _) = b.op(Class::Ext, OpKind::Mul, square, Some(beta));
        let graph = b.freeze();
        let plan = PreparationPlan::new(
            &graph,
            &constraints(
                vec![constant, base],
                vec![lifted, beta, ext_constant, square, ext_neg, cube],
            ),
        );

        assert_eq!(plan.terms(), [ext_neg, square, cube]);
        for id in [constant, base, lifted, beta, ext_constant] {
            assert_eq!(plan.slot(id), None, "{id:?}");
        }
    }
}
