//! Selects challenge-only results to share across native row evaluations.

use crate::ir::{
    CapturedConstraints, Class, Graph, Leaf, Node, NodeId, analyze::ChallengeDependencies,
};

/// One cache layout shared by preparation and row emission for a captured AIR.
///
/// Select reachable extension operations whose results feed expressions requiring other inputs
/// or are assertion roots themselves. Intermediate results stay local to preparation. Leaves
/// and base operations receive no cache slots.
pub(super) struct PreparationPlan {
    terms: Vec<NodeId>,
    slots: Vec<Option<usize>>,
}

impl PreparationPlan {
    pub(super) fn new(graph: &Graph, constraints: &CapturedConstraints) -> Self {
        let dependencies = ChallengeDependencies::new(graph);
        let mut needed = vec![false; graph.len()];
        for &root in constraints.base_roots.iter().chain(&constraints.ext_roots) {
            needed[root.index()] = true;
        }
        // Parents precede their children in reverse graph order. Stop at challenge-only nodes:
        // their operands are also challenge-only, so this path has no further boundary.
        for (id, node) in graph.iter().rev() {
            if !needed[id.index()] || dependencies.is_challenge_only(id) {
                continue;
            }
            let children = match node {
                Node::Op { x, y, .. } => [Some(x), y],
                Node::Leaf(Leaf::ExtBase(inner)) => [Some(inner), None],
                _ => [None, None],
            };
            for child in children.into_iter().flatten() {
                needed[child.index()] = true;
            }
        }

        // Assign slots in graph order, independently of the root order.
        let mut terms = Vec::new();
        let mut slots = vec![None; graph.len()];
        for (id, node) in graph.iter() {
            if needed[id.index()]
                && dependencies.is_challenge_only(id)
                && matches!(node, Node::Op { class: Class::Ext, .. })
            {
                slots[id.index()] = Some(terms.len());
                terms.push(id);
            }
        }
        Self { terms, slots }
    }

    pub(super) fn terms(&self) -> &[NodeId] {
        &self.terms
    }

    pub(super) fn slot(&self, id: NodeId) -> Option<usize> {
        self.slots[id.index()]
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
        let square = b.op(Class::Ext, OpKind::Mul, beta, Some(beta));
        let cube = b.op(Class::Ext, OpKind::Mul, square, Some(beta));
        let unused = b.op(Class::Ext, OpKind::Mul, cube, Some(beta));
        let neg = b.op(Class::Ext, OpKind::Neg, beta, None);
        let main = b.leaf(Leaf::Main { offset: 0, index: 0 });
        let aux = b.leaf(Leaf::Aux { offset: 0, index: 0 });
        let first = b.op(Class::Ext, OpKind::Mul, cube, Some(main));
        let second = b.op(Class::Ext, OpKind::Mul, cube, Some(aux));
        let third = b.op(Class::Ext, OpKind::Mul, neg, Some(aux));
        let graph = b.freeze();
        let plan = PreparationPlan::new(&graph, &constraints(vec![], vec![third, second, first]));

        assert_eq!(plan.terms(), [cube, neg]);
        assert_eq!(plan.slot(cube), Some(0));
        assert_eq!(plan.slot(neg), Some(1));
        for id in [beta, square, unused, main, aux, first, second, third] {
            assert_eq!(plan.slot(id), None, "{id:?}");
        }
    }

    #[test]
    fn challenge_only_assertions_cache_extension_operations() {
        let mut b = GraphBuilder::new();
        let constant = b.leaf(Leaf::BaseConst(3));
        let base = b.op(Class::Base, OpKind::Neg, constant, None);
        let lifted = b.leaf(Leaf::ExtBase(base));
        let ext_constant = b.leaf(Leaf::ExtConst([7, 0]));
        let ext_neg = b.op(Class::Ext, OpKind::Neg, ext_constant, None);
        let beta = b.leaf(Leaf::Challenge(0));
        let square = b.op(Class::Ext, OpKind::Mul, beta, Some(beta));
        let cube = b.op(Class::Ext, OpKind::Mul, square, Some(beta));
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
