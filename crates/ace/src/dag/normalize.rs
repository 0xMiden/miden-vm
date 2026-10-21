//! Gate-count normalization for completed ACE DAGs.

use std::collections::HashMap;

use miden_crypto::field::Field;

use super::{AceDag, DagBuilder, NodeId, NodeKind};

/// Normalize identities that depend on final node fanout.
///
/// Each rewrite consumes only single-use intermediate nodes. Common-factor extraction replaces
/// two products and their sum or difference with one product and one sum or difference.
/// Associative rotation is applied only when the alternate inner expression already exists, so it
/// removes a node instead of merely changing the tree shape.
pub(crate) fn normalize_dag<EF: Field>(mut dag: AceDag<EF>) -> AceDag<EF> {
    loop {
        let (normalized, reduced) = normalize_once(dag);
        if !reduced {
            return normalized;
        }
        dag = normalized;
    }
}

fn normalize_once<EF: Field>(dag: AceDag<EF>) -> (AceDag<EF>, bool) {
    let before = dag.nodes.len();
    let fanout = fanout(&dag);
    let node_by_kind: HashMap<_, _> = dag
        .nodes
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, node)| (node, index))
        .collect();

    let root_index = dag.root().index();
    let mut builder = DagBuilder::new();
    let mut mapped = Vec::with_capacity(dag.nodes.len());
    let mut changed = false;

    for (index, node) in dag.nodes.iter().enumerate() {
        let id = match *node {
            NodeKind::Input(key) => builder.input(key),
            NodeKind::Constant(value) => builder.constant(value),
            NodeKind::Add(a, b) => {
                if let Some((factor, a_other, b_other)) = common_factor(&dag, &fanout, a, b) {
                    changed = true;
                    let sum = builder.add(mapped[a_other.index()], mapped[b_other.index()]);
                    builder.mul(mapped[factor.index()], sum)
                } else if let Some((existing, remaining)) =
                    existing_rotation(&dag, &fanout, &node_by_kind, index, a, b, AssociativeOp::Add)
                        .or_else(|| {
                            existing_rotation(
                                &dag,
                                &fanout,
                                &node_by_kind,
                                index,
                                b,
                                a,
                                AssociativeOp::Add,
                            )
                        })
                {
                    changed = true;
                    builder.add(mapped[existing], mapped[remaining])
                } else {
                    builder.add(mapped[a.index()], mapped[b.index()])
                }
            },
            NodeKind::Sub(a, b) => {
                if let Some((factor, a_other, b_other)) = common_factor(&dag, &fanout, a, b) {
                    changed = true;
                    let difference = builder.sub(mapped[a_other.index()], mapped[b_other.index()]);
                    builder.mul(mapped[factor.index()], difference)
                } else {
                    builder.sub(mapped[a.index()], mapped[b.index()])
                }
            },
            NodeKind::Mul(a, b) => {
                if let Some((existing, remaining)) =
                    existing_rotation(&dag, &fanout, &node_by_kind, index, a, b, AssociativeOp::Mul)
                        .or_else(|| {
                            existing_rotation(
                                &dag,
                                &fanout,
                                &node_by_kind,
                                index,
                                b,
                                a,
                                AssociativeOp::Mul,
                            )
                        })
                {
                    changed = true;
                    builder.mul(mapped[existing], mapped[remaining])
                } else {
                    builder.mul(mapped[a.index()], mapped[b.index()])
                }
            },
            NodeKind::Neg(a) => builder.neg(mapped[a.index()]),
        };
        mapped.push(id);
    }

    let root = mapped[root_index];
    let mut normalized = builder.build(root);
    normalized.compact();
    if changed && normalized.nodes.len() < before {
        (normalized, true)
    } else {
        // Interacting rewrites can make an otherwise saved node already dead. Discard a
        // size-neutral round so normalization cannot oscillate or change the protocol for no win.
        (dag, false)
    }
}

fn fanout<EF>(dag: &AceDag<EF>) -> Vec<usize> {
    let mut fanout = vec![0usize; dag.nodes.len()];
    for node in &dag.nodes {
        match node {
            NodeKind::Add(a, b) | NodeKind::Sub(a, b) | NodeKind::Mul(a, b) => {
                fanout[a.index()] += 1;
                fanout[b.index()] += 1;
            },
            NodeKind::Neg(a) => fanout[a.index()] += 1,
            NodeKind::Input(_) | NodeKind::Constant(_) => {},
        }
    }
    fanout[dag.root().index()] += 1;
    fanout
}

fn common_factor<EF>(
    dag: &AceDag<EF>,
    fanout: &[usize],
    a: NodeId,
    b: NodeId,
) -> Option<(NodeId, NodeId, NodeId)> {
    let NodeKind::Mul(a0, a1) = dag.nodes[a.index()] else {
        return None;
    };
    let NodeKind::Mul(b0, b1) = dag.nodes[b.index()] else {
        return None;
    };
    if fanout[a.index()] != 1 || fanout[b.index()] != 1 {
        return None;
    }

    for (factor, a_other) in [(a0, a1), (a1, a0)] {
        if factor == b0 {
            return Some((factor, a_other, b1));
        }
        if factor == b1 {
            return Some((factor, a_other, b0));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum AssociativeOp {
    Add,
    Mul,
}

fn existing_rotation<EF>(
    dag: &AceDag<EF>,
    fanout: &[usize],
    node_by_kind: &HashMap<NodeKind<EF>, usize>,
    parent_index: usize,
    inner: NodeId,
    other: NodeId,
    op: AssociativeOp,
) -> Option<(usize, usize)>
where
    EF: Eq + core::hash::Hash,
{
    if fanout[inner.index()] != 1 {
        return None;
    }
    let (x, y) = match (&dag.nodes[inner.index()], op) {
        (NodeKind::Add(x, y), AssociativeOp::Add) | (NodeKind::Mul(x, y), AssociativeOp::Mul) => {
            (*x, *y)
        },
        _ => return None,
    };

    for (candidate_operand, remaining) in [(x, y), (y, x)] {
        let (lhs, rhs) = canonical_pair(candidate_operand, other);
        let candidate = match op {
            AssociativeOp::Add => NodeKind::Add(lhs, rhs),
            AssociativeOp::Mul => NodeKind::Mul(lhs, rhs),
        };
        if let Some(&candidate_index) = node_by_kind.get(&candidate)
            && candidate_index < parent_index
        {
            return Some((candidate_index, remaining.index()));
        }
    }
    None
}

fn canonical_pair(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    if a <= b { (a, b) } else { (b, a) }
}

#[cfg(test)]
mod tests {
    use miden_core::field::QuadFelt;

    use super::normalize_dag;
    use crate::{InputKey, dag::DagBuilder};

    #[test]
    fn factors_single_use_products() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let factor = builder.input(InputKey::Public(2));
        let af = builder.mul(a, factor);
        let bf = builder.mul(b, factor);
        let root = builder.add(af, bf);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert_eq!(normalized.nodes.len(), before - 1);
    }

    #[test]
    fn preserves_products_with_multiple_consumers() {
        let mut builder = DagBuilder::<QuadFelt>::new();
        let a = builder.input(InputKey::Public(0));
        let b = builder.input(InputKey::Public(1));
        let factor = builder.input(InputKey::Public(2));
        let c = builder.input(InputKey::Public(3));
        let d = builder.input(InputKey::Public(4));
        let independent_factor = builder.input(InputKey::Public(5));
        let af = builder.mul(a, factor);
        let bf = builder.mul(b, factor);
        let sum = builder.add(af, bf);
        let shared = builder.add(sum, af);
        let cf = builder.mul(c, independent_factor);
        let df = builder.mul(d, independent_factor);
        let independent_sum = builder.add(cf, df);
        let root = builder.add(shared, independent_sum);
        let mut dag = builder.build(root);
        dag.compact();
        let before = dag.nodes.len();

        let normalized = normalize_dag(dag);

        assert!(normalized.nodes.len() < before, "the independent factorization must run");
        let fanout = super::fanout(&normalized);
        assert!(
            normalized
                .nodes
                .iter()
                .enumerate()
                .any(|(index, node)| matches!(node, crate::NodeKind::Mul(_, _))
                    && fanout[index] == 2),
            "the shared product must keep both consumers"
        );
    }

    #[test]
    fn rotates_single_use_chains_toward_existing_nodes() {
        for multiply in [false, true] {
            let mut builder = DagBuilder::<QuadFelt>::new();
            let a = builder.input(InputKey::Public(0));
            let b = builder.input(InputKey::Public(1));
            let c = builder.input(InputKey::Public(2));
            let existing = if multiply { builder.mul(a, c) } else { builder.add(a, c) };
            let nested = if multiply { builder.mul(a, b) } else { builder.add(a, b) };
            let target = if multiply {
                builder.mul(nested, c)
            } else {
                builder.add(nested, c)
            };
            let root = builder.add(existing, target);
            let mut dag = builder.build(root);
            dag.compact();
            let before = dag.nodes.len();

            let normalized = normalize_dag(dag);

            assert_eq!(normalized.nodes.len(), before - 1);
        }
    }
}
