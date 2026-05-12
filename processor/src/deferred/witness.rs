use alloc::{collections::BTreeSet, vec::Vec};

use miden_core::deferred::{DeferredWitness, Digest};

use super::state::DeferredState;

/// Extract the reachable subgraph of `state` as a [`DeferredWitness`].
///
/// Reachability is rooted at the lhs/rhs digests of every assertion. A BFS follows op-node
/// children via [`Node::binary_op_children`](miden_core::deferred::Node::binary_op_children);
/// digests that aren't in the state's node map are silently skipped (the assertion still
/// witnesses them — the verifier will surface the missing node as an evaluation failure if it
/// matters).
///
/// Output ordering is deterministic: nodes sorted by digest, assertions in insertion order.
pub fn extract_witness(state: &DeferredState) -> DeferredWitness {
    let mut visited: BTreeSet<Digest> = BTreeSet::new();
    let mut worklist: Vec<Digest> = Vec::new();

    for assertion in state.assertions() {
        worklist.push(assertion.lhs);
        worklist.push(assertion.rhs);
    }

    while let Some(digest) = worklist.pop() {
        if !visited.insert(digest) {
            continue;
        }
        if let Some(node) = state.get(&digest)
            && let Some((lhs, rhs)) = node.binary_op_children()
        {
            worklist.push(lhs);
            worklist.push(rhs);
        }
    }

    let nodes: Vec<_> =
        visited.into_iter().filter_map(|d| state.get(&d).map(|n| (d, *n))).collect();
    DeferredWitness::new(nodes, state.assertions().to_vec())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::deferred::{DeferredTag, Payload};

    use super::*;
    use crate::deferred::{
        events::{assert_eq, binary_op_payload, register_node},
        handlers::Field0Handler,
        registry::TypeHandlerRegistry,
    };
    use miden_core::{Felt, deferred::TagKind};

    fn make_registry() -> TypeHandlerRegistry {
        let mut reg = TypeHandlerRegistry::new();
        reg.register(Arc::new(Field0Handler)).unwrap();
        reg
    }

    fn field0_leaf(low: u64) -> (DeferredTag, Payload) {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        (DeferredTag::Field0Leaf, Payload::new(limbs))
    }

    #[test]
    fn empty_state_yields_empty_witness() {
        let state = DeferredState::new();
        let w = extract_witness(&state);
        assert!(w.nodes.is_empty());
        assert!(w.assertions.is_empty());
    }

    #[test]
    fn unreachable_nodes_are_excluded() {
        // Register two leaves; only assert one of them is equal to itself. The orphan stays in
        // the state but must not appear in the witness.
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(1);
        let (orphan_tag, orphan_payload) = field0_leaf(99);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let _orphan =
            register_node(&mut state, &reg, orphan_tag, orphan_payload, TagKind::Leaf).unwrap();
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, a, a).unwrap();

        let w = extract_witness(&state);
        assert_eq!(w.nodes.len(), 1);
        assert_eq!(w.nodes[0].0, a);
        assert_eq!(w.assertions.len(), 1);
    }

    #[test]
    fn reachable_subgraph_includes_op_nodes_and_their_children() {
        // (a + b) * c == precomputed_35
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (c_tag, c_payload) = field0_leaf(5);
        let (expected_tag, expected_payload) = field0_leaf(35);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        let c = register_node(&mut state, &reg, c_tag, c_payload, TagKind::Leaf).unwrap();
        let expected =
            register_node(&mut state, &reg, expected_tag, expected_payload, TagKind::Leaf).unwrap();
        let add = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Add,
            binary_op_payload(a, b),
            TagKind::BinaryOp,
        )
        .unwrap();
        let mul = register_node(
            &mut state,
            &reg,
            DeferredTag::Field0Mul,
            binary_op_payload(add, c),
            TagKind::BinaryOp,
        )
        .unwrap();
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, mul, expected).unwrap();

        let w = extract_witness(&state);
        // Six nodes: a, b, c, expected, add, mul.
        assert_eq!(w.nodes.len(), 6);
        let digests: BTreeSet<_> = w.nodes.iter().map(|(d, _)| *d).collect();
        for d in [a, b, c, expected, add, mul] {
            assert!(digests.contains(&d));
        }
    }

    #[test]
    fn node_ordering_is_deterministic_by_digest() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(11);
        let (b_tag, b_payload) = field0_leaf(22);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        // Assert each leaf equal to itself so both digests show up in the witness.
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, a, a).unwrap();
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, b, b).unwrap();

        let w = extract_witness(&state);
        // Two adjacent extracts must produce identical, sorted ordering.
        let w2 = extract_witness(&state);
        assert_eq!(w.nodes, w2.nodes);
        assert!(w.nodes.windows(2).all(|p| p[0].0 < p[1].0));
    }

    #[test]
    fn assertions_preserve_insertion_order() {
        let mut state = DeferredState::new();
        let reg = make_registry();
        let (a_tag, a_payload) = field0_leaf(1);
        let (b_tag, b_payload) = field0_leaf(2);
        let a = register_node(&mut state, &reg, a_tag, a_payload, TagKind::Leaf).unwrap();
        let b = register_node(&mut state, &reg, b_tag, b_payload, TagKind::Leaf).unwrap();
        // Self-equal each so both succeed.
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, a, a).unwrap();
        assert_eq(&mut state, &reg, DeferredTag::Field0AssertEq, b, b).unwrap();

        let w = extract_witness(&state);
        assert_eq!(w.assertions.len(), 2);
        assert_eq!(w.assertions[0].lhs, a);
        assert_eq!(w.assertions[1].lhs, b);
    }
}
