use alloc::{collections::BTreeSet, vec::Vec};

use miden_core::deferred::{DeferredWitness, Digest};

use super::{schema::Schema, state::DeferredState};

/// Extract the reachable subgraph of `state` as a [`DeferredWitness`].
///
/// Reachability is rooted at the lhs/rhs digests of every assertion. A BFS follows op-node
/// children via [`Schema::children`]; digests that aren't in the state's node map are silently
/// skipped (the assertion still witnesses them — the verifier will surface the missing node as
/// an evaluation failure if it matters).
///
/// Output ordering is deterministic: nodes sorted by digest, assertions in insertion order.
pub fn extract_witness(state: &DeferredState, schema: &dyn Schema) -> DeferredWitness {
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
        if let Some(node) = state.get(&digest) {
            for child in schema.children(node) {
                worklist.push(child);
            }
        }
    }

    let nodes: Vec<_> =
        visited.into_iter().filter_map(|d| state.get(&d).map(|n| (d, *n))).collect();
    DeferredWitness::new(nodes, state.assertions().to_vec())
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, deferred::{Payload, Tag}};

    use super::*;
    use crate::deferred::{
        events::{assert_eq, binary_op_payload, register_node},
        handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler},
    };

    fn field0_leaf(low: u64) -> (Tag, Payload) {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        (FIELD0_LEAF, Payload::new(limbs))
    }

    #[test]
    fn empty_state_yields_empty_witness() {
        let state = DeferredState::new();
        let schema = Field0Handler;
        let w = extract_witness(&state, &schema);
        assert!(w.nodes.is_empty());
        assert!(w.assertions.is_empty());
    }

    #[test]
    fn unreachable_nodes_are_excluded() {
        // Register two leaves; only assert one of them is equal to itself. The orphan stays in
        // the state but must not appear in the witness.
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(1);
        let (orphan_tag, orphan_payload) = field0_leaf(99);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let _orphan = register_node(&mut state, &mut schema, orphan_tag, orphan_payload).unwrap();
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, a, a).unwrap();

        let w = extract_witness(&state, &schema);
        assert_eq!(w.nodes.len(), 1);
        assert_eq!(w.nodes[0].0, a);
        assert_eq!(w.assertions.len(), 1);
    }

    #[test]
    fn reachable_subgraph_includes_op_nodes_and_their_children() {
        // (a + b) * c == precomputed_35
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (c_tag, c_payload) = field0_leaf(5);
        let (expected_tag, expected_payload) = field0_leaf(35);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        let c = register_node(&mut state, &mut schema, c_tag, c_payload).unwrap();
        let expected =
            register_node(&mut state, &mut schema, expected_tag, expected_payload).unwrap();
        let add =
            register_node(&mut state, &mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
        let mul =
            register_node(&mut state, &mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, mul, expected).unwrap();

        let w = extract_witness(&state, &schema);
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
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(11);
        let (b_tag, b_payload) = field0_leaf(22);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        // Assert each leaf equal to itself so both digests show up in the witness.
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, a, a).unwrap();
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, b, b).unwrap();

        let w = extract_witness(&state, &schema);
        // Two adjacent extracts must produce identical, sorted ordering.
        let w2 = extract_witness(&state, &schema);
        assert_eq!(w.nodes, w2.nodes);
        assert!(w.nodes.windows(2).all(|p| p[0].0 < p[1].0));
    }

    #[test]
    fn assertions_preserve_insertion_order() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(1);
        let (b_tag, b_payload) = field0_leaf(2);
        let a = register_node(&mut state, &mut schema, a_tag, a_payload).unwrap();
        let b = register_node(&mut state, &mut schema, b_tag, b_payload).unwrap();
        // Self-equal each so both succeed.
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, a, a).unwrap();
        assert_eq(&mut state, &mut schema, FIELD0_ASSERT_EQ, b, b).unwrap();

        let w = extract_witness(&state, &schema);
        assert_eq!(w.assertions.len(), 2);
        assert_eq!(w.assertions[0].lhs, a);
        assert_eq!(w.assertions[1].lhs, b);
    }
}
