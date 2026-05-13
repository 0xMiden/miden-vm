use alloc::vec::Vec;

use miden_core::deferred::DeferredWitness;

use super::state::DeferredState;

/// Snapshot the deferred state into a [`DeferredWitness`].
///
/// All registered expression nodes (in digest order, thanks to the `BTreeMap`) plus every
/// assertion node (in registration order) plus the final transcript digest. No reachability
/// filtering — if a program registers an orphan expression, it appears in the witness too.
pub fn extract_witness(state: &DeferredState) -> DeferredWitness {
    let nodes: Vec<_> = state.nodes().iter().map(|(d, n)| (*d, *n)).collect();
    DeferredWitness::new(nodes, state.assertions().to_vec(), state.transcript())
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word, deferred::{Payload, Tag}};

    use super::*;
    use crate::deferred::{
        binary_op_payload,
        handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler},
    };

    fn field0_leaf(low: u64) -> (Tag, Payload) {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        (FIELD0_LEAF, Payload::new(limbs))
    }

    /// Pulls the `lhs` digest out of an assertion node's payload (first 4 felts).
    fn assertion_lhs(node: &super::super::Node) -> Word {
        Word::new([node.payload.0[0], node.payload.0[1], node.payload.0[2], node.payload.0[3]])
    }

    #[test]
    fn empty_state_yields_empty_witness() {
        let state = DeferredState::new();
        let w = extract_witness(&state);
        assert!(w.nodes.is_empty());
        assert!(w.assertions.is_empty());
    }

    #[test]
    fn witness_includes_all_registered_nodes() {
        // Build (a + b) * c == precomputed_35 and assert it. Plus an orphan node that nothing
        // references — without reachability filtering it shows up in the witness too.
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(3);
        let (b_tag, b_payload) = field0_leaf(4);
        let (c_tag, c_payload) = field0_leaf(5);
        let (expected_tag, expected_payload) = field0_leaf(35);
        let (orphan_tag, orphan_payload) = field0_leaf(99);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();
        let c = state.register(&mut schema, c_tag, c_payload).unwrap();
        let expected = state.register(&mut schema, expected_tag, expected_payload).unwrap();
        let _orphan = state.register(&mut schema, orphan_tag, orphan_payload).unwrap();
        let add = state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
        let mul = state.register(&mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();
        state
            .register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(mul, expected))
            .unwrap();

        let w = extract_witness(&state);
        assert_eq!(w.nodes.len(), 7, "all 7 registered expression nodes are in the witness");
        assert!(w.nodes.windows(2).all(|p| p[0].0 < p[1].0), "sorted by digest");
        assert_eq!(w.assertions.len(), 1);
    }

    #[test]
    fn assertions_preserve_insertion_order() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let (a_tag, a_payload) = field0_leaf(1);
        let (b_tag, b_payload) = field0_leaf(2);
        let a = state.register(&mut schema, a_tag, a_payload).unwrap();
        let b = state.register(&mut schema, b_tag, b_payload).unwrap();
        state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(a, a)).unwrap();
        state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(b, b)).unwrap();

        let w = extract_witness(&state);
        assert_eq!(w.assertions.len(), 2);
        assert_eq!(assertion_lhs(&w.assertions[0]), a);
        assert_eq!(assertion_lhs(&w.assertions[1]), b);
    }
}
