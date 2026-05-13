use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Word, ZERO,
    crypto::hash::Poseidon2,
    deferred::{DeferredError, DeferredWitness, Digest, Node, Payload, Tag, hash_node},
};

use super::{
    schema::{NodeType, Schema, SchemaError},
    transaction::{DeferredMutation, HandlerTransaction},
};

/// In-memory deferred-DAG state owned by the host.
///
/// Three pieces of state:
/// - `nodes`: expression nodes content-addressed by their Poseidon2 digest. Re-inserting an
///   identical node is a no-op; inserting a different node at the same digest surfaces as
///   [`DeferredError::ConflictingNode`].
/// - `assertions`: assertion nodes in registration order. The schema classifies a node as an
///   assertion via `is_valid` returning `Some(NodeType::Assertion)`.
/// - `transcript`: a single rolling Poseidon2 digest folded over each assertion's digest, in
///   order. Mirrors [`miden_core::precompile::PrecompileTranscript`]. The verifier re-folds it
///   from the witness assertions to bind their content and order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    assertions: Vec<Node>,
    transcript: Digest,
}

impl Default for DeferredState {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            assertions: Vec::new(),
            transcript: Word::new([ZERO; 4]),
        }
    }
}

impl DeferredState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the node stored under `digest`, or [`SchemaError::MissingNode`] if no such node
    /// has been registered. Returning a `Result` lets schema implementations propagate the
    /// missing-node case with `?` instead of unwrapping an `Option`.
    pub fn get(&self, digest: &Digest) -> Result<&Node, SchemaError> {
        self.nodes.get(digest).ok_or(SchemaError::MissingNode)
    }

    pub fn contains(&self, digest: &Digest) -> bool {
        self.nodes.contains_key(digest)
    }

    pub fn assertions(&self) -> &[Node] {
        &self.assertions
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    /// Returns the running transcript digest folded over every assertion appended so far. Its
    /// initial value is `[ZERO; 4]`; each `AppendAssertion(node)` mutation folds in
    /// `hash_node(node.tag, &node.payload)` via `Poseidon2::merge`.
    pub fn transcript(&self) -> Digest {
        self.transcript
    }

    /// Register an opaque `(tag, payload)` node, asking `schema` to classify and (for
    /// assertions) verify it.
    ///
    /// - `is_valid(node) == None` → [`SchemaError::InvalidNode`].
    /// - `Some(NodeType::Expression)` → inserted into the DAG. Re-registering the same digest
    ///   is silently idempotent (the node is content-addressed; the second insert is a no-op).
    /// - `Some(NodeType::Assertion)` → appended to the assertion list (duplicates allowed —
    ///   each registration counts as its own check), folded into the running transcript, then
    ///   `schema.eval` is called for verification. A schema-reported `AssertionFailed`
    ///   propagates as-is; the transcript fold is committed regardless.
    pub fn register(
        &mut self,
        schema: &mut dyn Schema,
        tag: Tag,
        payload: Payload,
    ) -> Result<Digest, SchemaError> {
        let node = Node::new(tag, payload);
        let digest = hash_node(tag, &payload);
        match schema.is_valid(&node) {
            None => Err(SchemaError::InvalidNode),
            Some(NodeType::Expression) => {
                self.nodes.insert(digest, node);
                Ok(digest)
            },
            Some(NodeType::Assertion) => {
                self.transcript = Poseidon2::merge(&[self.transcript, digest]);
                self.assertions.push(node);
                schema.eval(self, node)?;
                Ok(digest)
            },
        }
    }

    /// Snapshot the current state into a [`DeferredWitness`].
    ///
    /// All registered expression nodes (in digest order, thanks to the `BTreeMap`) plus every
    /// assertion node (in registration order) plus the final transcript digest. No reachability
    /// filtering — if a program registers an orphan expression, it appears in the witness too.
    pub fn extract_witness(&self) -> DeferredWitness {
        let nodes: alloc::vec::Vec<_> = self.nodes.iter().map(|(d, n)| (*d, *n)).collect();
        DeferredWitness::new(nodes, self.assertions.clone(), self.transcript)
    }

    /// Apply every deferred mutation in `txn` in order.
    ///
    /// Inserts and appends are unconditional — re-registering an expression node overwrites
    /// (idempotent under content-addressing), and assertion duplicates are allowed.
    pub fn apply(&mut self, txn: &HandlerTransaction) -> Result<(), DeferredError> {
        for mutation in &txn.deferred {
            match mutation {
                DeferredMutation::InsertNode { digest, node } => {
                    self.nodes.insert(*digest, *node);
                },
                DeferredMutation::AppendAssertion(node) => {
                    let digest = hash_node(node.tag, &node.payload);
                    self.transcript = Poseidon2::merge(&[self.transcript, digest]);
                    self.assertions.push(*node);
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt, Word, ZERO,
        deferred::{Node, Payload, Tag},
    };

    use super::*;
    use crate::deferred::transaction::{DeferredMutation, HandlerTransaction};

    const TEST_LEAF_TAG: Tag = [Felt::new_unchecked(1), Felt::new_unchecked(0), ZERO, ZERO];
    const TEST_ASSERT_TAG: Tag = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(3),
        ZERO,
    ];

    fn leaf(seed: u64) -> Node {
        let felts = core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64));
        Node::new(TEST_LEAF_TAG, Payload::new(felts))
    }

    fn assertion(seed: u64) -> Node {
        let felts = core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64));
        Node::new(TEST_ASSERT_TAG, Payload::new(felts))
    }

    fn digest(seed: u64) -> Word {
        Word::new(core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64)))
    }

    #[test]
    fn empty_state_has_no_nodes_or_assertions() {
        let state = DeferredState::new();
        assert!(state.nodes().is_empty());
        assert!(state.assertions().is_empty());
    }

    #[test]
    fn insert_node_stores_it() {
        let mut state = DeferredState::new();
        let d = digest(1);
        let n = leaf(10);
        let txn = HandlerTransaction {
            deferred: vec![DeferredMutation::InsertNode { digest: d, node: n }],
            vm: vec![],
        };
        state.apply(&txn).unwrap();
        assert_eq!(state.get(&d).unwrap(), &n);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let d = digest(1);
        let n = leaf(10);
        let txn = HandlerTransaction {
            deferred: vec![DeferredMutation::InsertNode { digest: d, node: n }],
            vm: vec![],
        };
        state.apply(&txn).unwrap();
        // Same node, same digest — second apply is a silent no-op.
        state.apply(&txn).unwrap();
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn missing_node_get_returns_error() {
        let state = DeferredState::new();
        let err = state.get(&digest(1)).unwrap_err();
        assert!(matches!(err, SchemaError::MissingNode));
    }

    #[test]
    fn append_assertion_preserves_order() {
        let mut state = DeferredState::new();
        let a1 = assertion(1);
        let a2 = assertion(100);
        state
            .apply(&HandlerTransaction {
                deferred: vec![
                    DeferredMutation::AppendAssertion(a1),
                    DeferredMutation::AppendAssertion(a2),
                ],
                vm: vec![],
            })
            .unwrap();
        assert_eq!(state.assertions(), &[a1, a2]);
    }

    #[test]
    fn mixed_batch_applies_in_order() {
        let mut state = DeferredState::new();
        let d = digest(1);
        let n = leaf(10);
        let a = assertion(50);
        let txn = HandlerTransaction {
            deferred: vec![
                DeferredMutation::InsertNode { digest: d, node: n },
                DeferredMutation::AppendAssertion(a),
            ],
            vm: vec![],
        };
        state.apply(&txn).unwrap();
        assert_eq!(state.get(&d).unwrap(), &n);
        assert_eq!(state.assertions(), &[a]);
    }

    #[test]
    fn transcript_folds_each_assertion_digest_in_order() {
        let mut state = DeferredState::new();
        assert_eq!(state.transcript(), Word::new([ZERO; 4]));

        let a1 = assertion(1);
        let a2 = assertion(100);

        // Apply one by one and recompute the expected transcript manually.
        state
            .apply(&HandlerTransaction {
                deferred: vec![DeferredMutation::AppendAssertion(a1)],
                vm: vec![],
            })
            .unwrap();
        let d1 = miden_core::deferred::hash_node(a1.tag, &a1.payload);
        let expected1 = Poseidon2::merge(&[Word::new([ZERO; 4]), d1]);
        assert_eq!(state.transcript(), expected1);

        state
            .apply(&HandlerTransaction {
                deferred: vec![DeferredMutation::AppendAssertion(a2)],
                vm: vec![],
            })
            .unwrap();
        let d2 = miden_core::deferred::hash_node(a2.tag, &a2.payload);
        let expected2 = Poseidon2::merge(&[expected1, d2]);
        assert_eq!(state.transcript(), expected2);
    }

    // EXTRACT_WITNESS
    // --------------------------------------------------------------------------------------------

    mod witness_tests {
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

        fn assertion_lhs(node: &Node) -> Word {
            Word::new([node.payload.0[0], node.payload.0[1], node.payload.0[2], node.payload.0[3]])
        }

        #[test]
        fn empty_state_yields_empty_witness() {
            let state = DeferredState::new();
            let w = state.extract_witness();
            assert!(w.nodes.is_empty());
            assert!(w.assertions.is_empty());
        }

        #[test]
        fn witness_includes_all_registered_nodes() {
            // Build (a + b) * c == precomputed_35 and assert it. Plus an orphan node that
            // nothing references — without reachability filtering it shows up in the witness.
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
            let _expected =
                state.register(&mut schema, expected_tag, expected_payload).unwrap();
            let _orphan = state.register(&mut schema, orphan_tag, orphan_payload).unwrap();
            let add =
                state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
            let mul =
                state.register(&mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();
            let _ = mul;
            state
                .register(
                    &mut schema,
                    FIELD0_ASSERT_EQ,
                    binary_op_payload(mul, _expected),
                )
                .unwrap();

            let w = state.extract_witness();
            assert_eq!(w.nodes.len(), 7, "all 7 registered expression nodes are in witness");
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

            let w = state.extract_witness();
            assert_eq!(w.assertions.len(), 2);
            assert_eq!(assertion_lhs(&w.assertions[0]), a);
            assert_eq!(assertion_lhs(&w.assertions[1]), b);
        }
    }
}
