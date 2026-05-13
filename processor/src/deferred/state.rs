use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Word, ZERO,
    crypto::hash::Poseidon2,
    deferred::{DeferredError, Digest, Node, Payload, Tag, hash_node},
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

    pub fn get(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
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
    /// - `Some(NodeType::Expression)` → inserted into the DAG. Idempotent re-insert; a different
    ///   node at the same digest surfaces as [`DeferredError::ConflictingNode`].
    /// - `Some(NodeType::Assertion)` → appended to the assertion list, folded into the running
    ///   transcript, then `schema.eval` is called for verification. A schema-reported
    ///   `AssertionFailed` propagates as-is; the transcript fold is committed regardless
    ///   (execution dies on mismatch, post-mismatch state is unobservable, deterministic
    ///   transcript is easier to reason about).
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
                if let Some(existing) = self.nodes.get(&digest) {
                    if existing != &node {
                        return Err(SchemaError::Other(DeferredError::ConflictingNode));
                    }
                } else {
                    self.nodes.insert(digest, node);
                }
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

    /// Apply every deferred mutation in `txn` atomically.
    ///
    /// Validates the full batch against the current state first; only commits if the entire
    /// batch is consistent. On error the state is left untouched. VM mutations on `txn` are
    /// ignored here — the host drains those through its own channel.
    pub fn apply(&mut self, txn: &HandlerTransaction) -> Result<(), DeferredError> {
        // Stage inserts to detect intra-batch conflicts and to validate against the existing map
        // before mutating anything.
        let mut staged: BTreeMap<Digest, Node> = BTreeMap::new();
        for mutation in &txn.deferred {
            if let DeferredMutation::InsertNode { digest, node } = mutation {
                if let Some(existing) = self.nodes.get(digest)
                    && existing != node
                {
                    return Err(DeferredError::ConflictingNode);
                }
                if let Some(staged_node) = staged.get(digest)
                    && staged_node != node
                {
                    return Err(DeferredError::ConflictingNode);
                }
                staged.insert(*digest, *node);
            }
        }

        // Commit.
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
        deferred::{DeferredError, Node, Payload, Tag},
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
        assert_eq!(state.get(&d), Some(&n));
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
        // Same node, same digest — second apply must succeed and not duplicate.
        state.apply(&txn).unwrap();
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn conflicting_insert_against_existing_errors() {
        let mut state = DeferredState::new();
        let d = digest(1);
        let n1 = leaf(10);
        let n2 = leaf(20);
        state
            .apply(&HandlerTransaction {
                deferred: vec![DeferredMutation::InsertNode { digest: d, node: n1 }],
                vm: vec![],
            })
            .unwrap();
        let conflict = state.apply(&HandlerTransaction {
            deferred: vec![DeferredMutation::InsertNode { digest: d, node: n2 }],
            vm: vec![],
        });
        assert_eq!(conflict, Err(DeferredError::ConflictingNode));
        assert_eq!(state.get(&d), Some(&n1));
    }

    #[test]
    fn conflicting_insert_within_batch_errors_atomically() {
        let mut state = DeferredState::new();
        let d_ok = digest(1);
        let d_dup = digest(2);
        let n_ok = leaf(10);
        let n_a = leaf(20);
        let n_b = leaf(30);
        let txn = HandlerTransaction {
            deferred: vec![
                DeferredMutation::InsertNode { digest: d_ok, node: n_ok },
                DeferredMutation::InsertNode { digest: d_dup, node: n_a },
                DeferredMutation::InsertNode { digest: d_dup, node: n_b },
            ],
            vm: vec![],
        };
        assert_eq!(state.apply(&txn), Err(DeferredError::ConflictingNode));
        // Atomicity: the successful insert before the conflict must not be committed.
        assert!(state.nodes().is_empty());
        assert!(state.assertions().is_empty());
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
        assert_eq!(state.get(&d), Some(&n));
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
}
