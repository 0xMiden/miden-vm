use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::deferred::{Assertion, DeferredError, Digest, Node};

use super::transaction::{DeferredMutation, HandlerTransaction};

/// In-memory deferred-DAG state owned by the host.
///
/// Nodes are content-addressed by their Poseidon2 digest. The same digest may be re-inserted with
/// an identical node (no-op); inserting a different node at the same digest is treated as a hash
/// collision and surfaces as [`DeferredError::ConflictingNode`].
///
/// Assertions are kept in insertion order. The processor never executes the equality check —
/// that is the verifier's job — it only records the digests that the program claims to be equal.
#[derive(Debug, Clone, Default)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    assertions: Vec<Assertion>,
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

    pub fn assertions(&self) -> &[Assertion] {
        &self.assertions
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
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
                DeferredMutation::AppendAssertion(assertion) => {
                    self.assertions.push(*assertion);
                },
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt, Word,
        deferred::{Assertion, DeferredError, DeferredTag, Node, Payload},
    };

    use super::*;
    use crate::deferred::transaction::{DeferredMutation, HandlerTransaction};

    fn leaf(seed: u64) -> Node {
        let felts = core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64));
        Node::new(DeferredTag::Field0Leaf, Payload::new(felts))
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
        let a1 = Assertion::new(DeferredTag::Field0AssertEq, digest(1), digest(2));
        let a2 = Assertion::new(DeferredTag::Field0AssertEq, digest(3), digest(4));
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
        let a = Assertion::new(DeferredTag::Field0AssertEq, digest(2), digest(3));
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
}
