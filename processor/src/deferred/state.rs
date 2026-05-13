use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Word, ZERO,
    crypto::hash::Poseidon2,
    deferred::{DeferredWitness, Digest, Node, Payload, Tag, hash_node},
};

use super::schema::{NodeType, Schema, SchemaError};

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
    /// - `Some(NodeType::Expression)` → inserts the node into the DAG and returns its digest.
    ///   Re-registering the same digest is silently idempotent.
    /// - `Some(NodeType::Assertion)` → appends the node to the assertion list, folds it into
    ///   the running transcript, then calls `schema.eval` for verification. A schema-reported
    ///   `AssertionFailed` propagates as-is; the transcript fold is committed regardless.
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

    /// Evaluate an opaque `(tag, payload)` node to its canonical form via the installed schema.
    ///
    /// The node must classify as `Expression` (assertions aren't values — they're checks).
    /// Children referenced in the payload must already be registered in the DAG. State is not
    /// mutated; the returned `Node` is what the caller pushes onto the advice stack via the
    /// `deferred_evaluate` opcode.
    pub fn evaluate(
        &mut self,
        schema: &mut dyn Schema,
        tag: Tag,
        payload: Payload,
    ) -> Result<Node, SchemaError> {
        let node = Node::new(tag, payload);
        match schema.is_valid(&node) {
            Some(NodeType::Expression) => schema.eval(self, node),
            // Assertions aren't evaluatable values; an `is_valid` rejection rejects here too.
            _ => Err(SchemaError::InvalidNode),
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
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word, ZERO, deferred::{Payload, Tag}};

    use super::*;
    use crate::deferred::{
        binary_op_payload,
        handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler},
    };

    fn field0_leaf_payload(low: u64) -> Payload {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        Payload::new(limbs)
    }

    fn assertion_lhs(node: &Node) -> Word {
        Word::new([node.payload.0[0], node.payload.0[1], node.payload.0[2], node.payload.0[3]])
    }

    fn dummy_digest(seed: u64) -> Word {
        Word::new(core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64)))
    }

    #[test]
    fn empty_state_has_no_nodes_or_assertions() {
        let state = DeferredState::new();
        assert!(state.nodes().is_empty());
        assert!(state.assertions().is_empty());
        assert_eq!(state.transcript(), Word::new([ZERO; 4]));
    }

    #[test]
    fn missing_node_get_returns_error() {
        let state = DeferredState::new();
        let err = state.get(&dummy_digest(1)).unwrap_err();
        assert!(matches!(err, SchemaError::MissingNode));
    }

    #[test]
    fn register_leaf_stores_it() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let payload = field0_leaf_payload(7);
        let digest = state.register(&mut schema, FIELD0_LEAF, payload).unwrap();
        assert_eq!(state.get(&digest).unwrap(), &Node::new(FIELD0_LEAF, payload));
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let payload = field0_leaf_payload(7);
        let d1 = state.register(&mut schema, FIELD0_LEAF, payload).unwrap();
        let d2 = state.register(&mut schema, FIELD0_LEAF, payload).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        // Field0 prefix + unknown op-suffix: schema returns None.
        let bad_tag: Tag =
            [FIELD0_LEAF[0], FIELD0_LEAF[1], Felt::from_u32(99), ZERO];
        let err = state.register(&mut schema, bad_tag, field0_leaf_payload(0));
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn assertion_register_appends_node() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let a = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(1)).unwrap();
        // Self-equal assertion (A == A) — passes eval.
        state
            .register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(a, a))
            .unwrap();
        assert_eq!(state.assertions().len(), 1);
        assert_eq!(assertion_lhs(&state.assertions()[0]), a);
    }

    #[test]
    fn assertions_preserve_insertion_order() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let a = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(1)).unwrap();
        let b = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(2)).unwrap();
        state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(a, a)).unwrap();
        state.register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(b, b)).unwrap();

        assert_eq!(state.assertions().len(), 2);
        assert_eq!(assertion_lhs(&state.assertions()[0]), a);
        assert_eq!(assertion_lhs(&state.assertions()[1]), b);
    }

    #[test]
    fn transcript_folds_each_assertion_digest_in_order() {
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        assert_eq!(state.transcript(), Word::new([ZERO; 4]));

        let a = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(1)).unwrap();
        let b = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(2)).unwrap();

        // First assertion: A == A.
        let assertion1_payload = binary_op_payload(a, a);
        state.register(&mut schema, FIELD0_ASSERT_EQ, assertion1_payload).unwrap();
        let d1 = hash_node(FIELD0_ASSERT_EQ, &assertion1_payload);
        let expected1 = Poseidon2::merge(&[Word::new([ZERO; 4]), d1]);
        assert_eq!(state.transcript(), expected1);

        // Second assertion: B == B.
        let assertion2_payload = binary_op_payload(b, b);
        state.register(&mut schema, FIELD0_ASSERT_EQ, assertion2_payload).unwrap();
        let d2 = hash_node(FIELD0_ASSERT_EQ, &assertion2_payload);
        let expected2 = Poseidon2::merge(&[expected1, d2]);
        assert_eq!(state.transcript(), expected2);
    }

    #[test]
    fn witness_includes_all_registered_nodes() {
        // Build (a + b) * c == precomputed_35 and assert it. Plus an orphan node that
        // nothing references — without reachability filtering it shows up in the witness.
        let mut state = DeferredState::new();
        let mut schema = Field0Handler;
        let a = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(3)).unwrap();
        let b = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(4)).unwrap();
        let c = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(5)).unwrap();
        let expected = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(35)).unwrap();
        let _orphan = state.register(&mut schema, FIELD0_LEAF, field0_leaf_payload(99)).unwrap();
        let add = state.register(&mut schema, FIELD0_ADD, binary_op_payload(a, b)).unwrap();
        let mul = state.register(&mut schema, FIELD0_MUL, binary_op_payload(add, c)).unwrap();
        state
            .register(&mut schema, FIELD0_ASSERT_EQ, binary_op_payload(mul, expected))
            .unwrap();

        let w = state.extract_witness();
        assert_eq!(w.nodes.len(), 7, "all 7 registered expression nodes are in witness");
        assert!(w.nodes.windows(2).all(|p| p[0].0 < p[1].0), "sorted by digest");
        assert_eq!(w.assertions.len(), 1);
    }
}
