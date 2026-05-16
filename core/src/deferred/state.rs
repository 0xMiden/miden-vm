use alloc::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{BodyShape, ChildResolver, Digest, Node, NodePayload, Schema, SchemaError};
use crate::serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// In-memory deferred-DAG state — the verifier's witness.
///
/// State fields:
/// - `nodes`: expression and chunk nodes content-addressed by their Poseidon2 digest. Re-inserting
///   an identical node is a no-op (digests are collision-resistant, so same-key inserts are
///   same-value inserts in practice).
/// - `root`: the transcript root pointer. Initial value [`super::TRUE_DIGEST`]; advanced by
///   `log_precompile`, which interns an AND-node `{tag: TRUE_TAG, payload: prev_root || stmnt}`
///   and updates the root pointer. Reducing root to TRUE is the verifier's single check.
///
/// Ships as-is in `ExecutionProof`; the verifier consumes `(nodes, root)` directly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
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

    /// Inserts `node` into the DAG keyed by its Poseidon2 digest. Idempotent on identical
    /// `(digest, node)` pairs. The depth-first driver in [`Self::evaluate`] uses this to
    /// persist canonical intermediates reached during evaluation, so the eventual witness
    /// contains the full reduction proof.
    pub fn intern(&mut self, node: Node) {
        let digest = node.digest();
        self.nodes.insert(digest, node);
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    /// Returns the current transcript root pointer. Initial value is [`super::TRUE_DIGEST`].
    /// Advanced by `log_precompile` via [`Self::set_root`] in concert with AND-node interning.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Sets the transcript root. Only `log_precompile`-style entry points should call this; the
    /// host-hint register/evaluate paths must not touch the root.
    pub fn set_root(&mut self, root: Digest) {
        self.root = root;
    }

    /// Register an opaque node, asking `schema` to decode its tag.
    ///
    /// The node's payload variant must match `decode(tag).body`, otherwise
    /// [`SchemaError::InvalidNode`] is surfaced. The node is interned into the DAG by its
    /// Poseidon2 digest. Re-registering an identical `(digest, node)` pair is silently
    /// idempotent.
    ///
    /// Predicates (tags whose `evaluates_to == TRUE_TAG`) are *not* verified at registration —
    /// register is a pure host hint that only populates the DAG. Verification is explicit:
    /// either host-side via [`Self::evaluate`], or constrained via `log_precompile`.
    pub fn register(&mut self, schema: &dyn Schema, node: Node) -> Result<Digest, SchemaError> {
        let info = schema.decode(node.tag)?;
        if !payload_matches_body(info.body, &node.payload) {
            return Err(SchemaError::InvalidNode);
        }
        let digest = node.digest();
        self.nodes.insert(digest, node);
        Ok(digest)
    }

    /// Evaluate an opaque node via the installed schema.
    ///
    /// Reduces to canonical form per `schema.reduce`. The input node and every canonical
    /// intermediate produced during the walk are interned into `self.nodes`, so callers may
    /// invoke `evaluate` on a fresh op node without pre-registering it.
    ///
    /// For a predicate (`decode(tag).evaluates_to == TRUE_TAG`), success returns
    /// [`super::true_node`] and a mismatch surfaces as [`SchemaError::AssertionFailed`].
    ///
    /// Transitively-referenced child digests must resolve through the DAG — an unknown child
    /// digest surfaces as [`SchemaError::MissingNode`]. The advice-stack contract is enforced
    /// by the processor-side handler: for non-predicates the canonical 12 felts are pushed; for
    /// predicates (whose canonical is the TRUE node), nothing is pushed.
    ///
    /// **Why intern aggressively:** the verifier checks neighbors against each other rather than
    /// re-executing the DAG, so the witness must include the whole reduction proof — the input
    /// op, every op visited during recursive reduction, and every canonical leaf produced — not
    /// just the final answer. Missing any of these would leave a digest in the witness with no
    /// node defining it. The TRUE node is the one exception: it's a structural sentinel that the
    /// verifier accepts directly, so we don't waste DAG space on copies of it.
    pub fn evaluate(&mut self, schema: &dyn Schema, node: Node) -> Result<Node, SchemaError> {
        let info = schema.decode(node.tag)?;
        if !payload_matches_body(info.body, &node.payload) {
            return Err(SchemaError::InvalidNode);
        }
        DfsResolver { state: self, schema }.reduce_and_intern(node)
    }

}

// SERIALIZATION
// ================================================================================================
// The serialized layout iterates `nodes` in `BTreeMap` digest order, then writes the rolling
// root. Deserialization reconstructs the map by inserting in the same order; idempotent on
// content-addressed inserts.

impl Serializable for DeferredState {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.nodes.len());
        for (digest, node) in self.nodes.iter() {
            digest.write_into(target);
            node.write_into(target);
        }
        self.root.write_into(target);
    }
}

impl Deserializable for DeferredState {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let digest = Digest::read_from(source)?;
            let node = Node::read_from(source)?;
            nodes.insert(digest, node);
        }
        let root = Digest::read_from(source)?;
        Ok(Self { nodes, root })
    }
}

/// Returns `true` when the variant of `payload` agrees with the body shape the schema decoded
/// for the node's tag. Construction-time invariant — handlers always build the matching variant,
/// but a hand-constructed `Node` may disagree.
fn payload_matches_body(body: BodyShape, payload: &NodePayload) -> bool {
    match (body, payload) {
        (BodyShape::Expression, NodePayload::Expression(_)) => true,
        (BodyShape::Chunk(n), NodePayload::Chunk(chunks)) => chunks.len() == n as usize,
        _ => false,
    }
}

// REDUCTION DRIVER
// ================================================================================================

/// Bound the [`DeferredState`] and [`Schema`] together so [`ChildResolver::resolve`] can recurse
/// through [`Schema::reduce`] without aliasing borrow problems: the schema is held by shared
/// reference, the state by exclusive reference. Each `resolve` call looks the child up,
/// recursively reduces it, and interns every node it visits (except the TRUE sentinel).
struct DfsResolver<'a> {
    state: &'a mut DeferredState,
    schema: &'a dyn Schema,
}

impl DfsResolver<'_> {
    /// Reduce `node` to canonical form, interning every node visited along the way — the input
    /// and the canonical result — except the TRUE sentinel (which is a structural marker, not a
    /// load-bearing DAG node).
    ///
    /// `node` is passed to `schema.reduce` by reference so we can intern it by-move afterwards,
    /// avoiding a chunk-sized clone on every reduction.
    fn reduce_and_intern(&mut self, node: Node) -> Result<Node, SchemaError> {
        let schema = self.schema;
        let canonical = schema.reduce(&node, self)?;
        self.state.intern(node);
        if !canonical.is_true_node() {
            self.state.intern(canonical.clone());
        }
        Ok(canonical)
    }
}

impl ChildResolver for DfsResolver<'_> {
    fn resolve(&mut self, digest: Digest) -> Result<Node, SchemaError> {
        let child = self.state.get(&digest)?.clone();
        self.reduce_and_intern(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Field0Handler, Payload, TRUE_DIGEST, Tag},
    };

    fn field0_leaf_node(low: u64) -> Node {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        Node::expression(Field0Handler::LEAF, Payload::new(limbs))
    }

    fn dummy_digest(seed: u64) -> Word {
        Word::new(core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64)))
    }

    #[test]
    fn empty_state_has_no_nodes_and_root_is_true() {
        let state = DeferredState::new();
        assert!(state.nodes().is_empty());
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn set_root_persists() {
        let mut state = DeferredState::new();
        let d = dummy_digest(1);
        state.set_root(d);
        assert_eq!(state.root(), d);
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
        let schema = Field0Handler;
        let node = field0_leaf_node(7);
        let digest = state.register(&schema, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let node = field0_leaf_node(7);
        let d1 = state.register(&schema, node.clone()).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        // Field0 prefix + unknown op-suffix: schema decode returns Err.
        let bad_tag: Tag =
            [Field0Handler::LEAF[0], Field0Handler::LEAF[1], Felt::from_u32(99), ZERO];
        let bad = Node::expression(bad_tag, Payload::new([Felt::from_u32(0); 8]));
        let err = state.register(&schema, bad);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let op = Node::expression(Field0Handler::ADD, Payload::binary_op(a, b));
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // Under the unified design, `register` is a pure host hint — it interns the predicate
        // node but does NOT drive reduce. Programs that want host-side verification call
        // `evaluate`; programs that want constrained verification call `log_precompile`.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(a, b));
        let bad_digest = state.register(&schema, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(&schema, bad);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_succeeds_returns_true_node() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(7)).unwrap();
        let assertion = Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a));
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node(), "predicate success returns the canonical TRUE node");
    }

    #[test]
    fn evaluate_predicate_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let mismatch = Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(a, b));
        let err = state.evaluate(&schema, mismatch);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let assertion =
            Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(a, dangling));
        let err = state.evaluate(&schema, assertion);
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then verify equal to a pre-computed leaf via evaluate.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let expected = state.register(&schema, field0_leaf_node(35)).unwrap();
        let add = state
            .register(&schema, Node::expression(Field0Handler::ADD, Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(Field0Handler::MUL, Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected));
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn witness_includes_all_registered_nodes() {
        // Build (a + b) * c, assert it equals leaf(35), evaluate to drive the canonical
        // intermediates into the DAG, then snapshot the witness. The TRUE node is interned
        // *during* reduce but the DfsResolver skips it (sentinel, not load-bearing), so it
        // does not appear in the witness.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let expected = state.register(&schema, field0_leaf_node(35)).unwrap();
        let _orphan = state.register(&schema, field0_leaf_node(99)).unwrap();
        let add = state
            .register(&schema, Node::expression(Field0Handler::ADD, Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(Field0Handler::MUL, Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected));
        state.evaluate(&schema, assertion).unwrap();

        // 7 registered + 1 interned intermediate (canonical(add) = leaf(7)) +
        // 1 interned assertion-input (the ASSERT_EQ node, deposited by evaluate's reduce_and_intern).
        assert_eq!(state.nodes().len(), 9);
        let leaf_7_digest = field0_leaf_node(7).digest();
        assert!(
            state.contains(&leaf_7_digest),
            "canonical(add) must appear in the state"
        );
        assert_eq!(state.root(), TRUE_DIGEST, "no log_precompile called, root is still TRUE");
    }

    #[test]
    fn evaluate_interns_canonical_intermediates() {
        // Pre-register the op tree (a+b)*c. Evaluating `mul` should deposit canonical(add)=
        // leaf(7) and canonical(mul)=leaf(35) into state.nodes so the witness covers the
        // whole reduction proof, not just the final answer.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let add = Node::expression(Field0Handler::ADD, Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(Field0Handler::MUL, Payload::binary_op(add_digest, c));
        state.register(&schema, mul.clone()).unwrap();

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, field0_leaf_node(35));

        let leaf_7_digest = field0_leaf_node(7).digest();
        let leaf_35_digest = field0_leaf_node(35).digest();
        assert!(state.contains(&leaf_7_digest), "canonical(add) = leaf(7) must be interned");
        assert!(state.contains(&leaf_35_digest), "canonical(mul) = leaf(35) must be interned");
    }

    #[test]
    fn evaluate_interns_unregistered_input_op() {
        // Build (a+b)*c, but only pre-register the leaves and the inner `add` op. The outer `mul`
        // is constructed on the fly and handed straight to `evaluate` — it must end up interned
        // so the witness can link canonical(mul) back to its op-node parent.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let add = Node::expression(Field0Handler::ADD, Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(Field0Handler::MUL, Payload::binary_op(add_digest, c));

        let mul_digest = mul.digest();
        assert!(!state.contains(&mul_digest), "mul must not be pre-registered for this test");

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, field0_leaf_node(35));

        assert!(state.contains(&mul_digest), "input op node must be interned by evaluate");
        assert!(state.contains(&field0_leaf_node(7).digest()), "canonical(add) interned");
        assert!(state.contains(&field0_leaf_node(35).digest()), "canonical(mul) interned");
    }
}
