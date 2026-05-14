use alloc::{collections::BTreeMap, vec::Vec};

use super::{ChildResolver, DeferredWitness, Digest, Node, NodeType, Schema, SchemaError};
use crate::crypto::hash::Poseidon2;

/// In-memory deferred-DAG state owned by the host.
///
/// Three pieces of state:
/// - `nodes`: expression nodes content-addressed by their Poseidon2 digest. Re-inserting an
///   identical node is a no-op; inserting a different node at the same digest surfaces as
///   [`super::DeferredError::ConflictingNode`].
/// - `assertions`: assertion nodes in registration order. The schema classifies a node as an
///   assertion via `is_valid` returning `Some(NodeType::Assertion)`.
/// - `transcript`: a single rolling Poseidon2 digest folded over each assertion's digest, in order.
///   Mirrors [`crate::precompile::PrecompileTranscript`]. The verifier re-folds it from the witness
///   assertions to bind their content and order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    assertions: Vec<Node>,
    transcript: Digest,
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

    pub fn assertions(&self) -> &[Node] {
        &self.assertions
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    /// Returns the running transcript digest folded over every assertion appended so far. Its
    /// initial value is `[ZERO; 4]`; each assertion folds in `node.digest()` via
    /// `Poseidon2::merge`.
    pub fn transcript(&self) -> Digest {
        self.transcript
    }

    /// Register an opaque node, asking `schema` to classify and (for assertions) verify it.
    ///
    /// - `is_valid(node) == None` → [`SchemaError::InvalidNode`].
    /// - `Some(NodeType::Expression)` → inserts the node into the DAG and returns its digest.
    ///   Re-registering the same digest is silently idempotent.
    /// - `Some(NodeType::Assertion)` → appends the node to the assertion list, folds it into the
    ///   running transcript, then drives a depth-first reduction (see [`Self::evaluate`]) to verify
    ///   the assertion. A schema-reported `AssertionFailed` propagates as-is; the transcript fold
    ///   is committed regardless.
    pub fn register(&mut self, schema: &dyn Schema, node: Node) -> Result<Digest, SchemaError> {
        let digest = node.digest();
        match schema.is_valid(&node) {
            None => Err(SchemaError::InvalidNode),
            Some(NodeType::Expression) => {
                self.nodes.insert(digest, node);
                Ok(digest)
            },
            Some(NodeType::Assertion) => {
                self.transcript = Poseidon2::merge(&[self.transcript, digest]);
                self.assertions.push(node);
                DfsResolver { state: self, schema }.reduce_and_intern(node)?;
                Ok(digest)
            },
        }
    }

    /// Evaluate an opaque node via the installed schema.
    ///
    /// Accepts either classification:
    /// - `Expression` → reduces to canonical form. The input node and every canonical intermediate
    ///   produced during the walk are interned into `self.nodes`, so callers may invoke `evaluate`
    ///   on a fresh op node without pre-registering it.
    /// - `Assertion`  → verifies the assertion and returns the input node back; a mismatch surfaces
    ///   as [`SchemaError::AssertionFailed`]. Assertions are *not* interned; they live in
    ///   `self.assertions` when registered, and `evaluate` on an assertion is a pure verify.
    ///
    /// Transitively-referenced child digests must resolve through the DAG — an unknown child
    /// digest surfaces as [`SchemaError::MissingNode`]. The advice-stack contract is enforced by
    /// the processor-side handler: for expressions, MASM gets the 12 canonical felts back; for
    /// assertions, nothing is pushed.
    ///
    /// **Why intern aggressively:** the verifier checks neighbors against each other rather than
    /// re-executing the DAG, so the witness must include the whole reduction proof — the input op,
    /// every op visited during recursive reduction, and every canonical leaf produced — not just
    /// the final answer. Missing any of these would leave a digest in the witness with no node
    /// defining it.
    pub fn evaluate(&mut self, schema: &dyn Schema, node: Node) -> Result<Node, SchemaError> {
        if schema.is_valid(&node).is_none() {
            return Err(SchemaError::InvalidNode);
        }
        DfsResolver { state: self, schema }.reduce_and_intern(node)
    }

    /// Snapshot the current state into a [`DeferredWitness`].
    ///
    /// All registered expression nodes (in digest order, thanks to the `BTreeMap`) plus every
    /// assertion node (in registration order) plus the final transcript digest. No reachability
    /// filtering — if a program registers an orphan expression, it appears in the witness too.
    pub fn extract_witness(&self) -> DeferredWitness {
        let nodes: Vec<_> = self.nodes.iter().map(|(d, n)| (*d, *n)).collect();
        DeferredWitness::new(nodes, self.assertions.clone(), self.transcript)
    }
}

// REDUCTION DRIVER
// ================================================================================================

/// Bound the [`DeferredState`] and [`Schema`] together so [`ChildResolver::resolve`] can recurse
/// through [`Schema::reduce`] without aliasing borrow problems: the schema is held by shared
/// reference (Copy), the state by exclusive reference. Each `resolve` call looks the child up,
/// recursively reduces it, and interns every expression node it visits.
struct DfsResolver<'a> {
    state: &'a mut DeferredState,
    schema: &'a dyn Schema,
}

impl DfsResolver<'_> {
    /// Reduce `node` to canonical form, interning every expression node visited along the way
    /// — the input, any expression intermediates the schema's `reduce` walks through, and the
    /// canonical result if it differs from the input. Assertion nodes are not interned (they
    /// live in `state.assertions` when registered, or are pure verify-only when evaluated).
    fn reduce_and_intern(&mut self, node: Node) -> Result<Node, SchemaError> {
        let schema = self.schema;
        if matches!(schema.is_valid(&node), Some(NodeType::Expression)) {
            self.state.intern(node);
        }
        let canonical = schema.reduce(node, self)?;
        if canonical != node && matches!(schema.is_valid(&canonical), Some(NodeType::Expression)) {
            self.state.intern(canonical);
        }
        Ok(canonical)
    }
}

impl ChildResolver for DfsResolver<'_> {
    fn resolve(&mut self, digest: Digest) -> Result<Node, SchemaError> {
        let child = *self.state.get(&digest)?;
        self.reduce_and_intern(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Field0Handler, Payload, Tag},
    };

    fn field0_leaf_node(low: u64) -> Node {
        let mut limbs = [Felt::from_u32(0); 8];
        limbs[0] = Felt::from_u32(low as u32);
        limbs[1] = Felt::from_u32((low >> 32) as u32);
        Node::new(Field0Handler::LEAF, Payload::new(limbs))
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
        let schema = Field0Handler;
        let node = field0_leaf_node(7);
        let digest = state.register(&schema, node).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let node = field0_leaf_node(7);
        let d1 = state.register(&schema, node).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        // Field0 prefix + unknown op-suffix: schema returns None.
        let bad_tag: Tag =
            [Field0Handler::LEAF[0], Field0Handler::LEAF[1], Felt::from_u32(99), ZERO];
        let bad = Node::new(bad_tag, Payload::new([Felt::from_u32(0); 8]));
        let err = state.register(&schema, bad);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let op = Node::new(Field0Handler::ADD, Payload::binary_op(a, b));
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn assertion_register_appends_node() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(1)).unwrap();
        // Self-equal assertion (A == A) — passes eval.
        let assertion = Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a));
        state.register(&schema, assertion).unwrap();
        assert_eq!(state.assertions().len(), 1);
        assert_eq!(assertion_lhs(&state.assertions()[0]), a);
    }

    #[test]
    fn assertions_preserve_insertion_order() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(1)).unwrap();
        let b = state.register(&schema, field0_leaf_node(2)).unwrap();
        state
            .register(&schema, Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a)))
            .unwrap();
        state
            .register(&schema, Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(b, b)))
            .unwrap();

        assert_eq!(state.assertions().len(), 2);
        assert_eq!(assertion_lhs(&state.assertions()[0]), a);
        assert_eq!(assertion_lhs(&state.assertions()[1]), b);
    }

    #[test]
    fn transcript_folds_each_assertion_digest_in_order() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        assert_eq!(state.transcript(), Word::new([ZERO; 4]));

        let a = state.register(&schema, field0_leaf_node(1)).unwrap();
        let b = state.register(&schema, field0_leaf_node(2)).unwrap();

        // First assertion: A == A.
        let n1 = Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a));
        state.register(&schema, n1).unwrap();
        let expected1 = Poseidon2::merge(&[Word::new([ZERO; 4]), n1.digest()]);
        assert_eq!(state.transcript(), expected1);

        // Second assertion: B == B.
        let n2 = Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(b, b));
        state.register(&schema, n2).unwrap();
        let expected2 = Poseidon2::merge(&[expected1, n2.digest()]);
        assert_eq!(state.transcript(), expected2);
    }

    #[test]
    fn assert_eq_fails_on_mismatch() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let wrong = state.register(&schema, field0_leaf_node(99)).unwrap();
        let add = state
            .register(&schema, Node::new(Field0Handler::ADD, Payload::binary_op(a, b)))
            .unwrap();

        let err = state
            .register(&schema, Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(add, wrong)));
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
        // The assertion is still recorded (transcript folds eagerly; the mismatch is the only
        // observable consequence at this cycle).
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn assert_eq_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);

        let err = state.register(
            &schema,
            Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, dangling)),
        );
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then assert equal to a leaf holding (a + b) * c precomputed.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let expected = state.register(&schema, field0_leaf_node(35)).unwrap();
        let add = state
            .register(&schema, Node::new(Field0Handler::ADD, Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::new(Field0Handler::MUL, Payload::binary_op(add, c)))
            .unwrap();

        state
            .register(
                &schema,
                Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected)),
            )
            .unwrap();
        assert_eq!(state.assertions().len(), 1);
    }

    #[test]
    fn evaluate_assertion_verifies_and_returns_the_node() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(7)).unwrap();
        // Self-equal assertion: passes eval. State should be unchanged by `evaluate`.
        let assertion = Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, a));
        let before_nodes = state.nodes().len();
        let before_assertions = state.assertions().len();
        let result = state.evaluate(&schema, assertion).unwrap();
        assert_eq!(result, assertion, "evaluate returns the assertion node itself");
        assert_eq!(state.nodes().len(), before_nodes, "state.nodes unchanged");
        assert_eq!(state.assertions().len(), before_assertions, "no transcript fold");
    }

    #[test]
    fn evaluate_assertion_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let mismatch = Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(a, b));
        let err = state.evaluate(&schema, mismatch);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn witness_includes_all_registered_nodes() {
        // Build (a + b) * c == precomputed_35 and assert it. Plus an orphan node that
        // nothing references — without reachability filtering it shows up in the witness.
        // The assertion's eval interns one intermediate (canonical(add) = leaf(7)). The other
        // intermediate (canonical(mul) = leaf(35)) collides with the pre-registered `expected`,
        // so net new nodes = 1.
        let mut state = DeferredState::new();
        let schema = Field0Handler;
        let a = state.register(&schema, field0_leaf_node(3)).unwrap();
        let b = state.register(&schema, field0_leaf_node(4)).unwrap();
        let c = state.register(&schema, field0_leaf_node(5)).unwrap();
        let expected = state.register(&schema, field0_leaf_node(35)).unwrap();
        let _orphan = state.register(&schema, field0_leaf_node(99)).unwrap();
        let add = state
            .register(&schema, Node::new(Field0Handler::ADD, Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::new(Field0Handler::MUL, Payload::binary_op(add, c)))
            .unwrap();
        state
            .register(
                &schema,
                Node::new(Field0Handler::ASSERT_EQ, Payload::binary_op(mul, expected)),
            )
            .unwrap();

        let w = state.extract_witness();
        assert_eq!(w.nodes.len(), 8, "7 registered expression nodes + 1 interned intermediate");
        let leaf_7_digest = field0_leaf_node(7).digest();
        assert!(
            w.nodes.iter().any(|(d, _)| *d == leaf_7_digest),
            "canonical(add) must appear in the witness"
        );
        assert!(w.nodes.windows(2).all(|p| p[0].0 < p[1].0), "sorted by digest");
        assert_eq!(w.assertions.len(), 1);
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
        let add = Node::new(Field0Handler::ADD, Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::new(Field0Handler::MUL, Payload::binary_op(add_digest, c));
        state.register(&schema, mul).unwrap();

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
        let add = Node::new(Field0Handler::ADD, Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::new(Field0Handler::MUL, Payload::binary_op(add_digest, c));

        let mul_digest = mul.digest();
        assert!(!state.contains(&mul_digest), "mul must not be pre-registered for this test");

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, field0_leaf_node(35));

        assert!(state.contains(&mul_digest), "input op node must be interned by evaluate");
        assert!(state.contains(&field0_leaf_node(7).digest()), "canonical(add) interned");
        assert!(state.contains(&field0_leaf_node(35).digest()), "canonical(mul) interned");
    }
}
