use alloc::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    DeferredError, Digest, Node, NodePayload, NodeType, Payload, ReduceCtx, Schema, SchemaError,
    TRUE_TAG,
};
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

    /// Inserts `node` into the DAG keyed by its Poseidon2 digest. Returns the digest. Idempotent
    /// on identical `(digest, node)` pairs. The depth-first driver in [`Self::evaluate`] uses
    /// this to persist canonical intermediates reached during evaluation, so the eventual witness
    /// contains the full reduction proof.
    ///
    /// `node.digest()` populates the memoisation cache as a side effect, so subsequent reads of
    /// the interned node (and its clones, post-priming) skip Poseidon2.
    ///
    /// Internal: external callers go through the schema-aware [`Self::register`] / [`Self::evaluate`]
    /// / [`Self::log`] entry points, which preserve the type invariants. Raw `intern` bypasses
    /// tag-validation and root-shape checks.
    pub(crate) fn intern(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        self.nodes.insert(digest, node);
        digest
    }

    /// Insert `node` under a caller-supplied `digest`, skipping the Poseidon2 hash. Useful on
    /// the resolve-then-intern path where the digest is already known from the resolver's
    /// lookup. The hint is primed into the node's digest cache so subsequent reads are O(1).
    /// A `debug_assert!` cross-checks the hint against the recomputed digest in debug
    /// builds — release builds trust the caller.
    ///
    /// Internal: only the `DfsResolver` reduction driver invokes this. The hint is trusted in
    /// release builds, so it must not be exposed to external code.
    pub(crate) fn intern_with_digest(&mut self, digest: Digest, node: Node) {
        debug_assert_eq!(
            digest,
            node.compute_digest(),
            "intern_with_digest: hint must match node.digest()"
        );
        node.prime_digest(digest);
        self.nodes.insert(digest, node);
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    /// Returns the current transcript root pointer. Initial value is [`super::TRUE_DIGEST`].
    /// Advanced exclusively by [`Self::log`] — no external API mutates this field directly.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Advance the transcript root by one AND-step.
    ///
    /// Interns `AND(self.root, stmt_digest)` and updates `root` to its digest. The caller passes
    /// `expected_new_root` so the host-side and in-circuit hashers can be cross-checked: if they
    /// disagree the call fails with [`super::DeferredError::InvalidPayload`] and the state is
    /// left untouched (no node interned, root unchanged).
    ///
    /// The caller is responsible for having previously `evaluate`-d the statement (the prover does
    /// this via `DeferredEvaluate`); this method does not re-run reduce. Statement-validity is
    /// re-established on the verifier side by `DeferredState::rehydrate` (introduced in a later
    /// step), which walks the chain and evaluates each statement.
    pub fn log(
        &mut self,
        stmt_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<(), DeferredError> {
        let and_node = Node::expression(TRUE_TAG, Payload::binary_op(self.root, stmt_digest));
        let actual = and_node.digest();
        if actual != expected_new_root {
            return Err(DeferredError::InvalidPayload);
        }
        // Side effect: primes the AND-node's digest cache via `node.digest()`.
        self.nodes.insert(actual, and_node);
        self.root = actual;
        Ok(())
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
        if !payload_matches_type(info.node_type, &node.payload) {
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
        if !payload_matches_type(info.node_type, &node.payload) {
            return Err(SchemaError::InvalidNode);
        }
        // Compute the input digest once at the entry; the resolver threads it through so the
        // post-reduce intern of the input doesn't hash it again.
        let digest = node.digest();
        DfsResolver { state: self, schema }.reduce_and_intern(node, digest)
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

/// Returns `true` when the variant of `payload` agrees with the [`NodeType`] the schema decoded
/// for the node's tag. Construction-time invariant — handlers always build the matching variant,
/// but a hand-constructed `Node` may disagree.
///
/// `Value` and `Binary` both map to `NodePayload::Expression` at the in-memory level — the schema
/// is the source of truth for whether the 8 felts encode raw data or two child digests, and
/// rejects payload-semantic violations inside `reduce`.
fn payload_matches_type(nt: NodeType, payload: &NodePayload) -> bool {
    match (nt, payload) {
        (NodeType::Value | NodeType::Binary, NodePayload::Expression(_)) => true,
        (NodeType::Chunks(n), NodePayload::Chunk(chunks)) => chunks.len() == n as usize,
        _ => false,
    }
}

// REDUCTION DRIVER
// ================================================================================================

/// Bound the [`DeferredState`] and [`Schema`] together so [`ReduceCtx::resolve`] can recurse
/// through [`Schema::reduce`] without aliasing borrow problems: the schema is held by shared
/// reference, the state by exclusive reference. Each `resolve` call looks the child up,
/// recursively reduces it, and interns every node it visits (except the TRUE sentinel); each
/// `intern` call deposits a freshly-minted canonical node directly into the DAG.
struct DfsResolver<'a> {
    state: &'a mut DeferredState,
    schema: &'a dyn Schema,
}

impl DfsResolver<'_> {
    /// Reduce `node` to canonical form, interning every node visited along the way — the input
    /// (under the caller-supplied `input_digest`, no re-hash) and the canonical result — except
    /// the TRUE sentinel (which is a structural marker, not a load-bearing DAG node).
    ///
    /// `node` is passed to `schema.reduce` by reference so we can intern it by-move afterwards,
    /// avoiding a chunk-sized clone on every reduction.
    fn reduce_and_intern(
        &mut self,
        node: Node,
        input_digest: Digest,
    ) -> Result<Node, SchemaError> {
        let schema = self.schema;
        let canonical = schema.reduce(&node, self)?;
        self.state.intern_with_digest(input_digest, node);
        if !canonical.is_true_node() {
            self.state.intern(canonical.clone());
        }
        Ok(canonical)
    }
}

impl ReduceCtx for DfsResolver<'_> {
    fn resolve(&mut self, digest: Digest) -> Result<Node, SchemaError> {
        let child = self.state.get(&digest)?.clone();
        // Pass the known digest through so the post-reduce intern of `child` skips Poseidon2.
        self.reduce_and_intern(child, digest)
    }

    fn intern(&mut self, node: Node) -> Digest {
        self.state.intern(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Payload, TRUE_DIGEST, Tag, Uint256},
    };

    fn uint256_leaf_node(low: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = low as u32;
        limbs[1] = (low >> 32) as u32;
        Uint256::leaf_node(limbs)
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
    fn log_advances_root_with_and_node() {
        // Logging interns AND(prev_root, stmt) and sets root to its digest.
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(7)).unwrap();
        let pred =
            Node::expression(Uint256::eq_tag(), Payload::binary_op(a, a));
        let stmt = state.evaluate(&schema, pred).unwrap();
        // The canonical of an `eq` predicate is `true_node()`. Use the predicate's *digest* —
        // which we recover from the original node — as `stmt_digest`.
        let _ = stmt; // canonical, discarded
        let stmt_digest =
            Node::expression(Uint256::eq_tag(), Payload::binary_op(a, a)).digest();

        let expected = Node::expression(TRUE_TAG, Payload::binary_op(TRUE_DIGEST, stmt_digest))
            .digest();
        state.log(stmt_digest, expected).unwrap();
        assert_eq!(state.root(), expected);
        // The newly-minted AND-node must be in the map keyed by its digest.
        assert!(state.contains(&expected));
    }

    #[test]
    fn log_rejects_wrong_expected_root() {
        // A wrong `expected_new_root` makes `log` fail without mutating the state.
        let mut state = DeferredState::new();
        let stmt_digest = dummy_digest(7);
        let bogus_root = dummy_digest(42);
        let pre_root = state.root();
        let pre_node_count = state.nodes().len();
        let err = state.log(stmt_digest, bogus_root);
        assert!(matches!(err, Err(super::super::DeferredError::InvalidPayload)));
        assert_eq!(state.root(), pre_root, "root must remain unchanged on failure");
        assert_eq!(state.nodes().len(), pre_node_count, "no node interned on failure");
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
        let schema = Uint256;
        let node = uint256_leaf_node(7);
        let digest = state.register(&schema, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        let node = uint256_leaf_node(7);
        let d1 = state.register(&schema, node.clone()).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        // Uint256 app_id + unknown discriminant: schema decode returns Err.
        let bad_tag: Tag = [Uint256::app_id(), Felt::from_u32(99), ZERO, ZERO];
        let bad = Node::expression(bad_tag, Payload::new([Felt::from_u32(0); 8]));
        let err = state.register(&schema, bad);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let op = Node::expression(Uint256::add_tag(), Payload::binary_op(a, b));
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // Under the unified design, `register` is a pure host hint — it interns the predicate
        // node but does NOT drive reduce. Programs that want host-side verification call
        // `evaluate`; programs that want constrained verification call `log_precompile`.
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::expression(Uint256::eq_tag(), Payload::binary_op(a, b));
        let bad_digest = state.register(&schema, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(&schema, bad);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_succeeds_returns_true_node() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(7)).unwrap();
        let assertion = Node::expression(Uint256::eq_tag(), Payload::binary_op(a, a));
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node(), "predicate success returns the canonical TRUE node");
    }

    #[test]
    fn evaluate_predicate_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let mismatch = Node::expression(Uint256::eq_tag(), Payload::binary_op(a, b));
        let err = state.evaluate(&schema, mismatch);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let assertion =
            Node::expression(Uint256::eq_tag(), Payload::binary_op(a, dangling));
        let err = state.evaluate(&schema, assertion);
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then verify equal to a pre-computed leaf via evaluate.
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let c = state.register(&schema, uint256_leaf_node(5)).unwrap();
        let expected = state.register(&schema, uint256_leaf_node(35)).unwrap();
        let add = state
            .register(&schema, Node::expression(Uint256::add_tag(), Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(Uint256::mul_tag(), Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(Uint256::eq_tag(), Payload::binary_op(mul, expected));
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
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let c = state.register(&schema, uint256_leaf_node(5)).unwrap();
        let expected = state.register(&schema, uint256_leaf_node(35)).unwrap();
        let _orphan = state.register(&schema, uint256_leaf_node(99)).unwrap();
        let add = state
            .register(&schema, Node::expression(Uint256::add_tag(), Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(Uint256::mul_tag(), Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(Uint256::eq_tag(), Payload::binary_op(mul, expected));
        state.evaluate(&schema, assertion).unwrap();

        // 7 registered + 1 interned intermediate (canonical(add) = leaf(7)) +
        // 1 interned assertion-input (the ASSERT_EQ node, deposited by evaluate's reduce_and_intern).
        assert_eq!(state.nodes().len(), 9);
        let leaf_7_digest = uint256_leaf_node(7).digest();
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
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let c = state.register(&schema, uint256_leaf_node(5)).unwrap();
        let add = Node::expression(Uint256::add_tag(), Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(Uint256::mul_tag(), Payload::binary_op(add_digest, c));
        state.register(&schema, mul.clone()).unwrap();

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, uint256_leaf_node(35));

        let leaf_7_digest = uint256_leaf_node(7).digest();
        let leaf_35_digest = uint256_leaf_node(35).digest();
        assert!(state.contains(&leaf_7_digest), "canonical(add) = leaf(7) must be interned");
        assert!(state.contains(&leaf_35_digest), "canonical(mul) = leaf(35) must be interned");
    }

    #[test]
    fn evaluate_interns_unregistered_input_op() {
        // Build (a+b)*c, but only pre-register the leaves and the inner `add` op. The outer `mul`
        // is constructed on the fly and handed straight to `evaluate` — it must end up interned
        // so the witness can link canonical(mul) back to its op-node parent.
        let mut state = DeferredState::new();
        let schema = Uint256;
        let a = state.register(&schema, uint256_leaf_node(3)).unwrap();
        let b = state.register(&schema, uint256_leaf_node(4)).unwrap();
        let c = state.register(&schema, uint256_leaf_node(5)).unwrap();
        let add = Node::expression(Uint256::add_tag(), Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(Uint256::mul_tag(), Payload::binary_op(add_digest, c));

        let mul_digest = mul.digest();
        assert!(!state.contains(&mul_digest), "mul must not be pre-registered for this test");

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, uint256_leaf_node(35));

        assert!(state.contains(&mul_digest), "input op node must be interned by evaluate");
        assert!(state.contains(&uint256_leaf_node(7).digest()), "canonical(add) interned");
        assert!(state.contains(&uint256_leaf_node(35).digest()), "canonical(mul) interned");
    }
}
