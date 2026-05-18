use alloc::{collections::BTreeMap, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodePayload, NodeType, Payload,
    ReduceCtx, Schema, SchemaError, TRUE_DIGEST, TRUE_TAG,
};

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

    /// Serialize this state to its wire form. Walks reachable nodes from `root` in DFS
    /// post-order, assigning each visited node a `u32` index in emission order. `Binary`-shape
    /// entries encode their children as indices into the earlier wire entries (or [`TRUE_INDEX`]
    /// for the [`TRUE_DIGEST`] terminal). `register`-then-never-referenced orphans plus
    /// canonical intermediates that nothing references are trimmed at the wire boundary;
    /// rehydrate's phase-2 reduce re-mints any canonical intermediates as a side effect of
    /// re-evaluating each predicate.
    ///
    /// Reachability is computed *structurally*, without consulting the schema: for any node
    /// with an `Expression` payload, interpret the 8 felts as `(lhs_digest, rhs_digest)`. If
    /// both digests resolve in `self.nodes` (or are [`TRUE_DIGEST`]), the encoder treats the
    /// node as Binary and emits indices; otherwise it falls back to `Value` (raw felts). Real
    /// Binary children are always interned (registers and op-evaluates intern them
    /// transitively), so the heuristic never misses one. False positives — a `Value` leaf whose
    /// 8 payload felts happen to coincide with the digests of two interned nodes — round-trip
    /// safely because the reconstructed payload bytes are byte-identical.
    pub fn to_wire(&self) -> DeferredStateWire {
        let mut by_digest = BTreeMap::<Digest, u32>::new();
        let mut entries = Vec::<super::WireEntry>::new();
        self.dfs_post_order(self.root, &mut by_digest, &mut entries);
        DeferredStateWire { entries, root: self.root }
    }

    /// Internal DFS post-order helper for [`Self::to_wire`]. Recursive; for the DAG shapes
    /// produced by `register`/`evaluate`/`log` this is bounded by the depth of the expression
    /// tree, which is well within Rust's default stack budget.
    fn dfs_post_order(
        &self,
        d: Digest,
        by_digest: &mut BTreeMap<Digest, u32>,
        entries: &mut Vec<super::WireEntry>,
    ) {
        if d == TRUE_DIGEST || by_digest.contains_key(&d) {
            return;
        }
        let Some(node) = self.nodes.get(&d) else {
            // Reachable digest with no interned node — bare statement commitment in the
            // production precompile-transcript model. The wire doesn't carry it; the precompile
            // verifier registry validates it externally.
            return;
        };

        // Determine whether this is a real Binary node (children resolve) or a Value-shaped
        // node. For Chunk bodies, no children to recurse into.
        let mut binary_indices: Option<(Digest, Digest)> = None;
        if let Some(payload) = node.expression_payload() {
            let (lhs, rhs) = payload.binary_op_children();
            let lhs_ok = lhs == TRUE_DIGEST || self.nodes.contains_key(&lhs);
            let rhs_ok = rhs == TRUE_DIGEST || self.nodes.contains_key(&rhs);
            if lhs_ok && rhs_ok {
                // Recurse into children first so they receive lower indices.
                self.dfs_post_order(lhs, by_digest, entries);
                self.dfs_post_order(rhs, by_digest, entries);
                binary_indices = Some((lhs, rhs));
            }
        }

        let idx = entries.len() as u32;
        by_digest.insert(d, idx);

        let body = match (&node.payload, binary_indices) {
            (NodePayload::Chunk(chunks), _) => super::WireBody::Chunks(chunks.clone()),
            (NodePayload::Expression(payload), None) => super::WireBody::Value(*payload),
            (NodePayload::Expression(_), Some((lhs, rhs))) => {
                let lhs_idx = if lhs == TRUE_DIGEST { super::TRUE_INDEX } else { by_digest[&lhs] };
                let rhs_idx = if rhs == TRUE_DIGEST { super::TRUE_INDEX } else { by_digest[&rhs] };
                super::WireBody::Binary { lhs: lhs_idx, rhs: rhs_idx }
            },
        };
        entries.push(super::WireEntry { tag: node.tag, body });
    }

    /// Construct a verified [`DeferredState`] from a wire-format value under the installed
    /// `schema`. Re-runs the prover's schema-validation, content-addressing, and AND-chain walk;
    /// the returned state therefore satisfies the invariants documented at the top of this
    /// module.
    ///
    /// The two phases:
    /// - **Phase 1 (structural):** read each wire entry in order, reconstruct the digest-form
    ///   [`Node`] (translating `Binary` indices to the digests of earlier entries), `schema.decode`
    ///   the tag, and intern. Index bounds and chunk arities are validated; `payload_matches_type`
    ///   confirms the schema-declared [`NodeType`] is compatible with the in-memory shape.
    /// - **Phase 2 (semantic):** walk the AND-chain from `wire.root` down to
    ///   [`super::TRUE_DIGEST`], asserting each step has `tag == TRUE_TAG` and re-evaluating each
    ///   predicate statement via [`Self::evaluate`]. The walk surfaces tampered AND-payloads,
    ///   missing statements, non-predicate statements, and failed equalities.
    pub fn rehydrate(
        wire: &DeferredStateWire,
        schema: &dyn Schema,
    ) -> Result<Self, IntegrityError> {
        let mut state = Self::new();
        // Parallel to `wire.entries`: the recomputed digest at each index. `Binary` entries at
        // position `i` reconstruct their payload by reading earlier `digests[lhs/rhs]` (or
        // `TRUE_DIGEST` when the index is `TRUE_INDEX`).
        let mut digests: Vec<Digest> = Vec::with_capacity(wire.entries.len());

        for (i, entry) in wire.entries.iter().enumerate() {
            let node = match &entry.body {
                super::WireBody::Value(payload) => Node::expression(entry.tag, *payload),
                super::WireBody::Chunks(chunks) => Node::chunk(entry.tag, chunks.clone()),
                super::WireBody::Binary { lhs, rhs } => {
                    let lhs_d = resolve_index(*lhs, i, &digests)?;
                    let rhs_d = resolve_index(*rhs, i, &digests)?;
                    Node::expression(entry.tag, Payload::binary_op(lhs_d, rhs_d))
                },
            };

            // Schema-validate. `decode_node_type` handles AND-nodes (framework-owned `TRUE_TAG`)
            // without invoking the user schema, then defers to `schema.decode` for everything
            // else. `payload_matches_type` enforces the Expression-vs-Chunk distinction (and
            // chunk count for Chunks tags).
            let node_type = decode_node_type(schema, &node)?;
            if !payload_matches_type(node_type, &node.payload) {
                return Err(IntegrityError::ShapeMismatch);
            }

            let d = node.digest();
            digests.push(d);
            state.intern(node);
        }

        // Validate root pointer's existence before walking. `TRUE_DIGEST` is the trivial-empty
        // root and is allowed even when `entries` is empty.
        if wire.root != TRUE_DIGEST && !state.nodes.contains_key(&wire.root) {
            return Err(IntegrityError::MissingRoot);
        }
        state.root = wire.root;

        // Phase 2 — chain walk + per-statement re-evaluation. AND-nodes share TRUE_TAG and a
        // `(prev_root, stmt_digest)` payload; statements must reduce to `true_node` under the
        // schema.
        let mut cur = wire.root;
        while cur != TRUE_DIGEST {
            let and_node = state
                .nodes
                .get(&cur)
                .ok_or(IntegrityError::MissingRoot)?
                .clone();
            if and_node.tag != TRUE_TAG {
                return Err(IntegrityError::NonAndNode);
            }
            let (prev_root, stmt_digest) = and_node
                .expression_payload()
                .ok_or(IntegrityError::BadAndPayload)?
                .binary_op_children();
            let stmt = state
                .nodes
                .get(&stmt_digest)
                .ok_or(IntegrityError::MissingStatement)?
                .clone();
            let canonical = state.evaluate(schema, stmt)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }
            cur = prev_root;
        }

        Ok(state)
    }

    /// Walk the AND-chain from `self.root` down to [`super::TRUE_DIGEST`] and return each
    /// statement digest in execution order (oldest first). Assumes the state's chain integrity
    /// has already been established (e.g. by `rehydrate`); panics on a missing or non-AND node
    /// because that situation can't arise on a value produced by the supported constructors.
    pub fn statements(&self) -> Vec<Digest> {
        let mut out = Vec::new();
        let mut cur = self.root;
        while cur != TRUE_DIGEST {
            let and_node = self
                .nodes
                .get(&cur)
                .expect("statements(): AND-chain references a node not in state");
            debug_assert_eq!(
                and_node.tag, TRUE_TAG,
                "statements(): AND-chain step is not tagged TRUE_TAG"
            );
            let (prev_root, stmt_digest) = and_node
                .expression_payload()
                .expect("statements(): AND-node has non-expression body")
                .binary_op_children();
            out.push(stmt_digest);
            cur = prev_root;
        }
        out.reverse();
        out
    }
}

// SERIALIZATION
// ================================================================================================
// `DeferredState` is intentionally NOT `Serializable` / `Deserializable`. Wire-level transit
// goes through [`DeferredStateWire`]; in-memory construction from bytes goes through
// `DeferredState::rehydrate(&wire, schema)`. This keeps the only path from untrusted bytes to
// an in-memory state through the schema-validated, chain-walked rehydrate constructor.

/// Resolve a wire `Binary` child index against the digest table built so far during phase 1 of
/// rehydrate. [`super::TRUE_INDEX`] maps to [`TRUE_DIGEST`]; any other value must be a valid
/// position strictly less than the current entry (topological invariant).
fn resolve_index(
    idx: u32,
    current: usize,
    digests: &[Digest],
) -> Result<Digest, IntegrityError> {
    if idx == super::TRUE_INDEX {
        return Ok(TRUE_DIGEST);
    }
    let i = idx as usize;
    if i >= current || i >= digests.len() {
        return Err(IntegrityError::BadIndex);
    }
    Ok(digests[i])
}

/// Decode a node's [`NodeType`] for `rehydrate`. Framework-owned `TRUE_TAG` AND-nodes are
/// classified as `Binary` directly (user schemas don't claim that tag); everything else routes
/// through `schema.decode`.
fn decode_node_type(schema: &dyn Schema, node: &Node) -> Result<NodeType, IntegrityError> {
    if node.tag == TRUE_TAG {
        return Ok(NodeType::Binary);
    }
    schema
        .decode(node.tag)
        .map(|info| info.node_type)
        .map_err(|_| IntegrityError::UnknownTag)
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
        deferred::{Payload, TRUE_DIGEST, Tag, test_precompile::TestPrecompile},
    };

    fn test_leaf(low: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = low as u32;
        limbs[1] = (low >> 32) as u32;
        TestPrecompile::leaf_node(limbs)
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
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, a));
        let stmt = state.evaluate(&schema, pred).unwrap();
        // The canonical of an `eq` predicate is `true_node()`. Use the predicate's *digest* —
        // which we recover from the original node — as `stmt_digest`.
        let _ = stmt; // canonical, discarded
        let stmt_digest =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, a)).digest();

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
        let schema = TestPrecompile;
        let node = test_leaf(7);
        let digest = state.register(&schema, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let node = test_leaf(7);
        let d1 = state.register(&schema, node.clone()).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        // TestPrecompile app_id + unknown discriminant: schema decode returns Err.
        let bad_tag: Tag = [TestPrecompile::app_id(), Felt::from_u32(99), ZERO, ZERO];
        let bad = Node::expression(bad_tag, Payload::new([Felt::from_u32(0); 8]));
        let err = state.register(&schema, bad);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let op = Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b));
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // Under the unified design, `register` is a pure host hint — it interns the predicate
        // node but does NOT drive reduce. Programs that want host-side verification call
        // `evaluate`; programs that want constrained verification call `log_precompile`.
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, b));
        let bad_digest = state.register(&schema, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(&schema, bad);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_succeeds_returns_true_node() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let assertion = Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, a));
        let result = state.evaluate(&schema, assertion).unwrap();
        assert!(result.is_true_node(), "predicate success returns the canonical TRUE node");
    }

    #[test]
    fn evaluate_predicate_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let mismatch = Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, b));
        let err = state.evaluate(&schema, mismatch);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn evaluate_predicate_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let assertion =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, dangling));
        let err = state.evaluate(&schema, assertion);
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then verify equal to a pre-computed leaf via evaluate.
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state
            .register(&schema, Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(TestPrecompile::mul_tag(), Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(mul, expected));
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
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let add = state
            .register(&schema, Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(TestPrecompile::mul_tag(), Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(mul, expected));
        state.evaluate(&schema, assertion).unwrap();

        // 7 registered + 1 interned intermediate (canonical(add) = leaf(7)) +
        // 1 interned assertion-input (the ASSERT_EQ node, deposited by evaluate's reduce_and_intern).
        assert_eq!(state.nodes().len(), 9);
        let leaf_7_digest = test_leaf(7).digest();
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
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let add = Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(TestPrecompile::mul_tag(), Payload::binary_op(add_digest, c));
        state.register(&schema, mul.clone()).unwrap();

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, test_leaf(35));

        let leaf_7_digest = test_leaf(7).digest();
        let leaf_35_digest = test_leaf(35).digest();
        assert!(state.contains(&leaf_7_digest), "canonical(add) = leaf(7) must be interned");
        assert!(state.contains(&leaf_35_digest), "canonical(mul) = leaf(35) must be interned");
    }

    #[test]
    fn evaluate_interns_unregistered_input_op() {
        // Build (a+b)*c, but only pre-register the leaves and the inner `add` op. The outer `mul`
        // is constructed on the fly and handed straight to `evaluate` — it must end up interned
        // so the witness can link canonical(mul) back to its op-node parent.
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let add = Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b));
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::expression(TestPrecompile::mul_tag(), Payload::binary_op(add_digest, c));

        let mul_digest = mul.digest();
        assert!(!state.contains(&mul_digest), "mul must not be pre-registered for this test");

        let canonical = state.evaluate(&schema, mul).unwrap();
        assert_eq!(canonical, test_leaf(35));

        assert!(state.contains(&mul_digest), "input op node must be interned by evaluate");
        assert!(state.contains(&test_leaf(7).digest()), "canonical(add) interned");
        assert!(state.contains(&test_leaf(35).digest()), "canonical(mul) interned");
    }

    // REHYDRATE TESTS
    // ============================================================================================

    /// Build a fresh state that evaluates `(a+b)*c == 35` and then `log`s the assertion as a
    /// transcript step. Returns the populated state for round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state
            .register(&schema, Node::expression(TestPrecompile::add_tag(), Payload::binary_op(a, b)))
            .unwrap();
        let mul = state
            .register(&schema, Node::expression(TestPrecompile::mul_tag(), Payload::binary_op(add, c)))
            .unwrap();
        let assertion =
            Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(mul, expected));
        let stmt_digest = assertion.digest();
        state.evaluate(&schema, assertion).unwrap();
        let new_root =
            Node::expression(TRUE_TAG, Payload::binary_op(state.root(), stmt_digest)).digest();
        state.log(stmt_digest, new_root).unwrap();
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &TestPrecompile).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        // After rehydrate phase 2, additional canonical intermediates from the predicate's
        // re-evaluation may be present. So we only assert the root is preserved and the chain
        // walks the same statements.
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::empty();
        let state = DeferredState::rehydrate(&wire, &TestPrecompile).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert!(state.nodes().is_empty());
    }

    #[test]
    fn rehydrate_rejects_missing_root() {
        // Empty entries but a non-TRUE root: phase 1 succeeds (nothing to do), then the root
        // validation catches the dangling pointer.
        let wire =
            DeferredStateWire { entries: alloc::vec::Vec::new(), root: dummy_digest(7) };
        let err = DeferredState::rehydrate(&wire, &TestPrecompile);
        assert!(matches!(err, Err(IntegrityError::MissingRoot)));
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // A Binary entry whose lhs index points past the (empty) digest table: index 0 is not
        // < its own position 0 → BadIndex.
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: TestPrecompile::add_tag(),
                body: crate::deferred::WireBody::Binary { lhs: 0, rhs: 0 },
            }],
            root: TRUE_DIGEST,
        };
        let err = DeferredState::rehydrate(&wire, &TestPrecompile);
        assert!(matches!(err, Err(IntegrityError::BadIndex)));
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        // A tag the schema rejects — its app_id doesn't match TestPrecompile.
        let bogus_tag: Tag =
            [Felt::new_unchecked(0xdead), ZERO, ZERO, ZERO];
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: bogus_tag,
                body: crate::deferred::WireBody::Value(Payload::new([ZERO; 8])),
            }],
            root: TRUE_DIGEST,
        };
        let err = DeferredState::rehydrate(&wire, &TestPrecompile);
        assert!(matches!(err, Err(IntegrityError::UnknownTag)));
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_leaves() {
        // Register an orphan that no one references; build a logged-predicate chain. The wire
        // must contain the chain's reachable closure but NOT the orphan.
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, a));
        let stmt_digest = pred.digest();
        state.evaluate(&schema, pred).unwrap();
        let new_root = Node::expression(
            TRUE_TAG,
            Payload::binary_op(state.root(), stmt_digest),
        )
        .digest();
        state.log(stmt_digest, new_root).unwrap();

        let wire = state.to_wire();
        // Rehydrate and read back the digest set — the wire's bytes don't carry digests, but
        // rehydration recomputes them, so we exercise the round-trip identity here.
        let rehydrated = DeferredState::rehydrate(&wire, &TestPrecompile).unwrap();
        let orphan_digest = test_leaf(99).digest();
        assert!(
            !rehydrated.contains(&orphan_digest),
            "orphan must be trimmed from wire and absent after rehydrate"
        );
        // The chain and its closure must still ship and rehydrate.
        assert!(rehydrated.contains(&new_root), "AND-node must be in rehydrated state");
        assert!(rehydrated.contains(&stmt_digest), "stmt predicate must be in rehydrated state");
        assert!(rehydrated.contains(&a), "stmt's operand must be in rehydrated state");
    }

    #[test]
    fn to_wire_trimmed_round_trips_through_rehydrate() {
        // Trimmed wire must still round-trip via rehydrate (phase 2's evaluate re-mints any
        // canonical intermediates that the trim dropped).
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &TestPrecompile).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        // Build a chain whose statement is `eq(leaf(3), leaf(4))` — disagreeing leaves.
        // Phase 2's evaluate returns AssertionFailed, surfaced as `PredicateFailed`.
        let mut state = DeferredState::new();
        let schema = TestPrecompile;
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // Hand-roll a chain that points to a failing predicate without going through `log`'s
        // schema gate (which evaluate-rejects ahead of time).
        let bad_pred = Node::expression(TestPrecompile::eq_tag(), Payload::binary_op(a, b));
        let bad_digest = bad_pred.digest();
        state.intern(bad_pred);
        let and_node =
            Node::expression(TRUE_TAG, Payload::binary_op(TRUE_DIGEST, bad_digest));
        let and_digest = and_node.digest();
        state.intern(and_node);
        state.root = and_digest;

        let wire = state.to_wire();
        let err = DeferredState::rehydrate(&wire, &TestPrecompile);
        assert!(
            matches!(err, Err(IntegrityError::PredicateFailed(_))),
            "expected PredicateFailed, got {err:?}"
        );
    }
}
