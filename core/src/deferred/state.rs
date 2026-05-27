use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodeType, Payload,
    PrecompileError, PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory witness for deferred-DAG verification.
///
/// The state keeps committed nodes, host-side reduction memos, and the current transcript root.
/// It is intentionally not serialized directly: proofs carry [`DeferredStateWire`], and
/// [`Self::rehydrate`] rebuilds this state only after schema checks, reachability checks, and
/// transcript re-evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    evals: BTreeMap<Digest, Node>,
}

impl Default for DeferredState {
    fn default() -> Self {
        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, Node::TRUE);
        Self {
            nodes: BTreeMap::new(),
            root: TRUE_DIGEST,
            evals,
        }
    }
}

impl DeferredState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a committed node, or [`PrecompileError::MissingNode`] for an unknown digest.
    pub fn get(&self, digest: &Digest) -> Result<&Node, PrecompileError> {
        self.nodes.get(digest).ok_or(PrecompileError::MissingNode)
    }

    /// Returns whether a digest is materialized in the DAG store.
    ///
    /// [`TRUE_DIGEST`] is virtual and is never stored as a node, so callers that accept it must
    /// handle it explicitly.
    pub fn contains(&self, digest: &Digest) -> bool {
        self.nodes.contains_key(digest)
    }

    /// Interns a node by digest without schema checks.
    ///
    /// Use only after the caller has established the relevant invariants. The wire encoder emits
    /// an interned node only if it is reachable from the transcript root.
    pub(crate) fn intern(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        self.nodes.insert(digest, node);
        digest
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    fn get_eval(&self, digest: &Digest) -> Option<&Node> {
        self.evals.get(digest)
    }

    /// Caches a reduction result and materializes its canonical node for downstream references.
    fn record_eval(&mut self, input_digest: Digest, canonical: Node) {
        self.evals.insert(input_digest, canonical.clone());
        self.intern(canonical);
    }

    /// Returns the current transcript root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Appends a statement commitment to the transcript.
    ///
    /// `expected_new_root` lets the host check that its digest agrees with the in-circuit hash.
    /// This method records the commitment only; semantic validity is re-established during
    /// [`DeferredState::rehydrate`] by re-evaluating each logged statement.
    pub fn log(
        &mut self,
        stmt_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<(), DeferredError> {
        let and_node = Node::and(self.root, stmt_digest);
        let actual = and_node.digest();
        if actual != expected_new_root {
            return Err(DeferredError::InvalidPayload);
        }
        self.nodes.insert(actual, and_node);
        self.root = actual;
        Ok(())
    }

    /// Commits a schema-valid node to the DAG without reducing it.
    ///
    /// Registration lets later nodes reference this digest and lets predicates be logged, but it
    /// does not prove predicate truth. Verification happens only through evaluation or through
    /// the rehydration check of a logged transcript.
    pub fn register(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Digest, PrecompileError> {
        let node_type = precompiles.decode(node.tag)?;
        if !payload_matches_type(node_type, &node.payload) {
            return Err(PrecompileError::InvalidNode);
        }
        let digest = node.digest();
        self.nodes.insert(digest, node);
        Ok(digest)
    }

    /// Reduces a concrete node through the precompile registry and caches its canonical form.
    ///
    /// Child digests must already be committed in the DAG, so the same witness can be serialized
    /// and rehydrated. Predicate success returns [`Node::TRUE`]; mismatch returns
    /// [`PrecompileError::AssertionFailed`].
    pub fn evaluate_node(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Node, PrecompileError> {
        let node_type = precompiles.decode(node.tag)?;
        if !payload_matches_type(node_type, &node.payload) {
            return Err(PrecompileError::InvalidNode);
        }
        let input_digest = node.digest();
        WitnessBuilder::new(self, precompiles).reduce_and_record_eval(node, input_digest)
    }

    /// Reduces a committed node addressed by digest.
    ///
    /// The memo is used only after the digest is proven present in `nodes`; memo entries alone do
    /// not create durable DAG membership.
    pub fn evaluate_digest(
        &mut self,
        precompiles: &PrecompileRegistry,
        digest: Digest,
    ) -> Result<Node, PrecompileError> {
        if !self.contains(&digest) {
            return Err(PrecompileError::MissingNode);
        }
        if let Some(canonical) = self.get_eval(&digest) {
            return Ok(canonical.clone());
        }
        let node = self.get(&digest)?.clone();
        self.evaluate_node(precompiles, node)
    }

    /// Serializes the transcript-reachable DAG into compact wire form.
    ///
    /// Only nodes reachable from `root` are emitted; registered or memoized orphans are dropped.
    /// Join-shaped expressions use earlier-entry indices, with [`crate::deferred::TRUE_INDEX`]
    /// for the virtual [`TRUE_DIGEST`] terminal. Value-looking payloads that coincidentally match
    /// child digests still round-trip because their reconstructed bytes are identical.
    pub fn to_wire(&self) -> DeferredStateWire {
        let mut by_digest = BTreeMap::<Digest, u32>::new();
        let mut entries = Vec::<super::WireEntry>::new();
        self.dfs_post_order(self.root, &mut by_digest, &mut entries);
        // DFS post-order from `self.root` emits the AND-node digesting to `self.root` last (or
        // emits nothing when root is `TRUE_DIGEST`). The deferred commitment is therefore
        // recoverable as `entries.last().digest()` — no need to ship it as a field.
        DeferredStateWire { entries }
    }

    /// Emits the root-reachable closure in child-before-parent order for index encoding.
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

        // Determine whether this is a real Join node (children resolve) or a Value-shaped
        // node. For Chunk bodies, no children to recurse into.
        let mut binary_indices: Option<(Digest, Digest)> = None;
        if let Ok((lhs, rhs)) = node.payload.join_children() {
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
            (Payload::Chunk(chunks), _) => super::WireBody::Chunks(chunks.clone()),
            (Payload::Expression(felts), None) => super::WireBody::Value(*felts),
            (Payload::Expression(_), Some((lhs, rhs))) => {
                let lhs_idx = if lhs == TRUE_DIGEST {
                    super::TRUE_INDEX
                } else {
                    by_digest[&lhs]
                };
                let rhs_idx = if rhs == TRUE_DIGEST {
                    super::TRUE_INDEX
                } else {
                    by_digest[&rhs]
                };
                super::WireBody::Join { lhs: lhs_idx, rhs: rhs_idx }
            },
        };
        entries.push(super::WireEntry { tag: node.tag, body });
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    ///
    /// Rehydration first reconstructs digest-addressed nodes under schema and shape checks, then
    /// rejects entries outside the transcript root's reachable closure, and finally walks the
    /// AND-chain while re-evaluating every logged statement.
    pub fn rehydrate(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut state = Self::new();
        // Parallel to `wire.entries`: the recomputed digest at each index. `Join` entries at
        // position `i` reconstruct their payload by reading earlier `digests[lhs/rhs]` (or
        // `TRUE_DIGEST` when the index is `TRUE_INDEX`).
        let mut digests: Vec<Digest> = Vec::with_capacity(wire.entries.len());

        for (i, entry) in wire.entries.iter().enumerate() {
            let node = match &entry.body {
                super::WireBody::Value(felts) => Node::leaf(entry.tag, *felts),
                super::WireBody::Chunks(chunks) => {
                    // The wire is untrusted: the deserializer accepts a zero-length chunk body,
                    // but empty chunk bodies are forbidden. Reject here, before `Node::chunk`
                    // (whose non-empty precondition would otherwise panic in debug builds);
                    // `payload_matches_type` below would also reject it, but only after
                    // construction.
                    if chunks.is_empty() {
                        return Err(IntegrityError::ShapeMismatch);
                    }
                    Node::chunk(entry.tag, chunks.clone())
                },
                super::WireBody::Join { lhs, rhs } => {
                    let lhs_d = resolve_index(*lhs, i, &digests)?;
                    let rhs_d = resolve_index(*rhs, i, &digests)?;
                    Node::join(entry.tag, lhs_d, rhs_d)
                },
            };

            // Validate. `decode_node_type` handles AND-nodes (framework-owned `Tag::TRUE`)
            // without invoking a precompile, then defers to `precompiles.decode` for everything
            // else. `payload_matches_type` enforces the Expression-vs-Chunk distinction (and the
            // exact chunk count for Chunks tags, which is ≥ 1 — empty chunk bodies are rejected).
            let node_type = decode_node_type(precompiles, &node)?;
            if !payload_matches_type(node_type, &node.payload) {
                return Err(IntegrityError::ShapeMismatch);
            }

            let d = state.intern(node);
            digests.push(d);
        }

        // Derive the deferred commitment from phase 1's last digest. DFS post-order from the
        // prover's `self.root` puts the topmost AND-node at the end of `entries`, so its digest
        // is the chain's head. Empty entries → trivial-empty transcript (`TRUE_DIGEST`).
        state.root = digests.last().copied().unwrap_or(TRUE_DIGEST);

        // Reachability — every interned entry must lie in the structural closure of `root`.
        // `to_wire` emits exactly that closure (DFS post-order from root), so a faithful wire
        // passes; an entry outside it is bloat or hidden data and is rejected. Done here, before
        // phase 2's evaluate re-mints canonical intermediates into `state.nodes`.
        if reachable_closure(&state.nodes, state.root).len() != state.nodes.len() {
            return Err(IntegrityError::DanglingNode);
        }

        // Phase 2 — chain walk + per-statement re-evaluation. AND-nodes share Tag::TRUE and a
        // `(prev_root, stmt_digest)` payload; statements must reduce to `Node::TRUE` under the
        // precompiles. An interior AND-node whose `prev_root` doesn't resolve in `state.nodes` (and
        // isn't `TRUE_DIGEST`) surfaces as `BrokenChain` — a tampered or corrupt transcript.
        let mut cur = state.root;
        while cur != TRUE_DIGEST {
            let and_node = state.nodes.get(&cur).ok_or(IntegrityError::BrokenChain)?.clone();
            if and_node.tag != Tag::TRUE {
                return Err(IntegrityError::NonAndNode);
            }
            let (prev_root, stmt_digest) =
                and_node.payload.join_children().map_err(|_| IntegrityError::BadAndPayload)?;
            let stmt =
                state.nodes.get(&stmt_digest).ok_or(IntegrityError::MissingStatement)?.clone();
            let canonical = state.evaluate_node(precompiles, stmt)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }
            cur = prev_root;
        }

        Ok(state)
    }

    /// Returns logged statement digests in execution order for already-verified test states.
    ///
    /// Panics if the chain is malformed; production callers should obtain states through
    /// [`Self::rehydrate`], which validates the chain first.
    #[cfg(test)]
    pub fn statements(&self) -> Vec<Digest> {
        let mut out = Vec::new();
        let mut cur = self.root;
        while cur != TRUE_DIGEST {
            let and_node = self
                .nodes
                .get(&cur)
                .expect("statements(): AND-chain references a node not in state");
            debug_assert_eq!(
                and_node.tag,
                Tag::TRUE,
                "statements(): AND-chain step is not tagged Tag::TRUE"
            );
            let (prev_root, stmt_digest) = and_node
                .payload
                .join_children()
                .expect("statements(): AND-node has non-expression body");
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

/// Resolves a wire child index to the digest it references during rehydration.
fn resolve_index(idx: u32, current: usize, digests: &[Digest]) -> Result<Digest, IntegrityError> {
    if idx == super::TRUE_INDEX {
        return Ok(TRUE_DIGEST);
    }
    let i = idx as usize;
    if i >= current || i >= digests.len() {
        return Err(IntegrityError::BadIndex);
    }
    Ok(digests[i])
}

/// Decodes a node shape during rehydration, treating framework TRUE/AND nodes as joins.
fn decode_node_type(
    precompiles: &PrecompileRegistry,
    node: &Node,
) -> Result<NodeType, IntegrityError> {
    if node.tag == Tag::TRUE {
        return Ok(NodeType::Join);
    }
    precompiles.decode(node.tag).map_err(|_| IntegrityError::UnknownTag)
}

/// Returns whether the payload variant matches the shape declared for a tag.
///
/// `Value` and `Join` both use expression payloads in memory; the tag decides how the owning
/// precompile interprets those eight felts.
fn payload_matches_type(nt: NodeType, payload: &Payload) -> bool {
    match (nt, payload) {
        (NodeType::Value | NodeType::Join, Payload::Expression(_)) => true,
        (NodeType::Chunks(n), Payload::Chunk(chunks)) => chunks.len() == n.get() as usize,
        _ => false,
    }
}

/// Returns the structural closure reachable from a transcript root.
///
/// This mirrors wire encoding: expression payloads are followed only when both child digests are
/// present or are the virtual [`TRUE_DIGEST`]. Rehydration uses the closure to reject hidden or
/// bloated wire entries.
fn reachable_closure(nodes: &BTreeMap<Digest, Node>, root: Digest) -> BTreeSet<Digest> {
    let mut seen = BTreeSet::new();
    let mut stack = alloc::vec![root];
    while let Some(d) = stack.pop() {
        if d == TRUE_DIGEST || !seen.insert(d) {
            continue;
        }
        let Some(node) = nodes.get(&d) else { continue };
        if let Ok((lhs, rhs)) = node.payload.join_children() {
            let lhs_ok = lhs == TRUE_DIGEST || nodes.contains_key(&lhs);
            let rhs_ok = rhs == TRUE_DIGEST || nodes.contains_key(&rhs);
            if lhs_ok && rhs_ok {
                stack.push(lhs);
                stack.push(rhs);
            }
        }
    }
    seen.remove(&TRUE_DIGEST);
    seen
}

// WITNESS BUILDER
// ================================================================================================

/// Capability object passed to precompiles during recursive reduction.
///
/// Precompiles do not own the DAG; they receive this handle to resolve committed children and to
/// intern helper nodes referenced by compound canonicals. The verifier reuses the same path during
/// [`DeferredState::rehydrate`], so prover and verifier agree on how witnesses are reconstructed.
pub struct WitnessBuilder<'a> {
    state: &'a mut DeferredState,
    precompiles: &'a PrecompileRegistry,
}

impl<'a> WitnessBuilder<'a> {
    /// Binds state and registry for one framework-driven reduction.
    pub(crate) fn new(state: &'a mut DeferredState, precompiles: &'a PrecompileRegistry) -> Self {
        Self { state, precompiles }
    }

    /// Resolves a committed child digest to its canonical form.
    ///
    /// The committed-node check keeps local evaluation reproducible by `to_wire` and rehydration;
    /// memo hits are used only after that membership is established.
    pub fn resolve(&mut self, digest: Digest) -> Result<Node, PrecompileError> {
        if !self.state.contains(&digest) {
            return Err(PrecompileError::MissingNode);
        }
        if let Some(canonical) = self.state.get_eval(&digest) {
            return Ok(canonical.clone());
        }
        let child = self.state.get(&digest)?.clone();
        self.reduce_and_record_eval(child, digest)
    }

    /// Commits a freshly minted helper node and returns its digest.
    ///
    /// Use this when a compound canonical needs stable child commitments that were created during
    /// reduction.
    pub fn intern(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        self.state.nodes.insert(digest, node);
        digest
    }

    /// Reduces a node, memoizes the canonical form, and commits the canonical node.
    fn reduce_and_record_eval(
        &mut self,
        node: Node,
        input_digest: Digest,
    ) -> Result<Node, PrecompileError> {
        let precompiles = self.precompiles;
        let canonical = precompiles.reduce(&node, self)?;
        self.state.record_eval(input_digest, canonical.clone());
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Payload, PrecompileRegistry, TRUE_DIGEST, Tag},
        testing::precompile::Uint,
    };

    /// Single-precompile registry used by deferred-state unit tests.
    fn precompiles() -> PrecompileRegistry {
        PrecompileRegistry::default().with_precompile(Uint)
    }

    fn test_leaf(value: u32) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value;
        Uint::leaf_node(limbs)
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
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt = state.evaluate_node(&schema, pred).unwrap();
        // The canonical of an `eq` predicate is `Node::TRUE`. Use the predicate's *digest* —
        // which we recover from the original node — as `stmt_digest`.
        let _ = stmt; // canonical, discarded
        let stmt_digest = Node::join(Uint::eq_tag(), a, a).digest();

        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
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
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
        assert_eq!(state.root(), pre_root, "root must remain unchanged on failure");
        assert_eq!(state.nodes().len(), pre_node_count, "no node interned on failure");
    }

    #[test]
    fn missing_node_get_returns_error() {
        let state = DeferredState::new();
        let err = state.get(&dummy_digest(1)).unwrap_err();
        assert!(matches!(err, PrecompileError::MissingNode));
    }

    #[test]
    fn register_leaf_stores_it() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let node = test_leaf(7);
        let digest = state.register(&schema, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let node = test_leaf(7);
        let d1 = state.register(&schema, node.clone()).unwrap();
        let d2 = state.register(&schema, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 1);
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        // Uint id + unknown discriminant: schema decode returns Err.
        let bad_tag = Tag {
            id: Uint::id(),
            args: [Felt::from_u32(99), ZERO, ZERO],
        };
        let bad = Node::leaf(bad_tag, [Felt::from_u32(0); 8]);
        let err = state.register(&schema, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn register_op_stores_op_node() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let op = Node::join(Uint::add_tag(), a, b);
        let digest = state.register(&schema, op).unwrap();
        assert!(state.contains(&digest));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // `register` is a pure host hint — it interns the predicate node without driving reduce.
        // Programs that want host-side verification call `evaluate`; programs that want
        // constrained verification call `log`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = state.register(&schema, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate_node(&schema, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_succeeds_returns_true_node() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), a, a);
        let result = state.evaluate_node(&schema, assertion).unwrap();
        assert!(result.is_true_node(), "predicate success returns the canonical TRUE node");
    }

    #[test]
    fn evaluate_predicate_mismatch_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let mismatch = Node::join(Uint::eq_tag(), a, b);
        let err = state.evaluate_node(&schema, mismatch);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_missing_node_errors() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(1)).unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let assertion = Node::join(Uint::eq_tag(), a, dangling);
        let err = state.evaluate_node(&schema, assertion);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn nested_evaluation_reduces_through_op_tree() {
        // Build (a + b) * c, then verify equal to a pre-computed leaf via evaluate.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let result = state.evaluate_node(&schema, assertion).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn evaluate_interns_canonicals_into_nodes() {
        // Register the full op tree (a + b) * c == 35 plus an orphan leaf, evaluate the
        // predicate, and assert evaluate interns computed canonicals into `state.nodes`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let assertion_digest = assertion.digest();
        state.evaluate_node(&schema, assertion).unwrap();

        // Newly interned canonicals: leaf(7) for add, and TRUE for the predicate result.
        assert_eq!(state.nodes().len(), 9);
        assert!(!state.contains(&assertion_digest), "evaluate does not auto-register input node");
        assert!(state.contains(&test_leaf(7).digest()), "canonical(add) is interned into nodes");
        assert!(state.contains(&Node::TRUE.digest()), "canonical(TRUE) is interned into nodes");
        assert_eq!(state.root(), TRUE_DIGEST, "no log called, root is still TRUE");
    }

    #[test]
    fn evaluate_does_not_intern_unregistered_input() {
        // Build (a+b)*c, pre-register only the leaves and `add`. The outer `mul` is handed
        // directly to `evaluate` — input stays out of `nodes`, but computed canonicals are
        // interned.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let add = Node::join(Uint::add_tag(), a, b);
        let add_digest = state.register(&schema, add).unwrap();
        let mul = Node::join(Uint::mul_tag(), add_digest, c);
        let mul_digest = mul.digest();

        let canonical = state.evaluate_node(&schema, mul).unwrap();
        assert_eq!(canonical, test_leaf(35));
        assert!(!state.contains(&mul_digest), "input op stays out of nodes");
        assert!(state.contains(&test_leaf(35).digest()), "computed canonical is interned");

        let err = state.evaluate_digest(&schema, mul_digest).unwrap_err();
        assert!(matches!(err, PrecompileError::MissingNode));
    }

    #[test]
    fn resolve_requires_committed_node_even_for_memo_entries() {
        // TRUE is seeded in `evals`, but it is not an interned DAG node. `resolve` is for payload
        // child references, so it requires committed DAG membership before consulting the memo.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let mut witness = WitnessBuilder::new(&mut state, &schema);
        let err = witness.resolve(TRUE_DIGEST).unwrap_err();
        assert!(matches!(err, PrecompileError::MissingNode));
    }

    // REHYDRATE TESTS
    // ============================================================================================

    /// Asserts that wire round-tripping preserves the verified transcript root and nodes.
    fn assert_round_trips(state: &DeferredState, precompiles: &PrecompileRegistry) {
        let rehydrated = DeferredState::rehydrate(&state.to_wire(), precompiles).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert!(
            rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
            "wire round-trip changed a reachable node",
        );
    }

    /// Builds a logged `(a+b)*c == 35` transcript used by round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        let c = state.register(&schema, test_leaf(5)).unwrap();
        let expected = state.register(&schema, test_leaf(35)).unwrap();
        let add = state.register(&schema, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&schema, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        // `log` references the predicate node by digest; pre-register so the wire embeds it as
        // a Join entry rather than a bare-commitment Value.
        let stmt_digest = state.register(&schema, assertion.clone()).unwrap();
        state.evaluate_node(&schema, assertion).unwrap();
        let new_root = Node::and(state.root(), stmt_digest).digest();
        state.log(stmt_digest, new_root).unwrap();
        // Defense-in-depth: every fixture consumer inherits a wire round-trip self-check, so any
        // future change that breaks `to_wire`/`rehydrate` consistency fails loudly here.
        assert_round_trips(&state, &precompiles());
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::default();
        let state = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert!(state.nodes().is_empty());
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // A Join entry whose lhs index points past the (empty) digest table: index 0 is not
        // < its own position 0 → BadIndex.
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: Uint::add_tag(),
                body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::BadIndex)));
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        // A tag the schema rejects — its id doesn't match Uint.
        let bogus_tag = Tag {
            id: Felt::new_unchecked(0xdead),
            args: [ZERO; 3],
        };
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: bogus_tag,
                body: crate::deferred::WireBody::Value([ZERO; 8]),
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::UnknownTag)));
    }

    #[test]
    fn rehydrate_rejects_empty_chunk_body() {
        // The deserializer accepts a zero-length chunk body, but empty chunk bodies are forbidden.
        // Rehydrate must reject one with `ShapeMismatch`, not panic in `Node::chunk`'s non-empty
        // precondition — the wire is untrusted. The guard fires before tag decode, so the tag is
        // irrelevant.
        let wire = DeferredStateWire {
            entries: alloc::vec![crate::deferred::WireEntry {
                tag: test_leaf(0).tag,
                body: crate::deferred::WireBody::Chunks(alloc::sync::Arc::from(
                    alloc::vec![[ZERO; 8]; 0]
                )),
            }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::ShapeMismatch)));
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_leaves() {
        // Register an orphan that no one references; build a logged-predicate chain. The wire
        // must contain the chain's reachable closure but NOT the orphan.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let _orphan = state.register(&schema, test_leaf(99)).unwrap();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt_digest = state.register(&schema, pred.clone()).unwrap();
        state.evaluate_node(&schema, pred).unwrap();
        let new_root = Node::and(state.root(), stmt_digest).digest();
        state.log(stmt_digest, new_root).unwrap();
        // Defense-in-depth: orphan-trimmed wire must still round-trip cleanly.
        assert_round_trips(&state, &schema);

        let wire = state.to_wire();
        // Rehydrate and read back the digest set — the wire's bytes don't carry digests, but
        // rehydration recomputes them, so we exercise the round-trip identity here.
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
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
        // Orphans dropped by `to_wire` must still round-trip via rehydrate.
        let original = built_state_with_logged_predicate();
        let wire = original.to_wire();
        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        // Build a chain whose statement is `eq(leaf(3), leaf(4))` — disagreeing leaves.
        // Phase 2's evaluate returns AssertionFailed, surfaced as `PredicateFailed`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // Hand-roll a chain that points to a failing predicate without going through `log`'s
        // schema gate (which evaluate-rejects ahead of time).
        let bad_pred = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = bad_pred.digest();
        state.intern(bad_pred);
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.intern(and_node);
        state.root = and_digest;

        let wire = state.to_wire();
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::PredicateFailed(_))),
            "expected PredicateFailed, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_broken_chain() {
        // An AND-node whose `prev_root` references a digest not present in the wire entries.
        // Because the structural heuristic only follows a node's `(lhs, rhs)` when *both*
        // resolve, the missing `prev_root` makes the AND-node opaque, leaving `a`/`pred`
        // outside the root's closure — so the reachability gate (before phase 2) rejects this
        // with `DanglingNode`, preempting the phase-2 `BrokenChain` backstop. Both are valid
        // rejections of the same malformed wire.
        //
        // Entries (DFS post-order):
        //   [0] leaf `a` = test_leaf(7)                              — Value
        //   [1] predicate eq(a, a)                                   — Join (lhs=rhs=0)
        //   [2] AND-node { Tag::TRUE, payload: (bogus_prev, pred) }   — Value (raw felts; the
        //       AND-node's `prev_root` can't be encoded as a wire index because it intentionally
        //       doesn't appear in the entries)
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let pred_digest = pred.digest();
        let bogus_prev = dummy_digest(42);
        let and_payload = *Payload::join(bogus_prev, pred_digest)
            .as_felts()
            .expect("join is expression-bodied");

        let wire = DeferredStateWire {
            entries: alloc::vec![
                crate::deferred::WireEntry {
                    tag: a.tag,
                    body: crate::deferred::WireBody::Value(a_payload),
                },
                crate::deferred::WireEntry {
                    tag: pred.tag,
                    body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
                },
                crate::deferred::WireEntry {
                    tag: Tag::TRUE,
                    body: crate::deferred::WireBody::Value(and_payload),
                },
            ],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::DanglingNode)),
            "expected DanglingNode (reachability gate preempts BrokenChain), got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_dangling_entry() {
        // A faithful chain (leaf a → eq(a, a) predicate → AND-node) plus an orphan leaf that
        // nothing references. Phase 1 interns all four; the reachability check (before phase 2)
        // finds the orphan outside the root's structural closure and rejects it.
        //
        // Entries:
        //   [0] leaf a = test_leaf(7)            — Value
        //   [1] orphan = test_leaf(99)           — Value (dangling: unreferenced)
        //   [2] predicate eq(a, a)               — Join { lhs: 0, rhs: 0 }
        //   [3] AND { Tag::TRUE, (TRUE, pred) }   — Join { lhs: TRUE_INDEX, rhs: 2 }
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let orphan = test_leaf(99);
        let orphan_payload = *orphan.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            entries: alloc::vec![
                crate::deferred::WireEntry {
                    tag: a.tag,
                    body: crate::deferred::WireBody::Value(a_payload),
                },
                crate::deferred::WireEntry {
                    tag: orphan.tag,
                    body: crate::deferred::WireBody::Value(orphan_payload),
                },
                crate::deferred::WireEntry {
                    tag: pred.tag,
                    body: crate::deferred::WireBody::Join { lhs: 0, rhs: 0 },
                },
                crate::deferred::WireEntry {
                    tag: Tag::TRUE,
                    body: crate::deferred::WireBody::Join {
                        lhs: crate::deferred::TRUE_INDEX,
                        rhs: 2,
                    },
                },
            ],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::DanglingNode)),
            "expected DanglingNode, got {err:?}"
        );
    }
}
