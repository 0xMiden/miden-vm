use alloc::collections::BTreeMap;

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, PrecompileError,
    PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory witness for deferred-DAG verification.
///
/// The state keeps committed nodes, host-side reduction memos, and the current transcript root.
/// It is intentionally not serialized directly: proofs carry [`DeferredStateWire`], and
/// [`Self::rehydrate`] rebuilds this state only after `PrecompileRegistry` checks,
/// reachability checks, and transcript re-evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    evals: BTreeMap<Digest, Node>,
}

impl Default for DeferredState {
    fn default() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);

        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, Node::TRUE);

        Self { nodes, root: TRUE_DIGEST, evals }
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
    /// [`TRUE_DIGEST`] is always present and maps to [`Node::TRUE`].
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

    /// Commits a `PrecompileRegistry`-valid node to the DAG without reducing it.
    ///
    /// Registration lets later nodes reference this digest and lets predicates be logged, but it
    /// does not prove predicate truth. Verification happens only through evaluation or through
    /// the rehydration check of a logged transcript.
    pub fn register(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Digest, PrecompileError> {
        precompiles.validate_node(&node)?;
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
        precompiles.validate_node(&node)?;
        let input_digest = node.digest();
        if node.tag == Tag::TRUE {
            self.record_eval(input_digest, Node::TRUE);
            Ok(Node::TRUE)
        } else if node.tag == Tag::AND {
            self.evaluate_framework_and(precompiles, node, input_digest)
        } else {
            WitnessBuilder::new(self, precompiles).reduce_and_record_eval(node, input_digest)
        }
    }

    /// Reduces a transcript/statement root to its canonical form.
    ///
    /// [`TRUE_DIGEST`] reduces to the always-present [`Node::TRUE`]. Materialized [`Tag::AND`]
    /// nodes are reduced by the framework as conjunctions: both child roots must reduce to TRUE.
    /// Other nodes are reduced through the installed precompiles.
    pub(crate) fn evaluate_statement_digest(
        &mut self,
        precompiles: &PrecompileRegistry,
        digest: Digest,
    ) -> Result<Node, PrecompileError> {
        self.evaluate_digest(precompiles, digest)
    }

    fn verify_statement_digest(
        &mut self,
        precompiles: &PrecompileRegistry,
        digest: Digest,
    ) -> Result<(), PrecompileError> {
        let canonical = self.evaluate_statement_digest(precompiles, digest)?;
        if canonical.is_true_node() {
            Ok(())
        } else {
            Err(PrecompileError::AssertionFailed)
        }
    }

    fn evaluate_framework_and(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
        input_digest: Digest,
    ) -> Result<Node, PrecompileError> {
        let (lhs, rhs) = node.payload.join_children()?;
        self.verify_statement_digest(precompiles, lhs)?;
        self.verify_statement_digest(precompiles, rhs)?;
        self.record_eval(input_digest, Node::TRUE);
        Ok(Node::TRUE)
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
    /// The installed `PrecompileRegistry` determines each node's shape, so graph edges are never
    /// inferred from opaque payload bytes.
    pub fn to_wire(
        &self,
        precompiles: &PrecompileRegistry,
    ) -> Result<DeferredStateWire, IntegrityError> {
        DeferredStateWire::from_state(self, precompiles)
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    ///
    /// Rehydration first reconstructs digest-addressed nodes under `PrecompileRegistry` and shape
    /// checks, then rejects reconstructed nodes outside the transcript root's reachable closure,
    /// and finally walks the AND-chain while re-evaluating every logged statement.
    pub fn rehydrate(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        wire.rehydrate(precompiles)
    }

    /// Returns logged statement digests in execution order for already-verified test states.
    ///
    /// Panics if the chain is malformed; production callers should obtain states through
    /// [`Self::rehydrate`], which validates the chain first.
    #[cfg(test)]
    pub fn statements(&self) -> alloc::vec::Vec<Digest> {
        use alloc::vec::Vec;

        let mut out = Vec::new();
        let mut cur = self.root;
        while cur != TRUE_DIGEST {
            let and_node = self
                .nodes
                .get(&cur)
                .expect("statements(): AND-chain references a node not in state");
            debug_assert_eq!(
                and_node.tag,
                super::Tag::AND,
                "statements(): AND-chain step is not tagged Tag::AND"
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
// `DeferredState::rehydrate(&wire, precompiles)`. This keeps the only path from untrusted bytes to
// an in-memory state through the registry-validated, chain-walked rehydrate constructor.

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
        deferred::{PrecompileRegistry, TRUE_DIGEST, Tag},
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
    fn empty_state_seeds_true_node_and_root_is_true() {
        let mut state = DeferredState::new();
        let schema = precompiles();

        assert_eq!(state.nodes().len(), 1);
        assert!(state.contains(&TRUE_DIGEST));
        assert_eq!(state.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.evaluate_digest(&schema, TRUE_DIGEST).unwrap(), Node::TRUE);
    }

    #[test]
    fn register_true_is_idempotent() {
        let mut state = DeferredState::new();
        let schema = precompiles();

        let digest = state.register(&schema, Node::TRUE).unwrap();
        assert_eq!(digest, TRUE_DIGEST);
        assert_eq!(state.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.nodes().len(), 1);
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
        assert_ne!(expected, TRUE_DIGEST);
        assert_eq!(state.root(), expected);
        // The newly-minted AND-node must be in the map keyed by its digest.
        assert!(state.contains(&expected));
        assert_eq!(state.get(&expected).unwrap().tag, Tag::AND);
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
        assert_eq!(state.nodes().len(), 2); // TRUE plus the leaf
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
    fn evaluate_predicate_reports_success_and_child_failures() {
        let schema = precompiles();
        let mut state = DeferredState::new();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let b = state.register(&schema, test_leaf(8)).unwrap();

        let ok = state.evaluate_node(&schema, Node::join(Uint::eq_tag(), a, a)).unwrap();
        assert!(ok.is_true_node(), "predicate success returns the canonical TRUE node");

        let mismatch = state.evaluate_node(&schema, Node::join(Uint::eq_tag(), a, b));
        assert!(matches!(mismatch.unwrap_err().root(), PrecompileError::AssertionFailed));

        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let missing = state.evaluate_node(&schema, Node::join(Uint::eq_tag(), a, dangling));
        assert!(matches!(missing.unwrap_err().root(), PrecompileError::MissingNode));
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

        // Newly interned canonicals: leaf(7) for add; TRUE was seeded at state creation.
        assert_eq!(state.nodes().len(), 9);
        assert!(!state.contains(&assertion_digest), "evaluate does not auto-register input node");
        assert!(state.contains(&test_leaf(7).digest()), "canonical(add) is interned into nodes");
        assert!(state.contains(&Node::TRUE.digest()), "canonical(TRUE) remains in nodes");
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

    // REHYDRATE TESTS
    // ============================================================================================

    /// Asserts that wire round-tripping preserves the verified transcript root and nodes.
    fn assert_round_trips(state: &DeferredState, precompiles: &PrecompileRegistry) {
        let wire = state.to_wire(precompiles).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, precompiles).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert!(
            rehydrated.nodes().iter().all(|(d, n)| state.nodes().get(d) == Some(n)),
            "wire round-trip changed a reachable node",
        );
        assert_eq!(
            rehydrated.to_wire(precompiles).unwrap(),
            wire,
            "accepted wire must be canonical"
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
        // `log` references the predicate node by digest; pre-register so the sectioned wire emits
        // it as a binary `WireNode` rather than treating the digest as a bare commitment.
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
        let schema = precompiles();
        let wire = original.to_wire(&schema).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &schema).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::default();
        let state = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.nodes().len(), 1);
        assert_eq!(state.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
    }

    #[test]
    fn to_wire_does_not_serialize_true_as_entry() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        state.register(&schema, Node::TRUE).unwrap();

        let wire = state.to_wire(&schema).unwrap();
        assert_eq!(wire, DeferredStateWire::default());
    }

    #[test]
    fn rehydrate_rejects_materialized_true_entries() {
        let wires = [
            DeferredStateWire {
                leaf_tags: alloc::vec![Tag::TRUE],
                blocks: alloc::vec![[ZERO; 8]],
                ..Default::default()
            },
            DeferredStateWire {
                nodes: alloc::vec![crate::deferred::WireNode {
                    tag: Tag::TRUE,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: crate::deferred::TRUE_INDEX,
                }],
                ..Default::default()
            },
        ];

        for wire in wires {
            let err = DeferredState::rehydrate(&wire, &precompiles());
            assert!(
                matches!(err, Err(IntegrityError::DuplicateNode)),
                "expected DuplicateNode, got {err:?}"
            );
        }
    }

    #[test]
    fn rehydrate_accepts_logged_empty_transcript_root() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let new_root = Node::and(state.root(), TRUE_DIGEST).digest();
        state.log(TRUE_DIGEST, new_root).unwrap();
        assert_ne!(new_root, TRUE_DIGEST);
        assert_eq!(state.get(&new_root).unwrap().tag, Tag::AND);

        let wire = state.to_wire(&schema).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &schema).unwrap();
        assert_eq!(rehydrated.root(), new_root);
        assert_eq!(rehydrated.statements(), alloc::vec![TRUE_DIGEST]);
        assert_round_trips(&state, &schema);
    }

    #[test]
    fn rehydrate_accepts_logged_nested_transcript_root() {
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let pred_digest = state.register(&schema, pred.clone()).unwrap();
        state.evaluate_node(&schema, pred).unwrap();

        let inner_root = state.register(&schema, Node::and(TRUE_DIGEST, pred_digest)).unwrap();
        let outer_root = Node::and(state.root(), inner_root).digest();
        state.log(inner_root, outer_root).unwrap();

        let wire = state.to_wire(&schema).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &schema).unwrap();
        assert_eq!(rehydrated.root(), outer_root);
        assert_eq!(rehydrated.statements(), alloc::vec![inner_root]);
        assert!(rehydrated.contains(&inner_root));
        assert!(rehydrated.contains(&pred_digest));
        assert_round_trips(&state, &schema);
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // Index 0 is reserved for TRUE. With no materialized nodes, index 1 is out of range.
        let wire = DeferredStateWire {
            nodes: alloc::vec![crate::deferred::WireNode { tag: Uint::add_tag(), lhs: 1, rhs: 0 }],
            ..Default::default()
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::BadIndex)));
    }

    #[test]
    fn rehydrate_rejects_duplicate_digest_in_any_section() {
        let leaf = test_leaf(7);
        let payload = *leaf.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), leaf.digest(), leaf.digest());
        let wires = [
            DeferredStateWire {
                leaf_tags: alloc::vec![leaf.tag, leaf.tag],
                blocks: alloc::vec![payload, payload],
                ..Default::default()
            },
            DeferredStateWire {
                leaf_tags: alloc::vec![leaf.tag],
                blocks: alloc::vec![payload],
                nodes: alloc::vec![
                    crate::deferred::WireNode { tag: pred.tag, lhs: 1, rhs: 1 },
                    crate::deferred::WireNode { tag: pred.tag, lhs: 1, rhs: 1 },
                ],
                ..Default::default()
            },
        ];

        for wire in wires {
            let err = DeferredState::rehydrate(&wire, &precompiles());
            assert!(
                matches!(err, Err(IntegrityError::DuplicateNode)),
                "expected DuplicateNode, got {err:?}"
            );
        }
    }

    #[test]
    fn rehydrate_rejects_non_and_root() {
        let leaf = test_leaf(7);
        let payload = *leaf.payload.as_felts().expect("leaf is expression-bodied");
        let wire = DeferredStateWire {
            leaf_tags: alloc::vec![leaf.tag],
            blocks: alloc::vec![payload],
            ..Default::default()
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::NonAndNode)),
            "expected NonAndNode, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        // A tag the schema rejects — its id doesn't match Uint.
        let bogus_tag = Tag {
            id: Felt::new_unchecked(0xdead),
            args: [ZERO; 3],
        };
        let wire = DeferredStateWire {
            leaf_tags: alloc::vec![bogus_tag],
            blocks: alloc::vec![[ZERO; 8]],
            ..Default::default()
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::UnknownTag)));
    }

    #[test]
    fn rehydrate_rejects_unclaimed_payload_block() {
        // Blocks must be consumed by leaf payloads or by schema-sized chunk payloads. A raw block
        // with no owning tag is hidden data and must be rejected.
        let wire = DeferredStateWire {
            blocks: alloc::vec![[ZERO; 8]],
            ..Default::default()
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

        let wire = state.to_wire(&schema).unwrap();
        // Rehydrate and read back the digest set — the wire's bytes don't carry digests, but
        // rehydration recomputes them, so we exercise the round-trip identity here.
        let rehydrated = DeferredState::rehydrate(&wire, &schema).unwrap();
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
    fn rehydrate_rejects_noncanonical_leaf_order() {
        let mut state = DeferredState::new();
        let schema = precompiles();

        let a = state.register(&schema, test_leaf(3)).unwrap();
        let pred_a = Node::join(Uint::eq_tag(), a, a);
        let pred_a_digest = state.register(&schema, pred_a.clone()).unwrap();
        state.evaluate_node(&schema, pred_a).unwrap();
        let root_a = Node::and(state.root(), pred_a_digest).digest();
        state.log(pred_a_digest, root_a).unwrap();

        let b = state.register(&schema, test_leaf(4)).unwrap();
        let pred_b = Node::join(Uint::eq_tag(), b, b);
        let pred_b_digest = state.register(&schema, pred_b.clone()).unwrap();
        state.evaluate_node(&schema, pred_b).unwrap();
        let root_b = Node::and(state.root(), pred_b_digest).digest();
        state.log(pred_b_digest, root_b).unwrap();

        let mut wire = state.to_wire(&schema).unwrap();
        assert_eq!(wire.leaf_tags.len(), 2, "fixture should have two leaves");
        assert_eq!(wire.nodes.len(), 4, "fixture should have two predicates and two ANDs");

        wire.blocks.swap(0, 1);
        // Preserve the same reconstructed DAG/root under the swapped leaf section by updating the
        // predicate indices. The result is semantically valid but not the canonical serializer's
        // first-visit order.
        wire.nodes[0].lhs = 2;
        wire.nodes[0].rhs = 2;
        wire.nodes[2].lhs = 1;
        wire.nodes[2].rhs = 1;

        let err = DeferredState::rehydrate(&wire, &schema);
        assert!(
            matches!(err, Err(IntegrityError::NonCanonicalWire)),
            "expected NonCanonicalWire, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        // Build a chain whose statement is `eq(leaf(3), leaf(4))` — disagreeing leaves.
        // Phase 2's evaluate returns AssertionFailed, surfaced as `PredicateFailed`.
        let mut state = DeferredState::new();
        let schema = precompiles();
        let a = state.register(&schema, test_leaf(3)).unwrap();
        let b = state.register(&schema, test_leaf(4)).unwrap();
        // Hand-roll a chain that points to a failing predicate without first evaluating the
        // predicate (which would reject ahead of time).
        let bad_pred = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = bad_pred.digest();
        state.intern(bad_pred);
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.intern(and_node);
        state.root = and_digest;

        let wire = state.to_wire(&schema).unwrap();
        let err = DeferredState::rehydrate(&wire, &schema);
        assert!(
            matches!(err, Err(IntegrityError::PredicateFailed(_))),
            "expected PredicateFailed, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_non_and_prev_root() {
        // The sectioned binary wire cannot encode a missing child digest: every binary edge is an
        // index. It can still encode a malformed transcript whose previous root is present but is
        // not itself an AND-chain node. Phase 2 rejects that when it walks to the leaf root.
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            leaf_tags: alloc::vec![a.tag],
            blocks: alloc::vec![a_payload],
            nodes: alloc::vec![
                crate::deferred::WireNode { tag: pred.tag, lhs: 1, rhs: 1 },
                crate::deferred::WireNode { tag: Tag::AND, lhs: 1, rhs: 2 },
            ],
            ..Default::default()
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::NonAndNode)),
            "expected NonAndNode, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_dangling_entry() {
        // A faithful chain (leaf a → eq(a, a) predicate → AND-node) plus an orphan leaf that
        // nothing references. Phase 1 interns all four; the reachability check (before phase 2)
        // finds the orphan outside the root's registry-declared closure and rejects it.
        //
        // Global indices:
        //   [0] TRUE
        //   [1] leaf a = test_leaf(7)
        //   [2] orphan = test_leaf(99)           — dangling: unreferenced
        //   [3] predicate eq(a, a)               — binary { lhs: 1, rhs: 1 }
        //   [4] AND { Tag::AND, (TRUE, pred) }    — binary { lhs: TRUE_INDEX, rhs: 3 }
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let orphan = test_leaf(99);
        let orphan_payload = *orphan.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            leaf_tags: alloc::vec![a.tag, orphan.tag],
            blocks: alloc::vec![a_payload, orphan_payload],
            nodes: alloc::vec![
                crate::deferred::WireNode { tag: pred.tag, lhs: 1, rhs: 1 },
                crate::deferred::WireNode {
                    tag: Tag::AND,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: 3,
                },
            ],
            ..Default::default()
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::DanglingNode)),
            "expected DanglingNode, got {err:?}"
        );
    }
}
