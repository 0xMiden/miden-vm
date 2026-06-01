use alloc::collections::BTreeMap;

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodeType, PrecompileError,
    PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory witness for deferred-DAG verification.
///
/// The state keeps committed nodes, host-side reduction memos, and the current transcript root.
/// Reduction memos are valid only under the same [`PrecompileRegistry`] semantics used to populate
/// them. The state is intentionally not serialized directly: proofs carry [`DeferredStateWire`],
/// and [`Self::rehydrate`] rebuilds this state only after `PrecompileRegistry` checks,
/// reachability checks, and transcript re-evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    evals: BTreeMap<Digest, Node>,
    num_elements: usize,
}

impl Default for DeferredState {
    fn default() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);

        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, Node::TRUE);

        Self {
            nodes,
            root: TRUE_DIGEST,
            evals,
            num_elements: 0,
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
    /// [`TRUE_DIGEST`] is always present and maps to [`Node::TRUE`].
    pub fn contains(&self, digest: &Digest) -> bool {
        self.nodes.contains_key(digest)
    }

    /// Interns a node by digest after validating its tag, payload shape, and child closure.
    ///
    /// This is used by framework-owned construction paths that need to materialize canonical
    /// helper nodes without reducing them again.
    pub(crate) fn intern(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Digest, PrecompileError> {
        self.validate_node_for_insertion(precompiles, &node)?;
        Ok(self.insert_node_counted(node))
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    /// Returns the approximate number of field elements stored by deferred nodes and eval memos.
    pub fn num_elements(&self) -> usize {
        self.num_elements
    }

    fn get_eval(&self, digest: &Digest) -> Option<&Node> {
        self.evals.get(digest)
    }

    fn add_elements(&mut self, elements: usize) {
        self.num_elements = self.num_elements.saturating_add(elements);
    }

    fn insert_node_counted(&mut self, node: Node) -> Digest {
        let digest = node.digest();
        if !self.nodes.contains_key(&digest) {
            self.add_elements(node.num_elements());
        }
        self.nodes.insert(digest, node);
        digest
    }

    /// Caches a reduction result and materializes its canonical node for downstream references.
    fn record_eval(
        &mut self,
        precompiles: &PrecompileRegistry,
        input_digest: Digest,
        canonical: Node,
    ) -> Result<(), PrecompileError> {
        self.validate_node_for_insertion(precompiles, &canonical)?;
        if !self.evals.contains_key(&input_digest) {
            self.add_elements(canonical.num_elements());
        }
        self.evals.insert(input_digest, canonical.clone());
        self.insert_node_counted(canonical);
        Ok(())
    }

    /// Returns the current transcript root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Appends a statement commitment to the transcript after proving it reduces to TRUE.
    ///
    /// The statement digest must already be materialized in `nodes`, unless it is the implicit
    /// [`TRUE_DIGEST`]. Evaluation may populate the registry-bound eval cache and materialize
    /// canonical helper nodes.
    pub fn append_statement(
        &mut self,
        precompiles: &PrecompileRegistry,
        stmt_digest: Digest,
    ) -> Result<Digest, PrecompileError> {
        let new_root = self.checked_append_root(precompiles, stmt_digest)?;
        self.append_statement_unchecked(stmt_digest, new_root)?;
        Ok(new_root)
    }

    /// Checked statement append with an expected in-circuit root.
    ///
    /// This performs the same semantic checks as [`Self::append_statement`] but leaves the
    /// transcript root unchanged if the computed root disagrees with `expected_new_root`.
    pub fn append_statement_with_expected_root(
        &mut self,
        precompiles: &PrecompileRegistry,
        stmt_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<(), PrecompileError> {
        let new_root = self.checked_append_root(precompiles, stmt_digest)?;
        if new_root != expected_new_root {
            return Err(DeferredError::InvalidPayload.into());
        }
        self.append_statement_unchecked(stmt_digest, new_root)?;
        Ok(())
    }

    fn checked_append_root(
        &mut self,
        precompiles: &PrecompileRegistry,
        stmt_digest: Digest,
    ) -> Result<Digest, PrecompileError> {
        let canonical = self.evaluate_statement_digest(precompiles, stmt_digest)?;
        if !canonical.is_true_node() {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(Node::and(self.root, stmt_digest).digest())
    }

    /// Appends a statement commitment to the transcript without semantic validation.
    ///
    /// This path exists only for replay and in-circuit root mirroring. It checks the expected root
    /// against the current root and statement digest, then materializes the framework AND node.
    pub(crate) fn append_statement_unchecked(
        &mut self,
        stmt_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<(), DeferredError> {
        let and_node = Node::and(self.root, stmt_digest);
        let actual = and_node.digest();
        if actual != expected_new_root {
            return Err(DeferredError::InvalidPayload);
        }
        self.insert_node_counted(and_node);
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
        self.validate_node_for_insertion(precompiles, &node)?;
        Ok(self.insert_node_counted(node))
    }

    fn validate_node_for_insertion(
        &self,
        precompiles: &PrecompileRegistry,
        node: &Node,
    ) -> Result<NodeType, PrecompileError> {
        let node_type = precompiles.validate_node(node)?;
        self.validate_join_children_present(node_type, node)?;
        Ok(node_type)
    }

    fn validate_join_children_present(
        &self,
        node_type: NodeType,
        node: &Node,
    ) -> Result<(), PrecompileError> {
        if node_type != NodeType::Join {
            return Ok(());
        }
        let (lhs, rhs) = node.payload.join_children()?;
        for child in [lhs, rhs] {
            if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                return Err(PrecompileError::MissingNode);
            }
        }
        Ok(())
    }

    /// Registers a concrete node and then reduces it by digest.
    ///
    /// This is the public convenience path for callers that have a concrete node value but want
    /// the durable, serializable semantics of digest-addressed evaluation.
    pub fn evaluate_node(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Node, PrecompileError> {
        let digest = self.register(precompiles, node)?;
        self.evaluate_digest(precompiles, digest)
    }

    /// Reduces an already-committed node through the precompile registry and caches its canonical
    /// form.
    ///
    /// Child digests must already be committed in the DAG, so the same witness can be serialized
    /// and rehydrated. Predicate success returns [`Node::TRUE`]; mismatch returns
    /// [`PrecompileError::AssertionFailed`].
    fn evaluate_registered_node(
        &mut self,
        precompiles: &PrecompileRegistry,
        node: Node,
    ) -> Result<Node, PrecompileError> {
        self.validate_node_for_insertion(precompiles, &node)?;
        let input_digest = node.digest();
        if node.tag == Tag::TRUE {
            self.record_eval(precompiles, input_digest, Node::TRUE)?;
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
        self.record_eval(precompiles, input_digest, Node::TRUE)?;
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
        self.evaluate_registered_node(precompiles, node)
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
    pub fn intern(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.state.intern(self.precompiles, node)
    }

    /// Reduces a node, memoizes the canonical form, and commits the canonical node.
    fn reduce_and_record_eval(
        &mut self,
        node: Node,
        input_digest: Digest,
    ) -> Result<Node, PrecompileError> {
        let precompiles = self.precompiles;
        let canonical = precompiles.reduce(&node, self)?;
        self.state.record_eval(precompiles, input_digest, canonical.clone())?;
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{PrecompileRegistry, TRUE_DIGEST, Tag, WireEntry},
        testing::precompile::{Hash, Uint},
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
        let registry = precompiles();

        assert_eq!(state.nodes().len(), 1);
        assert!(state.contains(&TRUE_DIGEST));
        assert_eq!(state.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.num_elements(), 0);
        assert_eq!(state.evaluate_digest(&registry, TRUE_DIGEST).unwrap(), Node::TRUE);
        assert_eq!(state.num_elements(), 0);
    }

    #[test]
    fn register_true_is_idempotent() {
        let mut state = DeferredState::new();
        let registry = precompiles();

        let digest = state.register(&registry, Node::TRUE).unwrap();
        assert_eq!(digest, TRUE_DIGEST);
        assert_eq!(state.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.nodes().len(), 1);
        assert_eq!(state.num_elements(), 0);
    }

    #[test]
    fn append_statement_advances_root_with_and_node() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt_digest = state.register(&registry, pred).unwrap();

        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
        let actual = state.append_statement(&registry, stmt_digest).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(expected, TRUE_DIGEST);
        assert_eq!(state.root(), expected);
        assert!(state.contains(&expected));
        assert_eq!(state.get(&expected).unwrap().tag, Tag::AND);
    }

    #[test]
    fn append_statement_rejects_wrong_expected_root() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let bogus_root = dummy_digest(42);
        let pre_root = state.root();
        let pre_node_count = state.nodes().len();
        let err = state.append_statement_with_expected_root(&registry, TRUE_DIGEST, bogus_root);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::Other(_)));
        assert_eq!(state.root(), pre_root, "root must remain unchanged on failure");
        assert_eq!(state.nodes().len(), pre_node_count, "no node interned on failure");
    }

    #[test]
    fn append_statement_rejects_missing_statement() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let err = state.append_statement(&registry, dummy_digest(7));
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn append_statement_rejects_statement_that_is_not_true() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let leaf = state.register(&registry, test_leaf(7)).unwrap();
        let err = state.append_statement(&registry, leaf);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn append_statement_unchecked_only_checks_expected_root() {
        let mut state = DeferredState::new();
        let stmt_digest = dummy_digest(7);
        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
        state.append_statement_unchecked(stmt_digest, expected).unwrap();
        assert_eq!(state.root(), expected);
        assert!(state.contains(&expected));
    }

    #[test]
    fn register_leaf_stores_it() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let node = test_leaf(7);
        let digest = state.register(&registry, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.get(&digest).unwrap(), &node);
        assert_eq!(state.num_elements(), node.num_elements());
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let node = test_leaf(7);
        let d1 = state.register(&registry, node.clone()).unwrap();
        let d2 = state.register(&registry, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes().len(), 2); // TRUE plus the leaf
        assert_eq!(state.num_elements(), test_leaf(7).num_elements());
    }

    #[test]
    fn chunk_nodes_contribute_payload_length_to_num_elements() {
        let mut state = DeferredState::new();
        let registry = PrecompileRegistry::default().with_precompile(Hash);
        let chunks = alloc::vec![[Felt::from_u32(1); 8], [Felt::from_u32(2); 8]];
        let node = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks);
        let expected_elements = node.num_elements();

        let digest = state.register(&registry, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(expected_elements, 20);
        assert_eq!(state.num_elements(), expected_elements);

        state.register(&registry, node).unwrap();
        assert_eq!(state.num_elements(), expected_elements, "idempotent re-registration is free");
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        // Uint id + unknown discriminant: registry decode returns Err.
        let bad_tag = Tag {
            id: Uint::id(),
            args: [Felt::from_u32(99), ZERO, ZERO],
        };
        let bad = Node::leaf(bad_tag, [Felt::from_u32(0); 8]);
        let err = state.register(&registry, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn register_join_requires_materialized_children() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let missing = dummy_digest(99);

        let err = state.register(&registry, Node::join(Uint::add_tag(), a, missing));
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // `register` is a pure host hint — it interns the predicate node without driving reduce.
        // Programs that want host-side verification call `evaluate`; programs that want
        // constrained verification call checked append.
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = state.register(&registry, bad.clone()).unwrap();
        assert!(state.contains(&bad_digest), "predicate interned even when it doesn't hold");
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate_node(&registry, bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_reports_success_and_child_failures() {
        let registry = precompiles();
        let mut state = DeferredState::new();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let b = state.register(&registry, test_leaf(8)).unwrap();

        let ok = state.evaluate_node(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();
        assert!(ok.is_true_node(), "predicate success returns the canonical TRUE node");

        let mismatch = state.evaluate_node(&registry, Node::join(Uint::eq_tag(), a, b));
        assert!(matches!(mismatch.unwrap_err().root(), PrecompileError::AssertionFailed));

        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let missing = state.evaluate_node(&registry, Node::join(Uint::eq_tag(), a, dangling));
        assert!(matches!(missing.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn evaluate_interns_canonicals_into_nodes() {
        // Register the full op tree (a + b) * c == 35 plus an orphan leaf, evaluate the
        // predicate, and assert evaluate interns computed canonicals into `state.nodes`.
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        let c = state.register(&registry, test_leaf(5)).unwrap();
        let expected = state.register(&registry, test_leaf(35)).unwrap();
        let _orphan = state.register(&registry, test_leaf(99)).unwrap();
        let add = state.register(&registry, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&registry, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let assertion_digest = assertion.digest();
        state.evaluate_node(&registry, assertion).unwrap();

        assert!(state.contains(&assertion_digest), "evaluate_node registers the input");
        assert!(state.contains(&test_leaf(7).digest()), "canonical(add) is interned into nodes");
        assert!(state.contains(&Node::TRUE.digest()), "canonical(TRUE) remains in nodes");
        assert_eq!(state.root(), TRUE_DIGEST, "no append called, root is still TRUE");
    }

    #[test]
    fn evaluate_node_registers_input_and_interns_canonical() {
        // Build (a+b)*c, pre-register only the leaves and `add`. The outer `mul` is registered by
        // the convenience API before digest-addressed evaluation, and its canonical is interned.
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        let c = state.register(&registry, test_leaf(5)).unwrap();
        let add = Node::join(Uint::add_tag(), a, b);
        let add_digest = state.register(&registry, add).unwrap();
        let mul = Node::join(Uint::mul_tag(), add_digest, c);
        let mul_digest = mul.digest();

        let canonical = state.evaluate_node(&registry, mul).unwrap();
        assert_eq!(canonical, test_leaf(35));
        assert!(state.contains(&mul_digest), "input op is registered before evaluation");
        assert!(state.contains(&test_leaf(35).digest()), "computed canonical is interned");
        assert_eq!(state.evaluate_digest(&registry, mul_digest).unwrap(), test_leaf(35));
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
            "canonical to_wire output must round-trip deterministically"
        );
    }

    /// Builds a logged `(a+b)*c == 35` transcript used by round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        let c = state.register(&registry, test_leaf(5)).unwrap();
        let expected = state.register(&registry, test_leaf(35)).unwrap();
        let add = state.register(&registry, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&registry, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let stmt_digest = state.register(&registry, assertion).unwrap();
        state.append_statement(&registry, stmt_digest).unwrap();
        // Defense-in-depth: every fixture consumer inherits a wire round-trip self-check, so any
        // future change that breaks `to_wire`/`rehydrate` consistency fails loudly here.
        assert_round_trips(&state, &precompiles());
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let registry = precompiles();
        let wire = original.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &registry).unwrap();
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
        let registry = precompiles();
        state.register(&registry, Node::TRUE).unwrap();

        let wire = state.to_wire(&registry).unwrap();
        assert_eq!(wire, DeferredStateWire::default());
    }

    #[test]
    fn rehydrate_rejects_materialized_true_entries() {
        let wires = [
            DeferredStateWire {
                entries: alloc::vec![WireEntry::Value { tag: Tag::TRUE, block: [ZERO; 8] }],
            },
            DeferredStateWire {
                entries: alloc::vec![WireEntry::Join {
                    tag: Tag::TRUE,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: crate::deferred::TRUE_INDEX,
                }],
            },
        ];

        for wire in wires {
            let err = DeferredState::rehydrate(&wire, &precompiles());
            assert!(
                matches!(err, Err(IntegrityError::MaterializedTrue)),
                "expected MaterializedTrue, got {err:?}"
            );
        }
    }

    #[test]
    fn rehydrate_accepts_logged_empty_transcript_root() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let new_root = state.append_statement(&registry, TRUE_DIGEST).unwrap();
        assert_ne!(new_root, TRUE_DIGEST);
        assert_eq!(state.get(&new_root).unwrap().tag, Tag::AND);

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &registry).unwrap();
        assert_eq!(rehydrated.root(), new_root);
        assert_eq!(rehydrated.statements(), alloc::vec![TRUE_DIGEST]);
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_accepts_logged_nested_transcript_root() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let pred_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();

        let inner_root = state.register(&registry, Node::and(TRUE_DIGEST, pred_digest)).unwrap();
        let outer_root = state.append_statement(&registry, inner_root).unwrap();

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &registry).unwrap();
        assert_eq!(rehydrated.root(), outer_root);
        assert_eq!(rehydrated.statements(), alloc::vec![inner_root]);
        assert!(rehydrated.contains(&inner_root));
        assert!(rehydrated.contains(&pred_digest));
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // Entry 1 cannot reference itself/future index 1 while it is being decoded.
        let wire = DeferredStateWire {
            entries: alloc::vec![WireEntry::Join { tag: Uint::add_tag(), lhs: 1, rhs: 0 }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::BadIndex)));
    }

    #[test]
    fn rehydrate_rejects_duplicate_digest_in_any_entry() {
        let leaf = test_leaf(7);
        let payload = *leaf.payload.as_felts().expect("leaf is expression-bodied");
        let wires = [
            DeferredStateWire {
                entries: alloc::vec![
                    WireEntry::Value { tag: leaf.tag, block: payload },
                    WireEntry::Value { tag: leaf.tag, block: payload },
                ],
            },
            DeferredStateWire {
                entries: alloc::vec![
                    WireEntry::Value { tag: leaf.tag, block: payload },
                    WireEntry::Join { tag: Uint::eq_tag(), lhs: 1, rhs: 1 },
                    WireEntry::Join { tag: Uint::eq_tag(), lhs: 1, rhs: 1 },
                ],
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
            entries: alloc::vec![WireEntry::Value { tag: leaf.tag, block: payload }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::NonAndNode)),
            "expected NonAndNode, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        let bogus_tag = Tag {
            id: Felt::new_unchecked(0xdead),
            args: [ZERO; 3],
        };
        let wire = DeferredStateWire {
            entries: alloc::vec![WireEntry::Value { tag: bogus_tag, block: [ZERO; 8] }],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(matches!(err, Err(IntegrityError::UnknownTag)));
    }

    #[test]
    fn rehydrate_rejects_malformed_chunk_entries() {
        let wrong_variant = DeferredStateWire {
            entries: alloc::vec![WireEntry::Chunks {
                tag: Uint::leaf_tag(),
                blocks: alloc::vec![[ZERO; 8]],
            }],
        };
        let err = DeferredState::rehydrate(&wrong_variant, &precompiles());
        assert!(matches!(err, Err(IntegrityError::ShapeMismatch)));

        let registry = PrecompileRegistry::default().with_precompile(Hash);
        let wrong_count = DeferredStateWire {
            entries: alloc::vec![WireEntry::Chunks {
                tag: Hash::preimage_tag(Hash::BYTES_PER_CHUNK),
                blocks: alloc::vec![],
            }],
        };
        let err = DeferredState::rehydrate(&wrong_count, &registry);
        assert!(matches!(err, Err(IntegrityError::ShapeMismatch)));
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_leaves() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let _orphan = state.register(&registry, test_leaf(99)).unwrap();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let stmt_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();
        let new_root = state.append_statement(&registry, stmt_digest).unwrap();
        assert_round_trips(&state, &registry);

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::rehydrate(&wire, &registry).unwrap();
        let orphan_digest = test_leaf(99).digest();
        assert!(
            !rehydrated.contains(&orphan_digest),
            "orphan must be trimmed from wire and absent after rehydrate"
        );
        assert!(rehydrated.contains(&new_root), "AND-node must be in rehydrated state");
        assert!(rehydrated.contains(&stmt_digest), "stmt predicate must be in rehydrated state");
        assert!(rehydrated.contains(&a), "stmt's operand must be in rehydrated state");
    }

    #[test]
    fn rehydrate_accepts_noncanonical_but_topological_wire() {
        let a = test_leaf(3);
        let b = test_leaf(4);
        let a_payload = *a.payload.as_felts().unwrap();
        let b_payload = *b.payload.as_felts().unwrap();
        let pred_a = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let pred_a_digest = pred_a.digest();
        let root_a = Node::and(TRUE_DIGEST, pred_a_digest).digest();
        let pred_b = Node::join(Uint::eq_tag(), b.digest(), b.digest());
        let pred_b_digest = pred_b.digest();
        let root_b = Node::and(root_a, pred_b_digest).digest();

        // This is semantically equivalent to canonical output, but it emits `b` before the first
        // transcript step's closure. The stream remains topological and root-last.
        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry::Value { tag: b.tag, block: b_payload },
                WireEntry::Value { tag: a.tag, block: a_payload },
                WireEntry::Join { tag: pred_a.tag, lhs: 2, rhs: 2 },
                WireEntry::Join {
                    tag: Tag::AND,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: 3
                },
                WireEntry::Join { tag: pred_b.tag, lhs: 1, rhs: 1 },
                WireEntry::Join { tag: Tag::AND, lhs: 4, rhs: 5 },
            ],
        };

        let rehydrated = DeferredState::rehydrate(&wire, &precompiles()).unwrap();
        assert_eq!(rehydrated.root(), root_b);
        assert_eq!(rehydrated.statements(), alloc::vec![pred_a_digest, pred_b_digest]);
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();

        let bad_pred = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = bad_pred.digest();
        state.insert_node_counted(bad_pred);
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.insert_node_counted(and_node);
        state.root = and_digest;

        let wire = state.to_wire(&registry).unwrap();
        let err = DeferredState::rehydrate(&wire, &registry);
        assert!(
            matches!(err, Err(IntegrityError::PredicateFailed(_))),
            "expected PredicateFailed, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_predicate_not_true() {
        let mut state = DeferredState::new();
        let registry = precompiles();
        let leaf = state.register(&registry, test_leaf(3)).unwrap();
        let and_node = Node::and(TRUE_DIGEST, leaf);
        let and_digest = and_node.digest();
        state.insert_node_counted(and_node);
        state.root = and_digest;

        let wire = state.to_wire(&registry).unwrap();
        let err = DeferredState::rehydrate(&wire, &registry);
        assert!(
            matches!(err, Err(IntegrityError::PredicateNotTrue)),
            "expected PredicateNotTrue, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_non_and_prev_root() {
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry::Value { tag: a.tag, block: a_payload },
                WireEntry::Join { tag: pred.tag, lhs: 1, rhs: 1 },
                WireEntry::Join { tag: Tag::AND, lhs: 1, rhs: 2 },
            ],
        };
        let err = DeferredState::rehydrate(&wire, &precompiles());
        assert!(
            matches!(err, Err(IntegrityError::NonAndNode)),
            "expected NonAndNode, got {err:?}"
        );
    }

    #[test]
    fn rehydrate_rejects_dangling_entry() {
        let a = test_leaf(7);
        let a_payload = *a.payload.as_felts().expect("leaf is expression-bodied");
        let orphan = test_leaf(99);
        let orphan_payload = *orphan.payload.as_felts().expect("leaf is expression-bodied");
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());

        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry::Value { tag: orphan.tag, block: orphan_payload },
                WireEntry::Value { tag: a.tag, block: a_payload },
                WireEntry::Join { tag: pred.tag, lhs: 2, rhs: 2 },
                WireEntry::Join {
                    tag: Tag::AND,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: 3,
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
