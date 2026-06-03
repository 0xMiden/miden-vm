use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodeType, PrecompileError,
    PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory witness for deferred-DAG verification.
///
/// The state keeps registered nodes, host-side evaluation memos, and the current transcript root.
/// Evaluation memos are valid only under the same [`PrecompileRegistry`] semantics used to populate
/// them. The state is intentionally not serialized directly: proofs carry [`DeferredStateWire`],
/// and [`Self::from_wire`] rebuilds this state only after registry checks, canonical wire checks,
/// expected-root matching, and root evaluation.
#[derive(Debug, Clone)]
pub struct DeferredState {
    registry: Arc<PrecompileRegistry>,
    nodes: BTreeMap<Digest, Node>,
    pub(super) root: Digest,
    evals: BTreeMap<Digest, Digest>,
    remaining_elements: usize,
}

impl Default for DeferredState {
    fn default() -> Self {
        Self::new(Arc::new(PrecompileRegistry::new()), usize::MAX)
            .expect("empty registry initialization cannot fail")
    }
}

impl DeferredState {
    pub fn new(
        registry: Arc<PrecompileRegistry>,
        max_elements: usize,
    ) -> Result<Self, PrecompileError> {
        let mut state = Self::empty(registry, max_elements);
        state.initialize_precompile_nodes()?;
        Ok(state)
    }

    /// Creates a state seeded only with framework basics.
    fn empty(registry: Arc<PrecompileRegistry>, max_elements: usize) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);

        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, TRUE_DIGEST);

        Self {
            registry,
            nodes,
            root: TRUE_DIGEST,
            evals,
            remaining_elements: max_elements,
        }
    }

    /// Loads all precompile initialization nodes, then evaluates each to ensure the bootstrap set
    /// resolves under this registry.
    fn initialize_precompile_nodes(&mut self) -> Result<(), PrecompileError> {
        let init_nodes = self.registry.init_nodes();
        let init_digests: Vec<Digest> = init_nodes.iter().map(Node::digest).collect();

        // Load the complete set before enforcing child closure. This lets init nodes depend on
        // TRUE or on any other node in the complete init set, independent of registry order.
        for node in init_nodes {
            self.registry.validate_node(&node)?;
            self.insert_node(node)?;
        }

        for digest in init_digests {
            self.evaluate(digest)?;
        }

        Ok(())
    }

    /// Add deferred precompiles to this state without discarding existing nodes, evals, root, or
    /// budget accounting.
    ///
    /// Registration is additive only: duplicate precompile ids panic via
    /// [`PrecompileRegistry::merge`], matching setup-time registry construction behavior. The
    /// state is cloned before mutation so failed precompile initialization leaves `self`
    /// unchanged.
    pub fn extend_precompiles(
        &mut self,
        precompiles: PrecompileRegistry,
    ) -> Result<(), PrecompileError> {
        let mut next = self.clone();
        Arc::make_mut(&mut next.registry).merge(precompiles);
        next.initialize_precompile_nodes()?;

        *self = next;
        Ok(())
    }

    pub fn registry(&self) -> &PrecompileRegistry {
        &self.registry
    }

    pub fn node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    pub fn nodes(&self) -> impl Iterator<Item = (&Digest, &Node)> + '_ {
        self.nodes.iter()
    }

    pub fn eval(&self, digest: &Digest) -> Option<Digest> {
        self.evals.get(digest).copied()
    }

    pub fn evals(&self) -> impl Iterator<Item = (&Digest, &Digest)> + '_ {
        self.evals.iter()
    }

    pub fn remaining_elements(&self) -> usize {
        self.remaining_elements
    }

    pub fn decode(&self, tag: Tag) -> Result<NodeType, PrecompileError> {
        if tag == Tag::TRUE {
            Ok(NodeType::True)
        } else if tag == Tag::AND {
            Ok(NodeType::Join)
        } else {
            self.registry.decode(tag)
        }
    }

    fn insert_node(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        let digest = node.digest();
        match self.nodes.get(&digest) {
            Some(existing) if existing == &node => Ok(digest),
            Some(_) => Err(DeferredError::ConflictingNode.into()),
            None => {
                let required = node.storage_felt_len();
                self.remaining_elements = self.remaining_elements.checked_sub(required).ok_or(
                    DeferredError::DeferredStateTooLarge {
                        num_elements: required,
                        max: self.remaining_elements,
                    },
                )?;
                self.nodes.insert(digest, node);
                Ok(digest)
            },
        }
    }

    /// Records an evaluation memo and stores its canonical node in `nodes` for downstream
    /// references.
    fn record_eval(
        &mut self,
        input_digest: Digest,
        canonical: Node,
    ) -> Result<(), PrecompileError> {
        if !self.nodes.contains_key(&input_digest) {
            return Err(PrecompileError::MissingNode);
        }
        self.validate_node_for_insertion(&canonical)?;
        let canonical_digest = self.insert_node(canonical)?;
        match self.evals.get(&input_digest) {
            Some(existing) if *existing == canonical_digest => Ok(()),
            Some(_) => Err(DeferredError::ConflictingNode.into()),
            None => {
                self.evals.insert(input_digest, canonical_digest);
                Ok(())
            },
        }
    }

    /// Returns the current transcript root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Appends a statement commitment to the transcript after proving it evaluates to TRUE.
    ///
    /// The statement digest must already be registered (present in `nodes`), unless it is the
    /// implicit [`TRUE_DIGEST`]. Evaluation may populate the registry-bound eval cache and store
    /// canonical/helper nodes in `nodes`.
    pub fn append_statement(&mut self, stmt_digest: Digest) -> Result<Digest, PrecompileError> {
        let canonical = self.evaluate(stmt_digest)?;
        if !canonical.is_true_node() {
            return Err(PrecompileError::AssertionFailed);
        }

        let and_node = Node::and(self.root, stmt_digest);
        let new_root = and_node.digest();
        self.insert_node(and_node)?;
        self.root = new_root;
        Ok(new_root)
    }

    /// Registers a `PrecompileRegistry`-valid node in the DAG without evaluating it.
    ///
    /// Registration lets later nodes reference this digest and lets predicates be logged, but it
    /// does not prove predicate truth. Verification happens only through evaluation or through
    /// the rehydration check of a logged transcript.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.validate_node_for_insertion(&node)?;
        self.insert_node(node)
    }

    fn validate_node_for_insertion(&self, node: &Node) -> Result<NodeType, PrecompileError> {
        let node_type = self.registry.validate_node(node)?;
        if let Some((lhs, rhs)) = node_type.children(node.payload())? {
            for child in [lhs, rhs] {
                if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                    return Err(PrecompileError::MissingNode);
                }
            }
        }
        Ok(node_type)
    }

    /// Evaluates a registered node addressed by digest.
    ///
    /// The memo is used only after the digest is proven present in `nodes`; memo entries alone do
    /// not create durable DAG membership. Predicate success returns [`Node::TRUE`]; mismatch
    /// returns [`PrecompileError::AssertionFailed`].
    pub fn evaluate(&mut self, digest: Digest) -> Result<Node, PrecompileError> {
        let node = self.nodes.get(&digest).ok_or(PrecompileError::MissingNode)?.clone();
        if let Some(canonical_digest) = self.evals.get(&digest) {
            return self.nodes.get(canonical_digest).cloned().ok_or(PrecompileError::MissingNode);
        }

        self.validate_node_for_insertion(&node)?;
        let canonical = if node.tag() == Tag::TRUE {
            Node::TRUE
        } else if node.tag() == Tag::AND {
            let (lhs, rhs) = node.payload().as_join()?;
            for child in [lhs, rhs] {
                if !self.evaluate(child)?.is_true_node() {
                    return Err(PrecompileError::AssertionFailed);
                }
            }
            Node::TRUE
        } else {
            let registry = Arc::clone(&self.registry);
            let mut context = DeferredContext::new(self);
            registry.evaluate(&node, &mut context)?
        };

        self.record_eval(digest, canonical.clone())?;
        Ok(canonical)
    }

    /// Serializes the root-reachable DAG into compact canonical wire form.
    ///
    /// Only nodes reachable from `root` are emitted; registered or memoized orphans are dropped.
    /// The installed `PrecompileRegistry` determines each node's shape, so graph edges are never
    /// inferred from opaque payload bytes.
    pub fn to_wire(&self) -> Result<DeferredStateWire, IntegrityError> {
        DeferredStateWire::from_state(self)
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    ///
    /// The wire root is implicit: empty wire opens [`TRUE_DIGEST`], otherwise the root is the
    /// digest of the final entry. Rehydration rejects non-canonical or dangling wire, then
    /// evaluates the implicit root to TRUE under the installed precompiles. Callers that need
    /// proof binding should compare the returned [`Self::root`] against the externally
    /// committed root.
    pub fn from_wire(
        registry: Arc<PrecompileRegistry>,
        wire: &DeferredStateWire,
        max_elements: usize,
    ) -> Result<Self, IntegrityError> {
        wire.rehydrate(registry, max_elements)
    }

    /// Returns logged statement digests in execution order for already-verified test states.
    ///
    /// Panics if the chain is malformed; production callers should obtain states through
    /// [`Self::from_wire`], which validates the chain first.
    #[cfg(test)]
    pub fn statements(&self) -> Vec<Digest> {
        use alloc::vec::Vec;

        let mut out = Vec::new();
        let mut cur = self.root;
        while cur != TRUE_DIGEST {
            let and_node = self
                .nodes
                .get(&cur)
                .expect("statements(): AND-chain references a node not in state");
            debug_assert_eq!(
                and_node.tag(),
                Tag::AND,
                "statements(): AND-chain step is not tagged Tag::AND"
            );
            let (prev_root, stmt_digest) =
                and_node.payload().as_join().expect("statements(): AND-node has non-join body");
            out.push(stmt_digest);
            cur = prev_root;
        }
        out.reverse();
        out
    }
}

// DEFERRED CONTEXT
// ================================================================================================

/// Capability object passed to precompiles during recursive evaluation.
///
/// Precompiles do not own the DAG; they receive this handle to resolve registered children and to
/// register helper nodes referenced by compound canonicals. The verifier reuses the same path
/// during [`DeferredState::from_wire`], so prover and verifier agree on how witnesses are
/// reconstructed.
pub struct DeferredContext<'a> {
    state: &'a mut DeferredState,
}

impl<'a> DeferredContext<'a> {
    /// Binds state for one framework-driven evaluation.
    pub(crate) fn new(state: &'a mut DeferredState) -> Self {
        Self { state }
    }

    /// Resolves a registered child digest by evaluating it to its canonical node.
    ///
    /// The `nodes` membership check keeps local evaluation reproducible by `to_wire` and
    /// rehydration; memo hits are used only after that membership is established.
    pub fn resolve(&mut self, digest: Digest) -> Result<Node, PrecompileError> {
        self.state.evaluate(digest)
    }

    /// Registers a freshly minted helper node and returns its digest.
    ///
    /// Use this when a compound canonical needs stable child commitments that were created during
    /// evaluation.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.state.register(node)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec::Vec};

    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{Precompile, PrecompileRegistry, TRUE_DIGEST, Tag, WireEntry},
        testing::precompile::{Hash, Uint},
    };

    /// Single-precompile registry used by deferred-state unit tests.
    fn precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(PrecompileRegistry::default().with_precompile(Uint))
    }

    fn hash_precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(PrecompileRegistry::default().with_precompile(Hash))
    }

    fn empty_precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(PrecompileRegistry::new())
    }

    fn state_with(registry: &Arc<PrecompileRegistry>, max_elements: usize) -> DeferredState {
        DeferredState::new(Arc::clone(registry), max_elements).unwrap()
    }

    fn test_value(value: u32) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value;
        Uint::value_node(limbs)
    }

    fn dummy_digest(seed: u64) -> Word {
        Word::new(core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64)))
    }

    fn value_entry(node: &Node) -> WireEntry {
        WireEntry::Data {
            tag: node.tag(),
            chunks: node.payload().as_data().expect("test node is data").to_vec(),
        }
    }

    fn wire(entries: Vec<WireEntry>) -> DeferredStateWire {
        DeferredStateWire { entries }
    }

    macro_rules! assert_rehydrate_err {
        ($wire:expr, $registry:expr, $pat:pat $(,)?) => {{
            let result = DeferredState::from_wire($registry, &$wire, usize::MAX);
            let expected = stringify!($pat);
            assert!(matches!(&result, Err($pat)), "expected {expected}, got {result:?}");
        }};
    }

    #[test]
    fn true_node_is_seeded_and_registering_it_is_free() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);

        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.nodes.get(&TRUE_DIGEST), Some(&Node::TRUE));
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.remaining_elements, usize::MAX);
        assert_eq!(state.evaluate(TRUE_DIGEST).unwrap(), Node::TRUE);

        let digest = state.register(Node::TRUE).unwrap();
        assert_eq!(digest, TRUE_DIGEST);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.remaining_elements, usize::MAX);
    }

    #[test]
    fn append_statement_advances_root_with_and_node() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a).unwrap();
        let stmt_digest = state.register(pred).unwrap();

        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
        let actual = state.append_statement(stmt_digest).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(expected, TRUE_DIGEST);
        assert_eq!(state.root(), expected);
        assert!(state.nodes.contains_key(&expected));
        assert_eq!(state.nodes.get(&expected).unwrap().tag(), Tag::AND);
    }

    #[test]
    fn append_statement_rejects_missing_statement() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let err = state.append_statement(dummy_digest(7));
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn append_statement_rejects_statement_that_is_not_true() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let value_digest = state.register(test_value(7)).unwrap();
        let err = state.append_statement(value_digest);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn register_value_stores_once_and_reinsert_is_free() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let node = test_value(7);
        let before_len = state.nodes.len();
        let before_remaining = state.remaining_elements;
        let digest = state.register(node.clone()).unwrap();
        let remaining = before_remaining - node.storage_felt_len();

        assert_eq!(digest, node.digest());
        assert_eq!(state.nodes.get(&digest), Some(&node));
        assert_eq!(state.nodes.len(), before_len + 1);
        assert_eq!(state.remaining_elements, remaining);

        assert_eq!(state.register(node).unwrap(), digest);
        assert_eq!(state.nodes.len(), before_len + 1);
        assert_eq!(state.remaining_elements, remaining);
    }

    #[test]
    fn registration_enforces_remaining_budget() {
        let registry = hash_precompiles();
        let node = Hash::digest_node([Felt::from_u32(7); 8]);
        let mut state = state_with(&registry, node.storage_felt_len() - 1);

        let err = state.register(node.clone()).unwrap_err();
        assert!(matches!(
            err.root(),
            PrecompileError::Other(DeferredError::DeferredStateTooLarge { num_elements, max })
                if *num_elements == node.storage_felt_len() && *max == node.storage_felt_len() - 1
        ));
    }

    #[test]
    fn duplicate_registration_at_limit_is_free() {
        let registry = hash_precompiles();
        let node = Hash::digest_node([Felt::from_u32(7); 8]);
        let mut state = state_with(&registry, node.storage_felt_len());

        state.register(node.clone()).unwrap();
        let before = state.remaining_elements;
        state.register(node).unwrap();
        assert_eq!(state.remaining_elements, before);
    }

    #[test]
    fn evaluated_digests_do_not_charge_eval_memos() {
        let registry = hash_precompiles();
        let first = Hash::digest_node([Felt::from_u32(7); 8]);
        let second = Hash::digest_node([Felt::from_u32(8); 8]);
        let registered_elements = first.storage_felt_len() + second.storage_felt_len();
        let mut state = state_with(&registry, registered_elements);
        let first_digest = state.register(first.clone()).unwrap();
        let second_digest = state.register(second.clone()).unwrap();
        assert_eq!(state.remaining_elements, 0);

        assert_eq!(state.evaluate(first_digest).unwrap(), first);
        assert_eq!(
            state.remaining_elements, 0,
            "evaluating an already-durable canonical must not charge its eval memo",
        );

        assert_eq!(state.evaluate(first_digest).unwrap(), first);
        assert_eq!(
            state.remaining_elements, 0,
            "re-evaluating the same digest must not charge its eval memo",
        );

        assert_eq!(state.evaluate(second_digest).unwrap(), second);
        assert_eq!(
            state.remaining_elements, 0,
            "distinct evaluated digests memoize without changing durable node accounting",
        );
    }

    #[test]
    fn data_nodes_decrement_remaining_budget_by_payload_length() {
        let registry = hash_precompiles();
        let chunks = alloc::vec![[Felt::from_u32(1); 8], [Felt::from_u32(2); 8]];
        let node = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks);
        let expected_elements = node.storage_felt_len();
        let mut state = state_with(&registry, expected_elements);

        let digest = state.register(node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(expected_elements, 20);
        assert_eq!(state.remaining_elements, 0);

        state.register(node).unwrap();
        assert_eq!(state.remaining_elements, 0, "idempotent re-registration is free");
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        // Uint id + unknown discriminant: registry decode returns Err.
        let bad_tag = Tag::new(Uint::id(), [Felt::from_u32(99), ZERO, ZERO])
            .expect("Uint id is precompile-owned");
        let bad = Node::value(bad_tag, [Felt::from_u32(0); 8]).unwrap();
        let err = state.register(bad);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn register_join_requires_children_present_in_nodes() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(3)).unwrap();
        let missing = dummy_digest(99);

        let err = state.register(Node::join(Uint::add_tag(), a, missing).unwrap());
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn register_predicate_does_not_verify_eagerly() {
        // `register` is a pure host hint — it stores the predicate node in `nodes` without
        // evaluating. Programs that want host-side verification call `evaluate`; programs
        // that want constrained verification call checked append.
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(3)).unwrap();
        let b = state.register(test_value(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::join(Uint::eq_tag(), a, b).unwrap();
        let bad_digest = state.register(bad).unwrap();
        assert!(
            state.nodes.contains_key(&bad_digest),
            "predicate is present in nodes even when it doesn't hold"
        );
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(bad_digest);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_reports_success_and_child_failures() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(7)).unwrap();
        let b = state.register(test_value(8)).unwrap();

        let ok_digest = state.register(Node::join(Uint::eq_tag(), a, a).unwrap()).unwrap();
        let ok = state.evaluate(ok_digest).unwrap();
        assert!(ok.is_true_node(), "predicate success returns the canonical TRUE node");

        let mismatch_digest = state.register(Node::join(Uint::eq_tag(), a, b).unwrap()).unwrap();
        let mismatch = state.evaluate(mismatch_digest);
        assert!(matches!(mismatch.unwrap_err().root(), PrecompileError::AssertionFailed));

        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let missing = state.register(Node::join(Uint::eq_tag(), a, dangling).unwrap());
        assert!(matches!(missing.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn register_then_evaluate_stores_canonical_in_nodes() {
        // Build (a+b)*c, pre-register only the leaves and `add`. The outer `mul` is explicitly
        // registered before digest-addressed evaluation, and its canonical is stored in `nodes`.
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(3)).unwrap();
        let b = state.register(test_value(4)).unwrap();
        let c = state.register(test_value(5)).unwrap();
        let add = Node::join(Uint::add_tag(), a, b).unwrap();
        let add_digest = state.register(add).unwrap();
        let mul = Node::join(Uint::mul_tag(), add_digest, c).unwrap();
        let mul_digest = state.register(mul).unwrap();

        let canonical = state.evaluate(mul_digest).unwrap();
        assert_eq!(canonical, test_value(35));
        assert!(
            state.nodes.contains_key(&mul_digest),
            "input op is registered before evaluation"
        );
        assert!(
            state.nodes.contains_key(&test_value(35).digest()),
            "computed canonical is present in nodes"
        );
        assert_eq!(state.evaluate(mul_digest).unwrap(), test_value(35));
    }

    #[test]
    fn extend_precompiles_preserves_existing_state_and_allows_new_ids() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Uint))
            .unwrap();

        let uint_node = test_value(7);
        let uint_digest = state.register(uint_node.clone()).unwrap();
        assert_eq!(state.evaluate(uint_digest).unwrap(), uint_node);

        let before_root = state.root();
        let before_remaining = state.remaining_elements;
        let before_nodes = state.nodes.len();
        let before_evals = state.evals.len();

        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Hash))
            .unwrap();

        assert_eq!(state.root(), before_root);
        assert_eq!(state.remaining_elements, before_remaining);
        assert_eq!(state.nodes.len(), before_nodes);
        assert_eq!(state.evals.len(), before_evals);
        assert_eq!(state.evaluate(uint_digest).unwrap(), uint_node);
        assert!(state.register(Hash::digest_node([ZERO; 8])).is_ok());
    }

    #[test]
    #[should_panic(expected = "duplicate precompile id")]
    fn extend_precompiles_rejects_duplicate_ids() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Uint))
            .unwrap();
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Uint))
            .unwrap();
    }

    #[test]
    fn extend_precompiles_replays_existing_init_nodes_for_free() {
        let init_cost: usize = Uint.init().iter().map(Node::storage_felt_len).sum();
        let registry = empty_precompiles();
        let mut state = state_with(&registry, init_cost);

        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Uint))
            .unwrap();
        assert_eq!(state.remaining_elements, 0);
        let nodes_after_uint = state.nodes.len();
        let evals_after_uint = state.evals.len();

        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Hash))
            .unwrap();
        assert_eq!(state.remaining_elements, 0);
        assert_eq!(state.nodes.len(), nodes_after_uint);
        assert_eq!(state.evals.len(), evals_after_uint);
    }

    // REHYDRATE TESTS
    // ============================================================================================

    /// Asserts that wire round-tripping preserves the verified root and canonical wire nodes.
    fn assert_round_trips(state: &DeferredState, precompiles: &Arc<PrecompileRegistry>) {
        let wire = state.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(precompiles), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert!(
            rehydrated.nodes.iter().all(|(d, n)| state.nodes.get(d) == Some(n)),
            "wire round-trip changed a reachable node",
        );
        assert_eq!(
            rehydrated.to_wire().unwrap(),
            wire,
            "canonical to_wire output must round-trip deterministically"
        );
    }

    /// Builds a logged `(a+b)*c == 35` root used by round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(3)).unwrap();
        let b = state.register(test_value(4)).unwrap();
        let c = state.register(test_value(5)).unwrap();
        let expected = state.register(test_value(35)).unwrap();
        let add = state.register(Node::join(Uint::add_tag(), a, b).unwrap()).unwrap();
        let mul = state.register(Node::join(Uint::mul_tag(), add, c).unwrap()).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected).unwrap();
        let stmt_digest = state.register(assertion).unwrap();
        state.append_statement(stmt_digest).unwrap();
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let registry = precompiles();
        let wire = original.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::default();
        let state = DeferredState::from_wire(empty_precompiles(), &wire, usize::MAX).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.nodes.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
    }

    #[test]
    fn rehydrate_enforces_budget() {
        let original = built_state_with_logged_predicate();
        let registry = precompiles();
        let wire = original.to_wire().unwrap();
        let err = DeferredState::from_wire(Arc::clone(&registry), &wire, 0).unwrap_err();
        assert!(matches!(
            err,
            IntegrityError::DeferredStateTooLarge { num_elements, max }
                if num_elements == test_value(3).storage_felt_len() && max == 0
        ));
    }

    #[test]
    fn to_wire_does_not_serialize_true_as_entry() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        state.register(Node::TRUE).unwrap();

        let wire = state.to_wire().unwrap();
        assert_eq!(wire, DeferredStateWire::default());
    }

    #[test]
    fn rehydrate_rejects_invalid_structure_cases() {
        let registry = precompiles();
        let hash_registry = hash_precompiles();
        let value = test_value(7);
        let duplicate_value = value_entry(&value);
        let duplicate_predicate = WireEntry::Join { tag: Uint::eq_tag(), lhs: 1, rhs: 1 };
        let unknown_tag = Tag::new(Felt::new_unchecked(0xdead), [ZERO; 3])
            .expect("unknown test id is not framework-reserved");

        let cases = [
            (
                "explicit TRUE data",
                wire(alloc::vec![WireEntry::Data {
                    tag: Tag::TRUE,
                    chunks: alloc::vec![[ZERO; 8]]
                }]),
                registry.clone(),
            ),
            (
                "explicit TRUE join",
                wire(alloc::vec![WireEntry::Join {
                    tag: Tag::TRUE,
                    lhs: crate::deferred::TRUE_INDEX,
                    rhs: crate::deferred::TRUE_INDEX,
                }]),
                registry.clone(),
            ),
            (
                "future/self index",
                wire(alloc::vec![WireEntry::Join { tag: Uint::add_tag(), lhs: 1, rhs: 0 }]),
                registry.clone(),
            ),
            (
                "duplicate value digest",
                wire(alloc::vec![duplicate_value.clone(), duplicate_value]),
                registry.clone(),
            ),
            (
                "duplicate join digest",
                wire(alloc::vec![
                    value_entry(&value),
                    duplicate_predicate.clone(),
                    duplicate_predicate,
                ]),
                registry.clone(),
            ),
            (
                "unknown tag",
                wire(alloc::vec![WireEntry::Data {
                    tag: unknown_tag,
                    chunks: alloc::vec![[ZERO; 8]],
                }]),
                registry.clone(),
            ),
            (
                "too many chunks for value tag",
                wire(alloc::vec![WireEntry::Data {
                    tag: Uint::value_tag(),
                    chunks: alloc::vec![[ZERO; 8], [ZERO; 8]],
                }]),
                registry,
            ),
            (
                "empty data for preimage tag",
                wire(alloc::vec![WireEntry::Data {
                    tag: Hash::preimage_tag(Hash::BYTES_PER_CHUNK),
                    chunks: alloc::vec![],
                }]),
                hash_registry,
            ),
        ];

        for (name, wire, registry) in cases {
            let result = DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX);
            assert!(
                matches!(result, Err(IntegrityError::InvalidStructure)),
                "case {name}: expected InvalidStructure, got {result:?}"
            );
        }
    }

    #[test]
    fn rehydrate_accepts_logged_empty_transcript_root() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let new_root = state.append_statement(TRUE_DIGEST).unwrap();
        assert_ne!(new_root, TRUE_DIGEST);
        assert_eq!(state.nodes.get(&new_root).unwrap().tag(), Tag::AND);

        let wire = state.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), new_root);
        assert_eq!(rehydrated.statements(), alloc::vec![TRUE_DIGEST]);
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_accepts_logged_nested_transcript_root() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(7)).unwrap();
        let pred_digest = state.register(Node::join(Uint::eq_tag(), a, a).unwrap()).unwrap();

        let inner_root = state.register(Node::and(TRUE_DIGEST, pred_digest)).unwrap();
        let outer_root = state.append_statement(inner_root).unwrap();

        let wire = state.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), outer_root);
        assert_eq!(rehydrated.statements(), alloc::vec![inner_root]);
        assert!(rehydrated.nodes.contains_key(&inner_root));
        assert!(rehydrated.nodes.contains_key(&pred_digest));
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_accepts_predicate_root() {
        let a = test_value(7);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest()).unwrap();
        let pred_digest = pred.digest();
        let wire = wire(alloc::vec![
            value_entry(&a),
            WireEntry::Join { tag: pred.tag(), lhs: 1, rhs: 1 },
        ]);

        let rehydrated = DeferredState::from_wire(precompiles(), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), pred_digest);
        assert_eq!(rehydrated.evals.get(&pred_digest), Some(&TRUE_DIGEST));
        assert_eq!(rehydrated.to_wire().unwrap(), wire);
    }

    #[test]
    fn rehydrate_rejects_root_that_evaluates_non_true() {
        let wire = wire(alloc::vec![value_entry(&test_value(7))]);
        assert_rehydrate_err!(wire, precompiles(), IntegrityError::RootNotTrue);
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_values() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let _orphan = state.register(test_value(99)).unwrap();
        let a = state.register(test_value(7)).unwrap();
        let stmt_digest = state.register(Node::join(Uint::eq_tag(), a, a).unwrap()).unwrap();
        let new_root = state.append_statement(stmt_digest).unwrap();
        assert_round_trips(&state, &registry);

        let wire = state.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        let orphan_digest = test_value(99).digest();
        assert!(
            !rehydrated.nodes.contains_key(&orphan_digest),
            "orphan must be trimmed from wire and absent after rehydrate"
        );
        assert!(rehydrated.nodes.contains_key(&new_root), "AND-node must be in rehydrated state");
        assert!(
            rehydrated.nodes.contains_key(&stmt_digest),
            "stmt predicate must be in rehydrated state"
        );
        assert!(rehydrated.nodes.contains_key(&a), "stmt's operand must be in rehydrated state");
    }

    #[test]
    fn rehydrate_rejects_noncanonical_but_topological_wire() {
        let a = test_value(3);
        let b = test_value(4);
        let pred_a = Node::join(Uint::eq_tag(), a.digest(), a.digest()).unwrap();
        let pred_b = Node::join(Uint::eq_tag(), b.digest(), b.digest()).unwrap();

        // This is semantically equivalent to canonical output, but it emits `b` before the first
        // transcript step's closure. Strict wire rejects the non-canonical order.
        let wire = wire(alloc::vec![
            value_entry(&b),
            value_entry(&a),
            WireEntry::Join { tag: pred_a.tag(), lhs: 2, rhs: 2 },
            WireEntry::Join {
                tag: Tag::AND,
                lhs: crate::deferred::TRUE_INDEX,
                rhs: 3,
            },
            WireEntry::Join { tag: pred_b.tag(), lhs: 1, rhs: 1 },
            WireEntry::Join { tag: Tag::AND, lhs: 4, rhs: 5 },
        ]);

        assert_rehydrate_err!(wire, precompiles(), IntegrityError::InvalidStructure);
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(test_value(3)).unwrap();
        let b = state.register(test_value(4)).unwrap();

        let bad_pred = Node::join(Uint::eq_tag(), a, b).unwrap();
        let bad_digest = bad_pred.digest();
        state.insert_node(bad_pred).unwrap();
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.insert_node(and_node).unwrap();
        state.root = and_digest;

        let wire = state.to_wire().unwrap();
        assert_rehydrate_err!(wire, Arc::clone(&registry), IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_and_with_non_true_child() {
        let registry = precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let value_digest = state.register(test_value(3)).unwrap();
        let and_node = Node::and(TRUE_DIGEST, value_digest);
        let and_digest = and_node.digest();
        state.insert_node(and_node).unwrap();
        state.root = and_digest;

        let wire = state.to_wire().unwrap();
        assert_rehydrate_err!(wire, Arc::clone(&registry), IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_and_with_non_true_lhs() {
        let a = test_value(7);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest()).unwrap();
        let wire = wire(alloc::vec![
            value_entry(&a),
            WireEntry::Join { tag: pred.tag(), lhs: 1, rhs: 1 },
            WireEntry::Join { tag: Tag::AND, lhs: 1, rhs: 2 },
        ]);

        assert_rehydrate_err!(wire, precompiles(), IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_dangling_entry_as_noncanonical() {
        let a = test_value(7);
        let orphan = test_value(99);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest()).unwrap();
        let wire = wire(alloc::vec![
            value_entry(&orphan),
            value_entry(&a),
            WireEntry::Join { tag: pred.tag(), lhs: 2, rhs: 2 },
            WireEntry::Join {
                tag: Tag::AND,
                lhs: crate::deferred::TRUE_INDEX,
                rhs: 3,
            },
        ]);

        assert_rehydrate_err!(wire, precompiles(), IntegrityError::InvalidStructure);
    }
}
