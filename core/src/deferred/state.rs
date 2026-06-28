use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use super::{
    DeferredError, DeferredStateWire, Digest, IntegrityError, Node, NodeType, PrecompileError,
    PrecompileRegistry, TRUE_DIGEST, Tag,
};

/// In-memory witness for deferred-DAG verification.
///
/// The state keeps registered nodes, host-side evaluation memos, and the current deferred root.
/// Evaluation memos are valid only under the same [`PrecompileRegistry`] semantics used to populate
/// them. The state is intentionally not serialized directly: proofs carry [`DeferredStateWire`],
/// and [`Self::from_wire`] rebuilds this state only after registry checks, canonical wire checks,
/// and root evaluation. Callers that need proof binding compare the returned root to the externally
/// committed deferred root.
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
            self.evaluate_digest(digest)?;
        }

        Ok(())
    }

    /// Adds deferred precompiles to this state without discarding existing nodes, evaluation memos,
    /// root, or budget accounting.
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

    /// Returns the current deferred root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    pub fn remaining_elements(&self) -> usize {
        self.remaining_elements
    }

    pub fn decode(&self, tag: Tag) -> Result<NodeType, PrecompileError> {
        self.registry.decode_node_type(tag)
    }

    /// Registers a `PrecompileRegistry`-valid node in the DAG and evaluates it immediately.
    ///
    /// Registration validates the node shape and child references, stores the original node under
    /// its own digest, evaluates it under the current registry, stores the canonical result node,
    /// preserves helper nodes registered during evaluation, and records the evaluation memo from
    /// original digest to canonical digest. The returned digest is always the original node digest.
    /// If evaluation fails, registration returns that error immediately. Re-registering an
    /// identical successfully registered node is idempotent and budget-free.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        let mut next = self.clone();
        next.validate_node_for_insertion(&node)?;
        let digest = next.insert_node(node)?;
        next.evaluate_digest(digest)?;
        *self = next;
        Ok(digest)
    }

    /// Logs a statement commitment after proving the current root and statement evaluate to TRUE.
    ///
    /// The statement digest must already be registered (present in `nodes`), unless it is the
    /// implicit [`TRUE_DIGEST`]. On success, this inserts the framework AND node, advances the
    /// deferred root, memoizes the new root as TRUE, and returns the new root.
    pub fn log_statement(&mut self, statement_digest: Digest) -> Result<Digest, PrecompileError> {
        let prev_root = self.root;

        self.require_true_eval(prev_root)?;
        self.require_true_eval(statement_digest)?;

        let and_node = Node::and(prev_root, statement_digest);
        let new_root = and_node.digest();
        self.insert_node(and_node)?;
        self.root = new_root;
        self.record_eval(new_root, Node::TRUE)?;
        Ok(new_root)
    }

    /// Evaluates a registered node addressed by digest and returns the canonical node digest.
    ///
    /// Evaluation memoization is an implementation detail: callers receive the canonical digest
    /// whether the result was already known or computed by this call. Use [`Self::get_node`] with
    /// the returned digest to inspect the canonical node contents.
    pub fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        let node = self.nodes.get(&digest).ok_or(PrecompileError::MissingNode)?.clone();
        if let Some(canonical_digest) = self.evals.get(&digest) {
            if self.nodes.contains_key(canonical_digest) {
                return Ok(*canonical_digest);
            }
            return Err(PrecompileError::MissingNode);
        }

        self.validate_node_for_insertion(&node)?;
        let canonical = if node.tag() == Tag::TRUE {
            Node::TRUE
        } else if node.tag() == Tag::AND {
            let (lhs, rhs) = node.payload().as_join()?;
            for child in [lhs, rhs] {
                self.require_true_eval(child)?;
            }
            Node::TRUE
        } else {
            let registry = Arc::clone(&self.registry);
            let mut context = DeferredContext::new(self);
            registry.evaluate(&node, &mut context)?
        };

        self.record_eval(digest, canonical)?;
        self.evals.get(&digest).copied().ok_or(PrecompileError::MissingNode)
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

    fn validate_node_for_insertion(&self, node: &Node) -> Result<NodeType, PrecompileError> {
        let node_type = self.registry.validate_node(node)?;
        for child in node_type.children(node)? {
            if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                return Err(PrecompileError::MissingNode);
            }
        }
        Ok(node_type)
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

    fn require_true_eval(&mut self, digest: Digest) -> Result<(), PrecompileError> {
        if self.evaluate_digest(digest)? != TRUE_DIGEST {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(())
    }
}

// DEFERRED CONTEXT
// ================================================================================================

/// Capability object passed to precompiles during recursive evaluation.
///
/// Precompiles do not own the DAG; they receive this handle to evaluate registered children and to
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

    /// Returns the registered node addressed by `digest`, if present.
    ///
    /// This is a syntactic DAG lookup: it does not evaluate the node or canonicalize it.
    pub fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.state.get_node(digest)
    }

    /// Evaluates a registered child digest and returns the canonical node digest.
    ///
    /// The `nodes` membership check keeps local evaluation reproducible by `to_wire` and
    /// rehydration; memoization is transparent to precompile implementations. Use
    /// [`Self::get_node`] with the returned digest to inspect the canonical node contents.
    pub fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        self.state.evaluate_digest(digest)
    }

    /// Evaluates two registered child digests to their canonical node digests.
    pub fn evaluate_digest_pair(
        &mut self,
        lhs: Digest,
        rhs: Digest,
    ) -> Result<(Digest, Digest), PrecompileError> {
        Ok((self.evaluate_digest(lhs)?, self.evaluate_digest(rhs)?))
    }

    /// Evaluates two child digests and requires their canonical nodes to be equal.
    pub fn ensure_equal(&mut self, lhs: Digest, rhs: Digest) -> Result<(), PrecompileError> {
        let (lhs, rhs) = self.evaluate_digest_pair(lhs, rhs)?;
        if lhs != rhs {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(())
    }

    /// Registers a freshly minted helper node and returns its original digest.
    ///
    /// Use this when a compound canonical needs stable child commitments that were created during
    /// evaluation. Helper registration follows the same eager semantics as ordinary registration.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.state.register(node)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::num::NonZeroU32;

    use super::*;
    use crate::{
        Felt, Word, ZERO,
        deferred::{
            DeferredContext, DeferredStateWire, Payload, Precompile, PrecompileRegistry,
            TRUE_DIGEST, TRUE_INDEX, Tag, WireEntry, precompile_id,
        },
        testing::precompile::{Hash, Uint},
    };

    fn hash_precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(PrecompileRegistry::default().with_precompile(Hash))
    }

    fn empty_precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(PrecompileRegistry::new())
    }

    fn state_with(registry: &Arc<PrecompileRegistry>, max_elements: usize) -> DeferredState {
        DeferredState::new(Arc::clone(registry), max_elements).unwrap()
    }

    fn digest_node(seed: u32) -> Node {
        Hash::digest_node(core::array::from_fn(|i| Felt::from_u32(seed + i as u32)))
    }

    fn preimage_chunks() -> Vec<[Felt; 8]> {
        vec![
            core::array::from_fn(|i| Felt::from_u32(1 + i as u32)),
            core::array::from_fn(|i| Felt::from_u32(9 + i as u32)),
        ]
    }

    fn preimage_node(chunks: Vec<[Felt; 8]>) -> Node {
        Hash::preimage_node(Hash::BYTES_PER_CHUNK * chunks.len() as u32, chunks)
    }

    fn uint_value(value: u32) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value;
        Uint::value_node(limbs)
    }

    #[derive(Debug, Clone, Copy)]
    struct PairListFixture;

    impl PairListFixture {
        const NAME: &'static str = "pair_list_fixture";
        const EQ_ALL_TAG_ID: u32 = 0;

        fn id() -> Felt {
            precompile_id(Self::NAME)
        }

        fn eq_all_tag(pair_count: NonZeroU32) -> Tag {
            Tag::precompile(
                Self::id(),
                [Felt::from_u32(Self::EQ_ALL_TAG_ID), Felt::from_u32(pair_count.get()), ZERO],
            )
            .expect("pair-list fixture id is not framework-reserved")
        }
    }

    impl Precompile for PairListFixture {
        fn name(&self) -> &'static str {
            Self::NAME
        }

        fn id(&self) -> Felt {
            Self::id()
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            if args[0].as_canonical_u64() != Self::EQ_ALL_TAG_ID as u64 {
                return None;
            }

            let pair_count = u32::try_from(args[1].as_canonical_u64()).ok()?;
            let pair_count = NonZeroU32::new(pair_count)?;
            Some(NodeType::PairList(pair_count))
        }

        fn evaluate(
            &self,
            _args: [Felt; 3],
            payload: &Payload,
            context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            for (lhs, rhs) in payload.as_pair_list()? {
                context.ensure_equal(lhs, rhs)?;
            }
            Ok(Node::TRUE)
        }
    }

    fn pair_list_precompiles() -> Arc<PrecompileRegistry> {
        Arc::new(
            PrecompileRegistry::default()
                .with_precompile(Uint)
                .with_precompile(PairListFixture),
        )
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

    fn durable_storage_used(state: &DeferredState) -> usize {
        state.nodes().values().map(Node::storage_felt_len).sum()
    }

    fn assert_budget_consistent(state: &DeferredState, max_elements: usize) {
        assert_eq!(
            state.remaining_elements(),
            max_elements - durable_storage_used(state),
            "remaining budget must match durable node storage"
        );
    }

    fn register_true_statement(state: &mut DeferredState, seed: u32) -> Digest {
        let value = state.register(digest_node(seed)).unwrap();
        state.register(Hash::eq_node(value, value)).unwrap()
    }

    fn logged_hash_state() -> (Arc<PrecompileRegistry>, DeferredState) {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let statement = register_true_statement(&mut state, 7);
        state.log_statement(statement).unwrap();
        (registry, state)
    }

    fn assert_round_trips(state: &DeferredState, registry: &Arc<PrecompileRegistry>) {
        let wire = state.to_wire().unwrap();
        let rehydrated = DeferredState::from_wire(Arc::clone(registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), state.root(), "wire round-trip preserves root");
        assert_eq!(
            rehydrated.to_wire().unwrap(),
            wire,
            "canonical wire output must be deterministic"
        );
    }

    #[test]
    fn initialization_and_duplicate_registration_are_free() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let remaining = state.remaining_elements();

        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.get_node(&TRUE_DIGEST), Some(&Node::TRUE));
        assert_eq!(state.evaluate_digest(TRUE_DIGEST).unwrap(), TRUE_DIGEST);
        assert_eq!(state.remaining_elements(), remaining);

        assert_eq!(state.register(Node::TRUE).unwrap(), TRUE_DIGEST);
        assert_eq!(state.remaining_elements(), remaining);

        let registry = hash_precompiles();
        let node = digest_node(7);
        let max_elements = node.storage_felt_len();
        let mut state = state_with(&registry, max_elements);
        let digest = state.register(node.clone()).unwrap();
        assert_budget_consistent(&state, max_elements);

        let remaining = state.remaining_elements();
        assert_eq!(state.register(node).unwrap(), digest);
        assert_eq!(state.remaining_elements(), remaining);
        assert_budget_consistent(&state, max_elements);
    }

    #[test]
    fn register_eagerly_stores_original_and_canonical_nodes() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let chunks = preimage_chunks();
        let original = preimage_node(chunks.clone());
        let canonical = Hash::digest_node(Hash::hash(&chunks));

        let digest = state.register(original.clone()).unwrap();

        assert_eq!(digest, original.digest(), "register returns original digest");
        assert_eq!(state.get_node(&digest), Some(&original), "original node is durable");
        assert_eq!(
            state.get_node(&canonical.digest()),
            Some(&canonical),
            "canonical node is durable"
        );
        let canonical_digest = state.evaluate_digest(digest).unwrap();
        assert_eq!(canonical_digest, canonical.digest());
        assert_eq!(state.get_node(&canonical_digest), Some(&canonical));
    }

    #[test]
    fn register_eagerly_rejects_false_predicate() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let a = state.register(digest_node(3)).unwrap();
        let b = state.register(digest_node(4)).unwrap();
        let remaining = state.remaining_elements();
        let root = state.root();
        let pred = Hash::eq_node(a, b);

        let err = state.register(pred.clone()).unwrap_err();
        assert!(matches!(err.root(), PrecompileError::AssertionFailed));
        assert_eq!(state.remaining_elements(), remaining);
        assert_eq!(state.root(), root);
        assert_eq!(state.get_node(&pred.digest()), None);
    }

    #[test]
    fn budget_tracks_durable_node_storage() {
        let registry = hash_precompiles();
        let max_elements = 128;
        let mut state = state_with(&registry, max_elements);
        assert_budget_consistent(&state, max_elements);

        let chunks = preimage_chunks();
        let original = preimage_node(chunks.clone());
        let canonical = Hash::digest_node(Hash::hash(&chunks));
        let used_before = durable_storage_used(&state);

        state.register(original.clone()).unwrap();

        assert_eq!(
            durable_storage_used(&state),
            used_before + original.storage_felt_len() + canonical.storage_felt_len()
        );
        assert_budget_consistent(&state, max_elements);
    }

    #[test]
    fn duplicate_registration_and_eval_memo_hits_are_free() {
        let registry = hash_precompiles();
        let first = digest_node(7);
        let second = digest_node(8);
        let max_elements = first.storage_felt_len() + second.storage_felt_len();
        let mut state = state_with(&registry, max_elements);

        let first_digest = state.register(first.clone()).unwrap();
        let second_digest = state.register(second.clone()).unwrap();
        assert_budget_consistent(&state, max_elements);
        let remaining = state.remaining_elements();

        assert_eq!(state.register(first.clone()).unwrap(), first_digest);
        assert_eq!(state.remaining_elements(), remaining);
        let canonical = state.evaluate_digest(first_digest).unwrap();
        assert_eq!(canonical, first.digest());
        assert_eq!(state.get_node(&canonical), Some(&first));
        assert_eq!(state.remaining_elements(), remaining);
        let canonical = state.evaluate_digest(second_digest).unwrap();
        assert_eq!(canonical, second.digest());
        assert_eq!(state.get_node(&canonical), Some(&second));
        assert_eq!(state.remaining_elements(), remaining);
        assert_budget_consistent(&state, max_elements);
    }

    #[test]
    fn registration_errors_when_next_durable_node_exceeds_budget() {
        let registry = hash_precompiles();

        let node = digest_node(7);
        let mut state = state_with(&registry, node.storage_felt_len() - 1);
        let err = state.register(node).unwrap_err();
        assert!(
            matches!(
                err.root(),
                PrecompileError::Other(DeferredError::DeferredStateTooLarge { .. })
            ),
            "original node cannot fit"
        );

        let chunks = preimage_chunks();
        let original = preimage_node(chunks);
        let mut state = state_with(&registry, original.storage_felt_len());
        let err = state.register(original).unwrap_err();
        assert!(
            matches!(
                err.root(),
                PrecompileError::Other(DeferredError::DeferredStateTooLarge { .. })
            ),
            "original node fits, but eager canonical materialization cannot fit"
        );
    }

    #[test]
    fn rehydrate_enforces_budget_for_wire_entries() {
        let (registry, state) = logged_hash_state();
        let wire = state.to_wire().unwrap();
        let max_elements = durable_storage_used(&state);

        let rehydrated = DeferredState::from_wire(Arc::clone(&registry), &wire, max_elements)
            .expect("wire fits exactly in its durable-storage budget");
        assert_budget_consistent(&rehydrated, max_elements);

        let err = DeferredState::from_wire(registry, &wire, max_elements - 1).unwrap_err();
        assert!(matches!(err, IntegrityError::DeferredStateTooLarge { .. }));
    }

    #[test]
    fn register_rejects_unknown_tags_and_missing_children() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let unknown_tag = Tag::precompile(Hash::id(), [Felt::from_u32(99), ZERO, ZERO])
            .expect("hash precompile id is precompile-owned");
        let unknown = Node::value(unknown_tag, [ZERO; 8]).unwrap();
        assert!(state.register(unknown).is_err());

        let mut state = state_with(&registry, usize::MAX);
        let present = state.register(digest_node(3)).unwrap();
        let missing = dummy_digest(99);
        let dangling = Node::join(Hash::eq_tag(), present, missing).unwrap();
        assert!(state.register(dangling).is_err());
    }

    #[test]
    fn log_statement_advances_root_with_framework_and() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let statement = register_true_statement(&mut state, 7);
        let previous_root = state.root();
        let expected_node = Node::and(previous_root, statement);
        let expected_root = expected_node.digest();

        let actual_root = state.log_statement(statement).unwrap();

        assert_eq!(actual_root, expected_root);
        assert_eq!(state.root(), expected_root);
        assert_eq!(state.get_node(&expected_root), Some(&expected_node));
        assert_eq!(state.evaluate_digest(expected_root).unwrap(), TRUE_DIGEST);
        assert_eq!(state.get_node(&TRUE_DIGEST), Some(&Node::TRUE));
    }

    #[test]
    fn log_statement_rejects_invalid_transitions() {
        type Case = fn(&Arc<PrecompileRegistry>) -> Result<Digest, PrecompileError>;

        let registry = hash_precompiles();
        let cases: [(&str, Case); 3] = [
            ("missing statement", |registry| {
                let mut state = state_with(registry, usize::MAX);
                state.log_statement(dummy_digest(7))
            }),
            ("non-TRUE statement", |registry| {
                let mut state = state_with(registry, usize::MAX);
                let value = state.register(digest_node(7))?;
                state.log_statement(value)
            }),
            ("non-TRUE current root", |registry| {
                let mut state = state_with(registry, usize::MAX);
                state.root = state.register(digest_node(7))?;
                state.log_statement(TRUE_DIGEST)
            }),
        ];

        for (name, run) in cases {
            assert!(run(&registry).is_err(), "case {name}");
        }
    }

    #[test]
    fn extend_precompiles_preserves_state_and_allows_new_ids() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Uint))
            .unwrap();

        let uint_node = uint_value(7);
        let uint_digest = state.register(uint_node.clone()).unwrap();
        let root_before = state.root();
        let canonical_before = state.evaluate_digest(uint_digest).unwrap();

        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Hash))
            .unwrap();

        assert_eq!(state.root(), root_before);
        assert_eq!(state.get_node(&uint_digest), Some(&uint_node));
        assert_eq!(state.evaluate_digest(uint_digest).unwrap(), canonical_before);
        assert_eq!(state.get_node(&canonical_before), Some(&uint_node));
        assert!(state.register(digest_node(11)).is_ok());
        assert_budget_consistent(&state, usize::MAX);
    }

    #[test]
    #[should_panic(expected = "duplicate precompile id")]
    fn extend_precompiles_rejects_duplicate_ids() {
        let registry = empty_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Hash))
            .unwrap();
        state
            .extend_precompiles(PrecompileRegistry::default().with_precompile(Hash))
            .unwrap();
    }

    #[test]
    fn wire_round_trips_empty_and_logged_states() {
        let empty_wire = DeferredStateWire { entries: Vec::new() };

        let empty_state = DeferredState::from_wire(empty_precompiles(), &empty_wire, usize::MAX)
            .expect("empty wire opens TRUE");
        assert_eq!(empty_state.root(), TRUE_DIGEST);
        assert_eq!(empty_state.to_wire().unwrap(), empty_wire);

        let (registry, state) = logged_hash_state();
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn wire_round_trips_logged_pair_list_state() {
        let registry = pair_list_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let lhs = state.register(uint_value(3)).expect("lhs must register");
        let rhs = state.register(uint_value(3)).expect("rhs must register");
        let pair_list = Node::try_pair_list(
            PairListFixture::eq_all_tag(NonZeroU32::new(2).unwrap()),
            vec![(lhs, lhs), (rhs, rhs)],
        )
        .expect("pair-list fixture owns tag");
        let statement = state.register(pair_list).expect("pair list must register");
        state.log_statement(statement).expect("pair list evaluates to TRUE");

        let wire = state.to_wire().unwrap();
        assert!(
            wire.entries.iter().any(
                |entry| matches!(entry, WireEntry::PairList { pairs, .. } if pairs.len() == 2)
            ),
            "canonical wire must include the multi-pair entry",
        );
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn to_wire_emits_only_root_reachable_canonical_nodes() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let orphan = state.register(digest_node(99)).unwrap();
        let statement = register_true_statement(&mut state, 7);
        let root = state.log_statement(statement).unwrap();
        assert_round_trips(&state, &registry);

        let wire = state.to_wire().unwrap();
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), root);
        assert!(rehydrated.get_node(&orphan).is_none(), "unreachable orphan must be omitted");
        assert!(rehydrated.get_node(&statement).is_some(), "statement remains root-reachable");
        assert!(rehydrated.get_node(&root).is_some(), "framework AND root remains reachable");
        assert_eq!(rehydrated.to_wire().unwrap(), wire);
    }

    #[test]
    fn to_wire_handles_long_left_deep_root_chain_iteratively() {
        let registry = hash_precompiles();
        let mut state = state_with(&registry, usize::MAX);
        let statement_count = 1024;
        for seed in 0..statement_count {
            let statement = register_true_statement(&mut state, seed);
            state.log_statement(statement).unwrap();
        }

        let wire = state.to_wire().unwrap();
        assert_eq!(wire.entries.len(), statement_count as usize * 3);
        let rehydrated =
            DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert_eq!(rehydrated.to_wire().unwrap(), wire);
    }

    #[test]
    fn rehydrate_rejects_malformed_or_noncanonical_wire() {
        let registry = hash_precompiles();
        let a = digest_node(3);
        let b = digest_node(4);
        let orphan = digest_node(99);
        let pred_a = Hash::eq_node(a.digest(), a.digest());
        let pred_b = Hash::eq_node(b.digest(), b.digest());
        let duplicate = value_entry(&a);

        let cases = vec![
            (
                "explicit TRUE as data entry",
                wire(vec![WireEntry::Data { tag: Tag::TRUE, chunks: vec![[ZERO; 8]] }]),
            ),
            (
                "future/self child index",
                wire(vec![WireEntry::Join {
                    tag: Hash::eq_tag(),
                    lhs: 1,
                    rhs: TRUE_INDEX,
                }]),
            ),
            ("duplicate digest", wire(vec![duplicate.clone(), duplicate])),
            (
                "wrong payload shape for known tag",
                wire(vec![WireEntry::Data {
                    tag: Hash::digest_tag(),
                    chunks: vec![[ZERO; 8], [ZERO; 8]],
                }]),
            ),
            (
                "noncanonical but topological order",
                wire(vec![
                    value_entry(&b),
                    value_entry(&a),
                    WireEntry::Join { tag: pred_a.tag(), lhs: 2, rhs: 2 },
                    WireEntry::Join { tag: Tag::AND, lhs: TRUE_INDEX, rhs: 3 },
                    WireEntry::Join { tag: pred_b.tag(), lhs: 1, rhs: 1 },
                    WireEntry::Join { tag: Tag::AND, lhs: 4, rhs: 5 },
                ]),
            ),
            (
                "dangling orphan before root path",
                wire(vec![
                    value_entry(&orphan),
                    value_entry(&a),
                    WireEntry::Join { tag: Hash::eq_tag(), lhs: 2, rhs: 2 },
                    WireEntry::Join { tag: Tag::AND, lhs: TRUE_INDEX, rhs: 3 },
                ]),
            ),
        ];

        for (name, wire) in cases {
            assert!(
                DeferredState::from_wire(Arc::clone(&registry), &wire, usize::MAX).is_err(),
                "case {name}"
            );
        }
    }

    #[test]
    fn rehydrate_rejects_semantically_invalid_roots() {
        let a = digest_node(3);
        let b = digest_node(4);
        enum ExpectedError {
            RootNotTrue,
            EvaluationFailed,
        }

        let cases = vec![
            (
                "root canonicalizes to non-TRUE",
                wire(vec![value_entry(&a)]),
                "The wire is structurally valid and evaluates successfully, but the root is not TRUE.",
                ExpectedError::RootNotTrue,
            ),
            (
                "predicate evaluation fails",
                wire(vec![
                    value_entry(&a),
                    value_entry(&b),
                    WireEntry::Join { tag: Hash::eq_tag(), lhs: 1, rhs: 2 },
                ]),
                "The root is predicate-shaped, but semantic evaluation rejects it.",
                ExpectedError::EvaluationFailed,
            ),
            (
                "AND child evaluates non-TRUE",
                wire(vec![
                    value_entry(&a),
                    WireEntry::Join { tag: Tag::AND, lhs: TRUE_INDEX, rhs: 1 },
                ]),
                "Framework AND is TRUE only when both children evaluate to TRUE.",
                ExpectedError::EvaluationFailed,
            ),
        ];

        for (name, wire, why, expected) in cases {
            let result = DeferredState::from_wire(hash_precompiles(), &wire, usize::MAX);
            match expected {
                ExpectedError::RootNotTrue => {
                    assert!(
                        matches!(result, Err(IntegrityError::RootNotTrue)),
                        "case {name}: {why}"
                    );
                },
                ExpectedError::EvaluationFailed => {
                    assert!(
                        matches!(result, Err(IntegrityError::EvaluationFailed(_))),
                        "case {name}: {why}"
                    );
                },
            }
        }
    }
}
