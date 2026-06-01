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
/// and [`Self::from_wire`] rebuilds this state only after registry checks, canonical wire checks,
/// expected-root matching, and root evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    pub(super) root: Digest,
    evals: BTreeMap<Digest, Digest>,
    remaining_elements: usize,
}

impl Default for DeferredState {
    fn default() -> Self {
        Self::new(usize::MAX)
    }
}

impl DeferredState {
    pub fn new(max_elements: usize) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);

        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, TRUE_DIGEST);

        Self {
            nodes,
            root: TRUE_DIGEST,
            evals,
            remaining_elements: max_elements,
        }
    }

    pub(super) fn node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    fn insert_node(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        let digest = node.digest();
        match self.nodes.get(&digest) {
            Some(existing) if existing == &node => Ok(digest),
            Some(_) => Err(DeferredError::ConflictingNode.into()),
            None => {
                let required = node.num_elements();
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

    /// Caches a reduction result and materializes its canonical node for downstream references.
    fn record_eval(
        &mut self,
        precompiles: &PrecompileRegistry,
        input_digest: Digest,
        canonical: Node,
    ) -> Result<(), PrecompileError> {
        if !self.nodes.contains_key(&input_digest) {
            return Err(PrecompileError::MissingNode);
        }
        self.validate_node_for_insertion(precompiles, &canonical)?;
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
        let canonical = self.evaluate(precompiles, stmt_digest)?;
        if !canonical.is_true_node() {
            return Err(PrecompileError::AssertionFailed);
        }

        let and_node = Node::and(self.root, stmt_digest);
        let new_root = and_node.digest();
        self.insert_node(and_node)?;
        self.root = new_root;
        Ok(new_root)
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
        self.insert_node(node)
    }

    fn validate_node_for_insertion(
        &self,
        precompiles: &PrecompileRegistry,
        node: &Node,
    ) -> Result<NodeType, PrecompileError> {
        let node_type = precompiles.validate_node(node)?;
        if let Some((lhs, rhs)) = node_type.children(&node.payload)? {
            for child in [lhs, rhs] {
                if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                    return Err(PrecompileError::MissingNode);
                }
            }
        }
        Ok(node_type)
    }

    /// Reduces a committed node addressed by digest.
    ///
    /// The memo is used only after the digest is proven present in `nodes`; memo entries alone do
    /// not create durable DAG membership. Predicate success returns [`Node::TRUE`]; mismatch
    /// returns [`PrecompileError::AssertionFailed`].
    pub fn evaluate(
        &mut self,
        precompiles: &PrecompileRegistry,
        digest: Digest,
    ) -> Result<Node, PrecompileError> {
        let node = self.nodes.get(&digest).ok_or(PrecompileError::MissingNode)?.clone();
        if let Some(canonical_digest) = self.evals.get(&digest) {
            return self.nodes.get(canonical_digest).cloned().ok_or(PrecompileError::MissingNode);
        }

        self.validate_node_for_insertion(precompiles, &node)?;
        let canonical = if node.tag == Tag::TRUE {
            Node::TRUE
        } else if node.tag == Tag::AND {
            let (lhs, rhs) = node.payload.join_children()?;
            for child in [lhs, rhs] {
                if !self.evaluate(precompiles, child)?.is_true_node() {
                    return Err(PrecompileError::AssertionFailed);
                }
            }
            Node::TRUE
        } else {
            let mut witness = WitnessBuilder::new(self, precompiles);
            precompiles.reduce(&node, &mut witness)?
        };

        self.record_eval(precompiles, digest, canonical.clone())?;
        Ok(canonical)
    }

    /// Serializes the root-reachable DAG into compact canonical wire form.
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
    /// The wire root is implicit: empty wire opens [`TRUE_DIGEST`], otherwise the root is the
    /// digest of the final entry. Rehydration rejects non-canonical or dangling wire, then
    /// evaluates the implicit root to TRUE under the installed precompiles. Callers that need
    /// proof binding should compare the returned [`Self::root`] against the externally
    /// committed root.
    pub fn from_wire(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
        max_elements: usize,
    ) -> Result<Self, IntegrityError> {
        wire.rehydrate(precompiles, max_elements)
    }

    /// Returns logged statement digests in execution order for already-verified test states.
    ///
    /// Panics if the chain is malformed; production callers should obtain states through
    /// [`Self::from_wire`], which validates the chain first.
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

// WITNESS BUILDER
// ================================================================================================

/// Capability object passed to precompiles during recursive reduction.
///
/// Precompiles do not own the DAG; they receive this handle to resolve committed children and to
/// intern helper nodes referenced by compound canonicals. The verifier reuses the same path during
/// [`DeferredState::from_wire`], so prover and verifier agree on how witnesses are reconstructed.
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
        self.state.evaluate(self.precompiles, digest)
    }

    /// Commits a freshly minted helper node and returns its digest.
    ///
    /// Use this when a compound canonical needs stable child commitments that were created during
    /// reduction.
    pub fn intern(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.state.register(self.precompiles, node)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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

    fn value_entry(node: &Node) -> WireEntry {
        WireEntry::Value {
            tag: node.tag,
            block: *node.payload.as_felts().expect("test node is expression-bodied"),
        }
    }

    fn wire(entries: Vec<WireEntry>) -> DeferredStateWire {
        DeferredStateWire { entries }
    }

    macro_rules! assert_rehydrate_err {
        ($wire:expr, $registry:expr, $pat:pat $(,)?) => {{
            let result = DeferredState::from_wire(&$wire, $registry, usize::MAX);
            let expected = stringify!($pat);
            assert!(matches!(&result, Err($pat)), "expected {expected}, got {result:?}");
        }};
    }

    #[test]
    fn empty_state_seeds_true_node_and_root_is_true() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();

        assert_eq!(state.nodes.len(), 1);
        assert!(state.nodes.contains_key(&TRUE_DIGEST));
        assert_eq!(state.nodes.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.remaining_elements, usize::MAX);
        assert_eq!(state.evaluate(&registry, TRUE_DIGEST).unwrap(), Node::TRUE);
        assert_eq!(state.remaining_elements, usize::MAX);
    }

    #[test]
    fn register_true_is_idempotent() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();

        let digest = state.register(&registry, Node::TRUE).unwrap();
        assert_eq!(digest, TRUE_DIGEST);
        assert_eq!(state.nodes.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.remaining_elements, usize::MAX);
    }

    #[test]
    fn append_statement_advances_root_with_and_node() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let pred = Node::join(Uint::eq_tag(), a, a);
        let stmt_digest = state.register(&registry, pred).unwrap();

        let expected = Node::and(TRUE_DIGEST, stmt_digest).digest();
        let actual = state.append_statement(&registry, stmt_digest).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(expected, TRUE_DIGEST);
        assert_eq!(state.root(), expected);
        assert!(state.nodes.contains_key(&expected));
        assert_eq!(state.nodes.get(&expected).unwrap().tag, Tag::AND);
    }

    #[test]
    fn append_statement_rejects_missing_statement() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let err = state.append_statement(&registry, dummy_digest(7));
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn append_statement_rejects_statement_that_is_not_true() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let leaf = state.register(&registry, test_leaf(7)).unwrap();
        let err = state.append_statement(&registry, leaf);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
        assert_eq!(state.root(), TRUE_DIGEST);
    }

    #[test]
    fn register_leaf_stores_it() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let node = test_leaf(7);
        let digest = state.register(&registry, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(state.nodes.get(&digest).unwrap(), &node);
        assert_eq!(state.remaining_elements, usize::MAX - node.num_elements());
    }

    #[test]
    fn idempotent_reinsert_succeeds() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let node = test_leaf(7);
        let d1 = state.register(&registry, node.clone()).unwrap();
        let d2 = state.register(&registry, node).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(state.nodes.len(), 2); // TRUE plus the leaf
        assert_eq!(state.remaining_elements, usize::MAX - test_leaf(7).num_elements());
    }

    #[test]
    fn registration_enforces_remaining_budget() {
        let mut state = DeferredState::new(test_leaf(7).num_elements() - 1);
        let registry = precompiles();

        let err = state.register(&registry, test_leaf(7)).unwrap_err();
        assert!(matches!(
            err.root(),
            PrecompileError::Other(DeferredError::DeferredStateTooLarge { num_elements, max })
                if *num_elements == test_leaf(7).num_elements() && *max == test_leaf(7).num_elements() - 1
        ));
    }

    #[test]
    fn duplicate_registration_at_limit_is_free() {
        let node = test_leaf(7);
        let mut state = DeferredState::new(node.num_elements());
        let registry = precompiles();

        state.register(&registry, node.clone()).unwrap();
        let before = state.remaining_elements;
        state.register(&registry, node).unwrap();
        assert_eq!(state.remaining_elements, before);
    }

    #[test]
    fn evaluated_digests_do_not_charge_eval_memos() {
        let registry = precompiles();
        let first = test_leaf(7);
        let second = test_leaf(8);
        let registered_elements = first.num_elements() + second.num_elements();
        let mut state = DeferredState::new(registered_elements);
        let first_digest = state.register(&registry, first.clone()).unwrap();
        let second_digest = state.register(&registry, second.clone()).unwrap();
        assert_eq!(state.remaining_elements, 0);

        assert_eq!(state.evaluate(&registry, first_digest).unwrap(), first);
        assert_eq!(
            state.remaining_elements, 0,
            "evaluating an already-durable canonical must not charge its eval memo",
        );

        assert_eq!(state.evaluate(&registry, first_digest).unwrap(), first);
        assert_eq!(
            state.remaining_elements, 0,
            "re-evaluating the same digest must not charge its eval memo",
        );

        assert_eq!(state.evaluate(&registry, second_digest).unwrap(), second);
        assert_eq!(
            state.remaining_elements, 0,
            "distinct evaluated digests memoize without changing durable node accounting",
        );
    }

    #[test]
    fn chunk_nodes_decrement_remaining_budget_by_payload_length() {
        let registry = PrecompileRegistry::default().with_precompile(Hash);
        let chunks = alloc::vec![[Felt::from_u32(1); 8], [Felt::from_u32(2); 8]];
        let node = Hash::preimage_node(2 * Hash::BYTES_PER_CHUNK, chunks);
        let expected_elements = node.num_elements();
        let mut state = DeferredState::new(expected_elements);

        let digest = state.register(&registry, node.clone()).unwrap();
        assert_eq!(digest, node.digest());
        assert_eq!(expected_elements, 20);
        assert_eq!(state.remaining_elements, 0);

        state.register(&registry, node).unwrap();
        assert_eq!(state.remaining_elements, 0, "idempotent re-registration is free");
    }

    #[test]
    fn register_with_unhandled_tag_errors() {
        let mut state = DeferredState::new(usize::MAX);
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
        let mut state = DeferredState::new(usize::MAX);
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
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        // A mismatched predicate — would fail if eagerly verified.
        let bad = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = state.register(&registry, bad).unwrap();
        assert!(
            state.nodes.contains_key(&bad_digest),
            "predicate interned even when it doesn't hold"
        );
        // Verification surfaces the mismatch only when explicitly invoked.
        let err = state.evaluate(&registry, bad_digest);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn evaluate_predicate_reports_success_and_child_failures() {
        let registry = precompiles();
        let mut state = DeferredState::new(usize::MAX);
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let b = state.register(&registry, test_leaf(8)).unwrap();

        let ok_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();
        let ok = state.evaluate(&registry, ok_digest).unwrap();
        assert!(ok.is_true_node(), "predicate success returns the canonical TRUE node");

        let mismatch_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, b)).unwrap();
        let mismatch = state.evaluate(&registry, mismatch_digest);
        assert!(matches!(mismatch.unwrap_err().root(), PrecompileError::AssertionFailed));

        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let missing = state.register(&registry, Node::join(Uint::eq_tag(), a, dangling));
        assert!(matches!(missing.unwrap_err().root(), PrecompileError::MissingNode));
    }

    #[test]
    fn evaluate_interns_canonicals_into_nodes() {
        // Register the full op tree (a + b) * c == 35 plus an orphan leaf, evaluate the
        // predicate, and assert evaluate interns computed canonicals into `state.nodes`.
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        let c = state.register(&registry, test_leaf(5)).unwrap();
        let expected = state.register(&registry, test_leaf(35)).unwrap();
        let _orphan = state.register(&registry, test_leaf(99)).unwrap();
        let add = state.register(&registry, Node::join(Uint::add_tag(), a, b)).unwrap();
        let mul = state.register(&registry, Node::join(Uint::mul_tag(), add, c)).unwrap();
        let assertion = Node::join(Uint::eq_tag(), mul, expected);
        let assertion_digest = state.register(&registry, assertion).unwrap();
        state.evaluate(&registry, assertion_digest).unwrap();

        assert!(state.nodes.contains_key(&assertion_digest), "predicate input is registered");
        assert!(
            state.nodes.contains_key(&test_leaf(7).digest()),
            "canonical(add) is interned into nodes"
        );
        assert!(
            state.nodes.contains_key(&Node::TRUE.digest()),
            "canonical(TRUE) remains in nodes"
        );
        assert_eq!(state.root(), TRUE_DIGEST, "no append called, root is still TRUE");
    }

    #[test]
    fn register_then_evaluate_interns_canonical() {
        // Build (a+b)*c, pre-register only the leaves and `add`. The outer `mul` is explicitly
        // registered before digest-addressed evaluation, and its canonical is interned.
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();
        let c = state.register(&registry, test_leaf(5)).unwrap();
        let add = Node::join(Uint::add_tag(), a, b);
        let add_digest = state.register(&registry, add).unwrap();
        let mul = Node::join(Uint::mul_tag(), add_digest, c);
        let mul_digest = state.register(&registry, mul).unwrap();

        let canonical = state.evaluate(&registry, mul_digest).unwrap();
        assert_eq!(canonical, test_leaf(35));
        assert!(
            state.nodes.contains_key(&mul_digest),
            "input op is registered before evaluation"
        );
        assert!(
            state.nodes.contains_key(&test_leaf(35).digest()),
            "computed canonical is interned"
        );
        assert_eq!(state.evaluate(&registry, mul_digest).unwrap(), test_leaf(35));
    }

    // REHYDRATE TESTS
    // ============================================================================================

    /// Asserts that wire round-tripping preserves the verified root and canonical wire nodes.
    fn assert_round_trips(state: &DeferredState, precompiles: &PrecompileRegistry) {
        let wire = state.to_wire(precompiles).unwrap();
        let rehydrated = DeferredState::from_wire(&wire, precompiles, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), state.root());
        assert!(
            rehydrated.nodes.iter().all(|(d, n)| state.nodes.get(d) == Some(n)),
            "wire round-trip changed a reachable node",
        );
        assert_eq!(
            rehydrated.to_wire(precompiles).unwrap(),
            wire,
            "canonical to_wire output must round-trip deterministically"
        );
    }

    /// Builds a logged `(a+b)*c == 35` root used by round-trip tests.
    fn built_state_with_logged_predicate() -> DeferredState {
        let mut state = DeferredState::new(usize::MAX);
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
        // future change that breaks `to_wire`/`from_wire` consistency fails loudly here.
        assert_round_trips(&state, &precompiles());
        state
    }

    #[test]
    fn rehydrate_round_trips_simple_chain() {
        let original = built_state_with_logged_predicate();
        let registry = precompiles();
        let wire = original.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::from_wire(&wire, &registry, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), original.root());
        assert_eq!(rehydrated.statements(), original.statements());
    }

    #[test]
    fn rehydrate_empty_state_succeeds() {
        let wire = DeferredStateWire::default();
        let state = DeferredState::from_wire(&wire, &precompiles(), usize::MAX).unwrap();
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.nodes.get(&TRUE_DIGEST).unwrap(), &Node::TRUE);
    }

    #[test]
    fn rehydrate_enforces_budget() {
        let original = built_state_with_logged_predicate();
        let registry = precompiles();
        let wire = original.to_wire(&registry).unwrap();
        let err = DeferredState::from_wire(&wire, &registry, 0).unwrap_err();
        assert!(matches!(
            err,
            IntegrityError::DeferredStateTooLarge { num_elements, max }
                if num_elements == test_leaf(3).num_elements() && max == 0
        ));
    }

    #[test]
    fn to_wire_does_not_serialize_true_as_entry() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        state.register(&registry, Node::TRUE).unwrap();

        let wire = state.to_wire(&registry).unwrap();
        assert_eq!(wire, DeferredStateWire::default());
    }

    #[test]
    fn rehydrate_rejects_materialized_true_entries() {
        let wires = [
            wire(alloc::vec![WireEntry::Value { tag: Tag::TRUE, block: [ZERO; 8] }]),
            wire(alloc::vec![WireEntry::Join {
                tag: Tag::TRUE,
                lhs: crate::deferred::TRUE_INDEX,
                rhs: crate::deferred::TRUE_INDEX,
            }]),
        ];

        for wire in wires {
            assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
        }
    }

    #[test]
    fn rehydrate_accepts_logged_empty_transcript_root() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let new_root = state.append_statement(&registry, TRUE_DIGEST).unwrap();
        assert_ne!(new_root, TRUE_DIGEST);
        assert_eq!(state.nodes.get(&new_root).unwrap().tag, Tag::AND);

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::from_wire(&wire, &registry, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), new_root);
        assert_eq!(rehydrated.statements(), alloc::vec![TRUE_DIGEST]);
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_accepts_logged_nested_transcript_root() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let pred_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();

        let inner_root = state.register(&registry, Node::and(TRUE_DIGEST, pred_digest)).unwrap();
        let outer_root = state.append_statement(&registry, inner_root).unwrap();

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::from_wire(&wire, &registry, usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), outer_root);
        assert_eq!(rehydrated.statements(), alloc::vec![inner_root]);
        assert!(rehydrated.nodes.contains_key(&inner_root));
        assert!(rehydrated.nodes.contains_key(&pred_digest));
        assert_round_trips(&state, &registry);
    }

    #[test]
    fn rehydrate_accepts_predicate_root() {
        let a = test_leaf(7);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let pred_digest = pred.digest();
        let wire =
            wire(alloc::vec![value_entry(&a), WireEntry::Join { tag: pred.tag, lhs: 1, rhs: 1 },]);

        let rehydrated = DeferredState::from_wire(&wire, &precompiles(), usize::MAX).unwrap();
        assert_eq!(rehydrated.root(), pred_digest);
        assert_eq!(rehydrated.evals.get(&pred_digest), Some(&TRUE_DIGEST));
        assert_eq!(rehydrated.to_wire(&precompiles()).unwrap(), wire);
    }

    #[test]
    fn rehydrate_rejects_bad_index() {
        // Entry 1 cannot reference itself/future index 1 while it is being decoded.
        let wire = wire(alloc::vec![WireEntry::Join { tag: Uint::add_tag(), lhs: 1, rhs: 0 }]);
        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
    }

    #[test]
    fn rehydrate_rejects_duplicate_digest_in_any_entry() {
        let leaf = test_leaf(7);
        let duplicate_leaf = value_entry(&leaf);
        let duplicate_predicate = WireEntry::Join { tag: Uint::eq_tag(), lhs: 1, rhs: 1 };
        let wires = [
            wire(alloc::vec![duplicate_leaf.clone(), duplicate_leaf]),
            wire(alloc::vec![
                value_entry(&leaf),
                duplicate_predicate.clone(),
                duplicate_predicate,
            ]),
        ];

        for wire in wires {
            assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
        }
    }

    #[test]
    fn rehydrate_rejects_root_that_reduces_non_true() {
        let wire = wire(alloc::vec![value_entry(&test_leaf(7))]);
        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::RootNotTrue);
    }

    #[test]
    fn rehydrate_rejects_unknown_tag() {
        let bogus_tag = Tag {
            id: Felt::new_unchecked(0xdead),
            args: [ZERO; 3],
        };
        let wire = wire(alloc::vec![WireEntry::Value { tag: bogus_tag, block: [ZERO; 8] }]);
        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
    }

    #[test]
    fn rehydrate_rejects_malformed_chunk_entries() {
        let wrong_variant = wire(alloc::vec![WireEntry::Chunks {
            tag: Uint::leaf_tag(),
            blocks: alloc::vec![[ZERO; 8]],
        }]);
        assert_rehydrate_err!(wrong_variant, &precompiles(), IntegrityError::InvalidStructure);

        let registry = PrecompileRegistry::default().with_precompile(Hash);
        let wrong_count = wire(alloc::vec![WireEntry::Chunks {
            tag: Hash::preimage_tag(Hash::BYTES_PER_CHUNK),
            blocks: alloc::vec![],
        }]);
        assert_rehydrate_err!(wrong_count, &registry, IntegrityError::InvalidStructure);
    }

    #[test]
    fn to_wire_drops_unreachable_orphan_leaves() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let _orphan = state.register(&registry, test_leaf(99)).unwrap();
        let a = state.register(&registry, test_leaf(7)).unwrap();
        let stmt_digest = state.register(&registry, Node::join(Uint::eq_tag(), a, a)).unwrap();
        let new_root = state.append_statement(&registry, stmt_digest).unwrap();
        assert_round_trips(&state, &registry);

        let wire = state.to_wire(&registry).unwrap();
        let rehydrated = DeferredState::from_wire(&wire, &registry, usize::MAX).unwrap();
        let orphan_digest = test_leaf(99).digest();
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
        let a = test_leaf(3);
        let b = test_leaf(4);
        let pred_a = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let pred_b = Node::join(Uint::eq_tag(), b.digest(), b.digest());

        // This is semantically equivalent to canonical output, but it emits `b` before the first
        // transcript step's closure. Strict wire rejects the non-canonical order.
        let wire = wire(alloc::vec![
            value_entry(&b),
            value_entry(&a),
            WireEntry::Join { tag: pred_a.tag, lhs: 2, rhs: 2 },
            WireEntry::Join {
                tag: Tag::AND,
                lhs: crate::deferred::TRUE_INDEX,
                rhs: 3,
            },
            WireEntry::Join { tag: pred_b.tag, lhs: 1, rhs: 1 },
            WireEntry::Join { tag: Tag::AND, lhs: 4, rhs: 5 },
        ]);

        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
    }

    #[test]
    fn rehydrate_rejects_failed_predicate() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let a = state.register(&registry, test_leaf(3)).unwrap();
        let b = state.register(&registry, test_leaf(4)).unwrap();

        let bad_pred = Node::join(Uint::eq_tag(), a, b);
        let bad_digest = bad_pred.digest();
        state.insert_node(bad_pred).unwrap();
        let and_node = Node::and(TRUE_DIGEST, bad_digest);
        let and_digest = and_node.digest();
        state.insert_node(and_node).unwrap();
        state.root = and_digest;

        let wire = state.to_wire(&registry).unwrap();
        assert_rehydrate_err!(wire, &registry, IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_and_with_non_true_child() {
        let mut state = DeferredState::new(usize::MAX);
        let registry = precompiles();
        let leaf = state.register(&registry, test_leaf(3)).unwrap();
        let and_node = Node::and(TRUE_DIGEST, leaf);
        let and_digest = and_node.digest();
        state.insert_node(and_node).unwrap();
        state.root = and_digest;

        let wire = state.to_wire(&registry).unwrap();
        assert_rehydrate_err!(wire, &registry, IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_and_with_non_true_lhs() {
        let a = test_leaf(7);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let wire = wire(alloc::vec![
            value_entry(&a),
            WireEntry::Join { tag: pred.tag, lhs: 1, rhs: 1 },
            WireEntry::Join { tag: Tag::AND, lhs: 1, rhs: 2 },
        ]);

        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::EvaluationFailed(_));
    }

    #[test]
    fn rehydrate_rejects_dangling_entry_as_noncanonical() {
        let a = test_leaf(7);
        let orphan = test_leaf(99);
        let pred = Node::join(Uint::eq_tag(), a.digest(), a.digest());
        let wire = wire(alloc::vec![
            value_entry(&orphan),
            value_entry(&a),
            WireEntry::Join { tag: pred.tag, lhs: 2, rhs: 2 },
            WireEntry::Join {
                tag: Tag::AND,
                lhs: crate::deferred::TRUE_INDEX,
                rhs: 3,
            },
        ]);

        assert_rehydrate_err!(wire, &precompiles(), IntegrityError::InvalidStructure);
    }
}
