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

    /// Adds precompiles to this state without discarding existing nodes, evaluation memos, root, or
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

    /// Returns the current deferred root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    /// Returns the already-memoized canonical digest for `digest`, if present.
    ///
    /// This is strictly read-only: it does not evaluate `digest`, validate deferred nodes, insert
    /// canonical results, or mutate the memo table. Missing memos and dangling memos whose
    /// canonical node is absent from this state both return `None`.
    pub fn get_canonical_digest(&self, digest: Digest) -> Option<Digest> {
        let canonical_digest = self.evals.get(&digest).copied()?;
        self.nodes.contains_key(&canonical_digest).then_some(canonical_digest)
    }

    /// Returns the already-memoized canonical node for `digest`, if present.
    ///
    /// This is strictly read-only and returns only canonical results that are already memoized and
    /// stored in this state.
    pub fn get_canonical_node(&self, digest: Digest) -> Option<(Digest, &Node)> {
        let canonical_digest = self.get_canonical_digest(digest)?;
        self.nodes.get(&canonical_digest).map(|node| (canonical_digest, node))
    }

    /// Returns the already-memoized canonical node for `digest` or
    /// [`PrecompileError::MissingNode`].
    ///
    /// This is strictly read-only and never evaluates or mutates deferred state.
    pub fn require_canonical_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError> {
        self.get_canonical_node(digest).ok_or(PrecompileError::MissingNode)
    }

    pub fn nodes(&self) -> &BTreeMap<Digest, Node> {
        &self.nodes
    }

    pub fn remaining_elements(&self) -> usize {
        self.remaining_elements
    }

    /// Updates the remaining deferred-node budget without discarding the installed registry,
    /// registered nodes, evaluation memos, or current root.
    ///
    /// If the current state already exceeds the new budget, future non-idempotent node insertions
    /// will fail because the remaining budget is set to zero. This lets callers tighten execution
    /// options without silently dropping proof-relevant deferred state.
    pub fn set_max_elements(&mut self, max_elements: usize) {
        let used_elements = self
            .nodes
            .iter()
            .filter_map(|(digest, node)| {
                (*digest != TRUE_DIGEST).then_some(node.storage_felt_len())
            })
            .sum::<usize>();
        self.remaining_elements = max_elements.saturating_sub(used_elements);
    }

    /// Recognizes `tag` under the installed registry and returns its declared outer payload shape.
    ///
    /// This does not inspect a payload, validate structural child references, or evaluate
    /// precompile semantics. [`Self::register`] performs those checks for a complete node.
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
        self.validate_node_for_insertion(&node)?;
        let digest = self.insert_node(node)?;
        self.evaluate_digest(digest)?;
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

    /// Logs a statement only if its constrained transition matches `expected_new_root`.
    ///
    /// The VM constrains `log_deferred` as a Poseidon2 fold over the previous deferred root and
    /// the statement digest. This helper binds the in-memory deferred DAG to that constrained
    /// transition: it validates the expected root before mutating `self`, then applies the same
    /// semantic checks as [`Self::log_statement`].
    pub fn log_verified_statement(
        &mut self,
        statement_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<Digest, PrecompileError> {
        let actual_new_root = Node::and(self.root, statement_digest).digest();
        if actual_new_root != expected_new_root {
            return Err(DeferredError::InvalidDeferredRootTransition {
                expected: expected_new_root,
                actual: actual_new_root,
            }
            .into());
        }

        self.log_statement(statement_digest)
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
        } else if node.tag() == Tag::CHUNKS {
            node
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
        for child in node.children() {
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
    use super::*;
    use crate::{
        Felt, ZERO,
        deferred::{Payload, Precompile, precompile_id},
    };

    #[derive(Debug, Clone, Copy)]
    struct RejectingPrecompile;

    impl Precompile for RejectingPrecompile {
        fn name(&self) -> &'static str {
            "rejecting-registration-fixture"
        }

        fn id(&self) -> Felt {
            precompile_id(self.name())
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            (args == [ZERO; 3]).then_some(NodeType::Data)
        }

        fn evaluate(
            &self,
            _args: [Felt; 3],
            _payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            Err(PrecompileError::AssertionFailed)
        }
    }

    #[test]
    fn register_eagerly_propagates_precompile_evaluation_errors() {
        let precompile = RejectingPrecompile;
        let tag =
            Tag::precompile(precompile.id(), [ZERO; 3]).expect("fixture id is precompile-owned");
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, usize::MAX).unwrap();
        let node = Node::value(tag, [ZERO; 8]).unwrap();
        let digest = node.digest();

        let error = state.register(node).unwrap_err();

        assert!(matches!(error.root(), PrecompileError::AssertionFailed));
        assert_eq!(state.get_canonical_digest(digest), None);
    }
}
