use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use super::{
    DeferredError, Digest, IntegrityError, MAX_DEFERRED_ELEMENTS, Node, NodeType, PrecompileError,
    PrecompileRegistry, PrecompileWitness, PreparedNode, TRUE_DIGEST, Tag,
};

/// Deferred graph and eager evaluation state.
///
/// Registered original nodes, canonical/helper nodes, evaluation memos, the current root, and the
/// element budget live here. [`Self::into_witness`] exports only the original root-reachable graph
/// and releases the state.
#[derive(Debug, Clone)]
pub struct DeferredState {
    registry: Arc<PrecompileRegistry>,
    // Every entry has a registry-valid shape, has child closure for the state in which it was
    // admitted, and is stored under the digest checked when its `PreparedNode` was constructed.
    nodes: BTreeMap<Digest, Node>,
    pub(super) root: Digest,
    evals: BTreeMap<Digest, Digest>,
    remaining_elements: usize,
}

impl Default for DeferredState {
    fn default() -> Self {
        Self::new(Arc::new(PrecompileRegistry::new()))
            .expect("empty registry initialization cannot fail")
    }
}

impl DeferredState {
    pub fn new(registry: Arc<PrecompileRegistry>) -> Result<Self, PrecompileError> {
        let mut state = Self::empty(registry);
        state.initialize_precompile_nodes()?;
        Ok(state)
    }

    /// Creates a state seeded only with framework basics.
    fn empty(registry: Arc<PrecompileRegistry>) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);

        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, TRUE_DIGEST);

        Self {
            registry,
            nodes,
            root: TRUE_DIGEST,
            evals,
            remaining_elements: MAX_DEFERRED_ELEMENTS,
        }
    }

    /// Loads all precompile initialization nodes, then evaluates each to ensure the bootstrap set
    /// resolves under this registry.
    fn initialize_precompile_nodes(&mut self) -> Result<(), PrecompileError> {
        let mut prepared_nodes = Vec::new();
        for node in self.registry.init_nodes() {
            self.registry.validate_node(&node)?;
            prepared_nodes.push(PreparedNode::new(node));
        }
        let init_digests = prepared_nodes.iter().map(PreparedNode::digest).collect::<Vec<_>>();
        for prepared in prepared_nodes {
            if prepared.node().children().any(|child| {
                child != TRUE_DIGEST
                    && !self.nodes.contains_key(&child)
                    && !init_digests.contains(&child)
            }) {
                return Err(PrecompileError::MissingNode);
            }
            self.insert_node(prepared)?;
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

    /// Returns the approximate number of field elements occupied by registered deferred nodes.
    pub fn num_elements(&self) -> usize {
        self.nodes
            .iter()
            .filter_map(|(digest, node)| {
                (*digest != TRUE_DIGEST).then_some(node.storage_felt_len())
            })
            .sum()
    }

    pub fn remaining_elements(&self) -> usize {
        self.remaining_elements
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
        let prepared = self.prepare_node(node)?;
        let digest = self.insert_node(prepared)?;
        self.evaluate_digest(digest)?;
        Ok(digest)
    }

    /// Logs a statement commitment after proving the current root and statement evaluate to TRUE.
    ///
    /// The statement digest must already be registered (present in `nodes`), unless it is the
    /// implicit [`TRUE_DIGEST`]. On success, this inserts the framework AND node, advances the
    /// deferred root, memoizes the new root as TRUE, and returns the new root.
    pub fn log_statement(&mut self, statement_digest: Digest) -> Result<Digest, PrecompileError> {
        let statement = self.prepare_statement(statement_digest)?;
        self.accept_statement(statement)
    }

    /// Logs a statement only if its constrained transition matches `expected_new_root`.
    ///
    /// The VM constrains `log_deferred` as a Poseidon2 fold over the previous deferred root and
    /// the statement digest. A mismatched commitment leaves the root unchanged.
    pub fn log_verified_statement(
        &mut self,
        statement_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<Digest, PrecompileError> {
        let statement = PreparedNode::new(Node::and(self.root, statement_digest));
        let actual_new_root = statement.digest();
        if actual_new_root != expected_new_root {
            return Err(DeferredError::InvalidDeferredRootTransition {
                expected: expected_new_root,
                actual: actual_new_root,
            }
            .into());
        }

        self.require_true_eval(self.root)?;
        self.require_true_eval(statement_digest)?;
        self.accept_statement(statement)
    }

    /// Evaluates a registered node addressed by digest and returns the canonical node digest.
    ///
    /// Evaluation memoization is an implementation detail: callers receive the canonical digest
    /// whether the result was already known or computed by this call. Use [`Self::get_node`] with
    /// the returned digest to inspect the canonical node contents.
    pub fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        if let Some(canonical) = self.evals.get(&digest).copied() {
            return self
                .nodes
                .contains_key(&canonical)
                .then_some(canonical)
                .ok_or(PrecompileError::MissingNode);
        }

        let node = self.nodes.get(&digest).ok_or(PrecompileError::MissingNode)?.clone();
        let canonical_digest = if node.tag() == Tag::TRUE {
            TRUE_DIGEST
        } else if node.tag() == Tag::AND {
            let (lhs, rhs) = node.payload().as_join()?;
            for child in [lhs, rhs] {
                self.require_true_eval(child)?;
            }
            TRUE_DIGEST
        } else if node.tag() == Tag::CHUNKS {
            digest
        } else {
            let registry = Arc::clone(&self.registry);
            let mut context = DeferredContext::new(self);
            let canonical = registry.evaluate(&node, &mut context)?;
            if canonical == node {
                digest
            } else if canonical == Node::TRUE {
                TRUE_DIGEST
            } else {
                let prepared = self.prepare_node(canonical)?;
                self.insert_node(prepared)?
            }
        };

        self.record_eval(digest, canonical_digest)?;
        Ok(canonical_digest)
    }

    /// Consumes completed execution state and exports its root-reachable portable graph.
    ///
    /// Executions without logged work return `None`. Export preserves original node commitments
    /// and omits unreachable nodes and evaluation caches; it does not serialize through bytes.
    pub fn into_witness(self) -> Result<Option<PrecompileWitness>, IntegrityError> {
        if self.root == TRUE_DIGEST {
            return Ok(None);
        }
        PrecompileWitness::from_state(&self).map(Some)
    }

    fn prepare_node(&self, node: Node) -> Result<PreparedNode, PrecompileError> {
        self.registry.validate_node(&node)?;
        for child in node.children() {
            if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                return Err(PrecompileError::MissingNode);
            }
        }
        Ok(PreparedNode::new(node))
    }

    pub(super) fn insert_node(
        &mut self,
        prepared: PreparedNode,
    ) -> Result<Digest, PrecompileError> {
        let (digest, node) = prepared.into_parts();
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

    fn record_eval(
        &mut self,
        input_digest: Digest,
        canonical_digest: Digest,
    ) -> Result<(), PrecompileError> {
        if !self.nodes.contains_key(&input_digest) || !self.nodes.contains_key(&canonical_digest) {
            return Err(PrecompileError::MissingNode);
        }
        match self.evals.get(&input_digest) {
            Some(existing) if *existing == canonical_digest => Ok(()),
            Some(_) => Err(DeferredError::ConflictingNode.into()),
            None => {
                self.evals.insert(input_digest, canonical_digest);
                Ok(())
            },
        }
    }

    fn prepare_statement(
        &mut self,
        statement_digest: Digest,
    ) -> Result<PreparedNode, PrecompileError> {
        self.require_true_eval(self.root)?;
        self.require_true_eval(statement_digest)?;
        self.prepare_node(Node::and(self.root, statement_digest))
    }

    fn accept_statement(&mut self, statement: PreparedNode) -> Result<Digest, PrecompileError> {
        let new_root = self.insert_node(statement)?;
        self.record_eval(new_root, TRUE_DIGEST)?;
        self.root = new_root;
        Ok(new_root)
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
/// register helper nodes referenced by compound canonicals during execution.
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
    /// The `nodes` membership check preserves the registered child closure; memoization is
    /// transparent to precompile implementations. Use
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
        deferred::{Payload, Precompile, WorkClass, WorkItem, precompile_id},
    };

    const FIXTURE_WORK: WorkClass = WorkClass::new("state-fixture");

    #[derive(Debug, Clone, Copy)]
    struct FixturePrecompile;

    impl FixturePrecompile {
        fn tag(self, mode: u64) -> Tag {
            Tag::precompile(self.id(), [Felt::new(mode).unwrap(), ZERO, ZERO])
                .expect("fixture id is precompile-owned")
        }

        fn node(self, mode: u64) -> Node {
            Node::value(self.tag(mode), [ZERO; 8]).unwrap()
        }
    }

    impl Precompile for FixturePrecompile {
        fn name(&self) -> &'static str {
            "deferred-state-fixture"
        }

        fn id(&self) -> Felt {
            precompile_id(self.name())
        }

        fn work_classes(&self) -> &'static [WorkClass] {
            &[FIXTURE_WORK]
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            (args[0].as_canonical_u64() <= 1 && args[1] == ZERO && args[2] == ZERO)
                .then_some(NodeType::Data)
        }

        fn work(&self, _args: [Felt; 3], _payload: &Payload) -> Result<WorkItem, PrecompileError> {
            Ok(WorkItem::new(FIXTURE_WORK, 1))
        }

        fn evaluate(
            &self,
            args: [Felt; 3],
            payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            let mode = args[0].as_canonical_u64() as usize;
            match mode {
                0 => Err(PrecompileError::AssertionFailed),
                1 => Node::try_data(
                    Tag::precompile(self.id(), [Felt::new(99).unwrap(), ZERO, ZERO]).unwrap(),
                    payload.as_data()?.to_vec(),
                )
                .map_err(PrecompileError::from),
                _ => unreachable!("decode admits only fixture modes"),
            }
        }
    }

    #[test]
    fn construction_uses_the_fixed_deferred_element_limit() {
        let state = DeferredState::new(Arc::new(PrecompileRegistry::new())).unwrap();
        let default_state = DeferredState::default();

        assert_eq!(state.num_elements(), 0);
        assert_eq!(state.remaining_elements(), MAX_DEFERRED_ELEMENTS);
        assert_eq!(default_state.remaining_elements(), MAX_DEFERRED_ELEMENTS);
    }

    #[test]
    fn register_eagerly_propagates_precompile_evaluation_errors() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry).unwrap();
        let node = precompile.node(0);
        let digest = node.digest();

        let error = state.register(node).unwrap_err();

        assert!(matches!(error.root(), PrecompileError::AssertionFailed));
        assert_eq!(state.get_canonical_digest(digest), None);
    }

    #[test]
    fn evaluation_validates_a_new_canonical_before_storing_it() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry).unwrap();
        let input = precompile.node(1);
        let input_digest = input.digest();
        let invalid = Node::value(
            Tag::precompile(precompile.id(), [Felt::new(99).unwrap(), ZERO, ZERO]).unwrap(),
            [ZERO; 8],
        )
        .unwrap();

        let error = state.register(input).unwrap_err();

        assert!(matches!(error.root(), PrecompileError::InvalidNode));
        assert!(state.get_node(&input_digest).is_some());
        assert!(state.get_node(&invalid.digest()).is_none());
        assert_eq!(state.get_canonical_digest(input_digest), None);
    }

    #[test]
    fn verified_statement_logging_matches_ordinary_logging_and_is_atomic_at_the_root() {
        let expected = Node::and(TRUE_DIGEST, TRUE_DIGEST).digest();
        let mut ordinary = DeferredState::default();
        assert_eq!(ordinary.log_statement(TRUE_DIGEST).unwrap(), expected);

        let mut verified = DeferredState::default();
        let mismatch = Node::and(expected, TRUE_DIGEST).digest();
        assert!(matches!(
            verified.log_verified_statement(TRUE_DIGEST, mismatch).unwrap_err(),
            PrecompileError::Other(DeferredError::InvalidDeferredRootTransition { .. })
        ));
        assert_eq!(verified.root(), TRUE_DIGEST);
        assert!(verified.get_node(&expected).is_none());

        assert_eq!(
            verified.log_verified_statement(TRUE_DIGEST, expected).unwrap(),
            ordinary.root()
        );
        assert_eq!(verified.get_canonical_digest(expected), Some(TRUE_DIGEST));
    }

    #[test]
    fn verified_root_mismatch_precedes_statement_evaluation() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry).unwrap();
        let statement = state.insert_node(PreparedNode::new(precompile.node(0))).unwrap();
        let actual_root = Node::and(TRUE_DIGEST, statement).digest();
        assert_ne!(actual_root, TRUE_DIGEST);

        assert!(matches!(
            state.log_verified_statement(statement, TRUE_DIGEST),
            Err(PrecompileError::Other(DeferredError::InvalidDeferredRootTransition { .. }))
        ));
        assert_eq!(state.root(), TRUE_DIGEST);
        assert_eq!(state.get_canonical_digest(statement), None);

        let error = state.log_verified_statement(statement, actual_root).unwrap_err();
        assert!(matches!(error.root(), PrecompileError::AssertionFailed));
    }
}
