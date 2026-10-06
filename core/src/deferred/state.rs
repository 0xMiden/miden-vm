use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_crypto::hash::eidos::{EidosDomain, EidosFrame};

use super::{
    DEFERRED_AND_FRAME, DeferredError, Digest, Node, NodeType, PrecompileError, PrecompileLimits,
    PrecompileRegistry, PrecompileWitness, PrecompileWork, PreparedNode, TRUE_DIGEST,
};
use crate::program::domain::DeferredChunksDomain;

/// Deferred graph and eager evaluation state.
///
/// Semantic graph state is delegated to `DeferredEvaluator`; this wrapper adds the current root
/// and execution-time admission policy. [`Self::into_witness`] independently admits and exports
/// only the original root-reachable graph under a verification policy, then releases the state.
#[derive(Debug, Clone)]
pub struct DeferredState {
    evaluator: DeferredEvaluator,
    pub(super) root: Digest,
    execution_work: PrecompileWork,
    execution_limits: PrecompileLimits,
}

/// The semantic engine shared by execution and already-admitted witness evaluation.
#[derive(Debug, Clone)]
pub(super) struct DeferredEvaluator {
    registry: Arc<PrecompileRegistry>,
    nodes: BTreeMap<Digest, Node>,
    evals: BTreeMap<Digest, Digest>,
}

impl Default for DeferredState {
    fn default() -> Self {
        Self::new(Arc::new(PrecompileRegistry::new()), PrecompileLimits::new(u64::MAX))
            .expect("empty registry initialization cannot fail")
    }
}

impl DeferredState {
    pub fn new(
        registry: Arc<PrecompileRegistry>,
        execution_limits: PrecompileLimits,
    ) -> Result<Self, PrecompileError> {
        Ok(Self {
            evaluator: DeferredEvaluator::new(registry)?,
            root: TRUE_DIGEST,
            execution_work: PrecompileWork::default(),
            execution_limits,
        })
    }

    /// Adds precompiles without discarding existing nodes, evaluation memos, root, or work
    /// accounting.
    ///
    /// Registration is additive only: duplicate precompile domains panic via
    /// [`PrecompileRegistry::merge`], matching setup-time registry construction behavior. The
    /// state is cloned before mutation so failed precompile initialization leaves `self`
    /// unchanged.
    pub fn extend_precompiles(
        &mut self,
        precompiles: PrecompileRegistry,
    ) -> Result<(), PrecompileError> {
        let mut next = self.clone();
        Arc::make_mut(&mut next.evaluator.registry).merge(precompiles);
        next.evaluator.initialize_precompile_nodes()?;

        *self = next;
        Ok(())
    }

    pub fn registry(&self) -> &PrecompileRegistry {
        &self.evaluator.registry
    }

    /// Returns the current deferred root; [`super::TRUE_DIGEST`] means no statements are logged.
    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.evaluator.get_node(digest)
    }

    /// Returns the already-memoized canonical digest for `digest`, if present.
    ///
    /// This is strictly read-only: it does not evaluate `digest`, validate deferred nodes, insert
    /// canonical results, or mutate the memo table. Missing memos and dangling memos whose
    /// canonical node is absent from this state both return `None`.
    pub fn get_canonical_digest(&self, digest: Digest) -> Option<Digest> {
        self.evaluator.get_canonical_digest(digest)
    }

    /// Returns the already-memoized canonical node for `digest`, if present.
    ///
    /// This is strictly read-only and returns only canonical results that are already memoized and
    /// stored in this state.
    pub fn get_canonical_node(&self, digest: Digest) -> Option<(Digest, &Node)> {
        let canonical_digest = self.get_canonical_digest(digest)?;
        self.evaluator.nodes.get(&canonical_digest).map(|node| (canonical_digest, node))
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

    /// Replaces the execution admission policy used for subsequent guest operations.
    ///
    /// The replacement must admit all work already consumed by this execution.
    pub fn set_execution_limits(
        &mut self,
        limits: PrecompileLimits,
    ) -> Result<(), PrecompileError> {
        self.execution_work.validate(&limits)?;
        self.execution_limits = limits;
        Ok(())
    }

    /// Recognizes `frame` under the installed registry and returns its declared outer payload
    /// shape.
    ///
    /// This does not inspect a payload, validate structural child references, or evaluate
    /// precompile semantics. [`Self::register`] performs those checks for a complete node.
    pub fn decode(&self, frame: EidosFrame) -> Result<NodeType, PrecompileError> {
        self.evaluator.registry.decode_node_type(frame)
    }

    /// Registers a `PrecompileRegistry`-valid node in the DAG and evaluates it immediately.
    ///
    /// Registration validates the node shape and child references, stores the original node under
    /// its own digest, evaluates it under the current registry, stores the canonical result node,
    /// preserves helper nodes registered during evaluation, and records the evaluation memo from
    /// original digest to canonical digest. The returned digest is always the original node digest.
    /// If evaluation fails, registration returns that error immediately. Every guest registration
    /// attempt is charged before storage or evaluation, including duplicate nodes; storage and
    /// successful semantic evaluation remain deduplicated internally.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        self.evaluator.validate_node(&node)?;
        self.execution_work
            .charge_node(&node, &self.evaluator.registry, &self.execution_limits)?;
        let prepared = PreparedNode::new(node);
        let digest = self.evaluator.insert_node(prepared)?;
        self.evaluate_digest(digest)?;
        Ok(digest)
    }

    /// Logs a statement commitment after proving the current root and statement evaluate to TRUE.
    ///
    /// The statement digest must already be registered (present in `nodes`), unless it is the
    /// implicit [`TRUE_DIGEST`]. On success, this inserts the framework AND node, advances the
    /// deferred root, memoizes the new root as TRUE, and returns the new root.
    pub fn log_statement(&mut self, statement_digest: Digest) -> Result<Digest, PrecompileError> {
        let statement = Node::and(self.root, statement_digest);
        self.execution_work.charge_node(
            &statement,
            &self.evaluator.registry,
            &self.execution_limits,
        )?;
        let statement = PreparedNode::new(statement);
        self.evaluator.require_true_eval(self.root)?;
        self.evaluator.require_true_eval(statement_digest)?;
        self.accept_statement(statement)
    }

    /// Logs a statement only if its constrained transition matches `expected_new_root`.
    ///
    /// The VM constrains `log_deferred` as an Eidos fold over the previous deferred root and
    /// the statement digest. A mismatched commitment leaves the root unchanged, but the attempted
    /// root node remains charged as guest work.
    pub fn log_verified_statement(
        &mut self,
        statement_digest: Digest,
        expected_new_root: Digest,
    ) -> Result<Digest, PrecompileError> {
        let statement = Node::and(self.root, statement_digest);
        self.execution_work.charge_node(
            &statement,
            &self.evaluator.registry,
            &self.execution_limits,
        )?;
        let statement = PreparedNode::new(statement);
        let actual_new_root = statement.digest();
        if actual_new_root != expected_new_root {
            return Err(DeferredError::InvalidDeferredRootTransition {
                expected: expected_new_root,
                actual: actual_new_root,
            }
            .into());
        }
        self.evaluator.require_true_eval(self.root)?;
        self.evaluator.require_true_eval(statement_digest)?;
        self.accept_statement(statement)
    }

    /// Evaluates a registered node addressed by digest and returns the canonical node digest.
    ///
    /// Evaluation memoization is an implementation detail: callers receive the canonical digest
    /// whether the result was already known or computed by this call. Use [`Self::get_node`] with
    /// the returned digest to inspect the canonical node contents.
    pub fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        self.evaluator.evaluate_digest(digest)
    }

    /// Consumes completed execution state and exports its root-reachable portable graph.
    ///
    /// Executions without logged work return `None`. Export preserves original node commitments,
    /// omits unreachable nodes and evaluation caches, and charges every unique explicit node under
    /// `verification_limits`; it does not serialize through bytes.
    pub fn into_witness(
        self,
        verification_limits: &PrecompileLimits,
    ) -> Result<Option<PrecompileWitness>, PrecompileError> {
        if self.root == TRUE_DIGEST {
            return Ok(None);
        }
        PrecompileWitness::from_state(&self, verification_limits).map(Some)
    }

    fn accept_statement(&mut self, statement: PreparedNode) -> Result<Digest, PrecompileError> {
        let new_root = self.evaluator.insert_node(statement)?;
        self.evaluator.record_eval(new_root, TRUE_DIGEST)?;
        self.root = new_root;
        Ok(new_root)
    }
}

impl DeferredEvaluator {
    pub(super) fn new(registry: Arc<PrecompileRegistry>) -> Result<Self, PrecompileError> {
        let mut nodes = BTreeMap::new();
        nodes.insert(TRUE_DIGEST, Node::TRUE);
        let mut evals = BTreeMap::new();
        evals.insert(TRUE_DIGEST, TRUE_DIGEST);
        let mut evaluator = Self { registry, nodes, evals };
        evaluator.initialize_precompile_nodes()?;
        Ok(evaluator)
    }

    /// Loads and evaluates fixed registry bootstrap nodes without charging guest work.
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

    pub(super) fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    fn get_canonical_digest(&self, digest: Digest) -> Option<Digest> {
        let canonical = self.evals.get(&digest).copied()?;
        self.nodes.contains_key(&canonical).then_some(canonical)
    }

    fn prepare_node(&self, node: Node) -> Result<PreparedNode, PrecompileError> {
        self.validate_node(&node)?;
        Ok(PreparedNode::new(node))
    }

    fn validate_node(&self, node: &Node) -> Result<(), PrecompileError> {
        self.registry.validate_node(node)?;
        for child in node.children() {
            if child != TRUE_DIGEST && !self.nodes.contains_key(&child) {
                return Err(PrecompileError::MissingNode);
            }
        }
        Ok(())
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
                self.nodes.insert(digest, node);
                Ok(digest)
            },
        }
    }

    pub(super) fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        if let Some(canonical) = self.evals.get(&digest).copied() {
            return self
                .nodes
                .contains_key(&canonical)
                .then_some(canonical)
                .ok_or(PrecompileError::MissingNode);
        }
        let node = self.nodes.get(&digest).ok_or(PrecompileError::MissingNode)?.clone();
        let canonical_digest = if node.is_true() {
            TRUE_DIGEST
        } else if node.frame() == Some(DEFERRED_AND_FRAME) {
            let (lhs, rhs) = node.payload().as_join()?;
            for child in [lhs, rhs] {
                self.require_true_eval(child)?;
            }
            TRUE_DIGEST
        } else if node.frame().is_some_and(|frame| frame.domain() == DeferredChunksDomain::TAG) {
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
    evaluator: &'a mut DeferredEvaluator,
}

impl<'a> DeferredContext<'a> {
    /// Binds state for one framework-driven evaluation.
    fn new(evaluator: &'a mut DeferredEvaluator) -> Self {
        Self { evaluator }
    }

    /// Returns the registered node addressed by `digest`, if present.
    ///
    /// This is a syntactic DAG lookup: it does not evaluate the node or canonicalize it.
    pub fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.evaluator.get_node(digest)
    }

    /// Evaluates a registered child digest and returns the canonical node digest.
    ///
    /// The `nodes` membership check preserves the registered child closure; memoization is
    /// transparent to precompile implementations. Use
    /// [`Self::get_node`] with the returned digest to inspect the canonical node contents.
    pub fn evaluate_digest(&mut self, digest: Digest) -> Result<Digest, PrecompileError> {
        self.evaluator.evaluate_digest(digest)
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
    /// evaluation. The helper is evaluated eagerly, but is not guest work and therefore does not
    /// pass through execution admission.
    pub fn register(&mut self, node: Node) -> Result<Digest, PrecompileError> {
        let prepared = self.evaluator.prepare_node(node)?;
        let digest = self.evaluator.insert_node(prepared)?;
        self.evaluator.evaluate_digest(digest)?;
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::hash::eidos::DomainTag;

    use super::*;
    use crate::{
        ZERO,
        deferred::{
            Payload, Precompile, PrecompileLimitError, WorkClass, WorkItem, WorkLimit,
            precompile::test_precompile_domain_tag,
        },
    };

    const FIXTURE_WORK: WorkClass = WorkClass::new("state-fixture");

    fn fixture_limits(max_count: u64) -> PrecompileLimits {
        PrecompileLimits::new(u64::MAX).with_class(
            FIXTURE_WORK,
            WorkLimit {
                max_count,
                max_total_size: u64::MAX,
                max_size: u32::MAX,
            },
        )
    }

    #[derive(Debug, Clone, Copy)]
    struct FixturePrecompile;

    impl FixturePrecompile {
        fn frame(self, mode: u32) -> EidosFrame {
            EidosFrame::new(self.domain(), [mode, 0, 0])
        }

        fn node(self, mode: u32) -> Node {
            Node::value(self.frame(mode), [ZERO; 8]).unwrap()
        }
    }

    impl Precompile for FixturePrecompile {
        fn name(&self) -> &'static str {
            "deferred-state-fixture"
        }

        fn domain(&self) -> DomainTag {
            test_precompile_domain_tag(2)
        }

        fn decode(&self, params: [u32; 3]) -> Option<NodeType> {
            (params[0] <= 1 && params[1] == 0 && params[2] == 0).then_some(NodeType::Data)
        }

        fn validate_payload(&self, _params: [u32; 3], payload: &Payload) -> bool {
            payload.as_value().is_ok()
        }

        fn work(&self, _params: [u32; 3], _payload: &Payload) -> Result<WorkItem, PrecompileError> {
            Ok(WorkItem::new(FIXTURE_WORK, 1))
        }

        fn evaluate(
            &self,
            params: [u32; 3],
            payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            match params[0] {
                0 => Err(PrecompileError::AssertionFailed),
                1 => Node::try_data(self.frame(99), payload.as_data()?.to_vec())
                    .map_err(PrecompileError::from),
                _ => unreachable!("decode admits only fixture modes"),
            }
        }
    }

    #[test]
    fn failed_duplicate_registration_attempts_are_charged() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, fixture_limits(1)).unwrap();
        let node = precompile.node(0);
        let digest = node.digest();

        let error = state.register(node.clone()).unwrap_err();

        assert!(matches!(error.root(), PrecompileError::AssertionFailed));
        assert_eq!(state.get_canonical_digest(digest), None);
        assert_eq!(state.execution_work.class(FIXTURE_WORK).unwrap().count(), 1);
        assert!(matches!(
            state.register(node),
            Err(PrecompileError::Limit(PrecompileLimitError::Count {
                class: FIXTURE_WORK,
                actual: 2,
                max: 1,
            }))
        ));
    }

    #[test]
    fn register_enforces_work_policy_before_evaluation() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, fixture_limits(0)).unwrap();
        let node = precompile.node(0);
        let digest = node.digest();

        let error = state.register(node).unwrap_err();

        assert!(matches!(error, PrecompileError::Limit(_)));
        assert!(state.get_node(&digest).is_none());
        assert_eq!(state.execution_work, PrecompileWork::default());
    }

    #[test]
    fn execution_limits_cannot_be_lowered_below_consumed_work() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, fixture_limits(u64::MAX)).unwrap();
        let node = precompile.node(0);
        assert!(matches!(
            state.register(node.clone()).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));

        let error = state.set_execution_limits(fixture_limits(0)).unwrap_err();

        assert!(matches!(
            error,
            PrecompileError::Limit(PrecompileLimitError::Count {
                class: FIXTURE_WORK,
                actual: 1,
                max: 0,
            })
        ));
        assert!(matches!(
            state.register(node).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));
        assert_eq!(state.execution_work.class(FIXTURE_WORK).unwrap().count(), 2);
    }

    #[test]
    fn evaluation_validates_a_new_canonical_before_storing_it() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, fixture_limits(u64::MAX)).unwrap();
        let input = precompile.node(1);
        let input_digest = input.digest();
        let invalid = Node::value(precompile.frame(99), [ZERO; 8]).unwrap();

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
        assert_eq!(ordinary.execution_work.nodes(), 1);

        let mut verified = DeferredState::default();
        let mismatch = Node::and(expected, TRUE_DIGEST).digest();
        assert!(matches!(
            verified.log_verified_statement(TRUE_DIGEST, mismatch).unwrap_err(),
            PrecompileError::Other(DeferredError::InvalidDeferredRootTransition { .. })
        ));
        assert_eq!(verified.root(), TRUE_DIGEST);
        assert!(verified.get_node(&expected).is_none());
        assert_eq!(verified.execution_work.nodes(), 1);

        assert_eq!(
            verified.log_verified_statement(TRUE_DIGEST, expected).unwrap(),
            ordinary.root()
        );
        assert_eq!(verified.get_canonical_digest(expected), Some(TRUE_DIGEST));
        assert_eq!(verified.execution_work.nodes(), 2);
    }

    #[test]
    fn verified_root_mismatch_precedes_statement_evaluation() {
        let precompile = FixturePrecompile;
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(precompile));
        let mut state = DeferredState::new(registry, fixture_limits(u64::MAX)).unwrap();
        let statement = state.evaluator.insert_node(PreparedNode::new(precompile.node(0))).unwrap();
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
