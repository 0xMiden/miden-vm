use alloc::vec::Vec;

use super::{
    DeferredState, Digest, IntegrityError, MAX_PRECOMPILE_ROOTS, PrecompileError, TRUE_DIGEST,
    fold_deferred_root,
};

/// A hydrated witness for one or more ordered deferred precompile roots.
///
/// Execution constructs singleton witnesses. [`Self::merge`] combines only singleton inputs and
/// retains their roots in input order, including duplicates.
///
/// A witness may contain private execution data and a large hydrated DAG. Treat it as sensitive
/// prover input, and prefer borrowing it during proving instead of cloning it.
#[derive(Debug, Clone)]
pub struct PrecompileWitness {
    state: DeferredState,
    roots: Vec<Digest>,
}

impl PrecompileWitness {
    /// Creates a singleton witness from a non-empty execution state.
    ///
    /// Singleton eligibility is representation-based: this retains exactly one root, but does not
    /// verify execution provenance.
    pub fn new(state: DeferredState) -> Result<Self, PrecompileWitnessError> {
        let root = state.root();
        if root == TRUE_DIGEST {
            return Err(PrecompileWitnessError::TrueRoot);
        }

        let witness = Self { state, roots: alloc::vec![root] };
        witness.validate()?;
        Ok(witness)
    }

    /// Returns the aggregate root authenticated by the hydrated deferred state.
    pub fn root(&self) -> Digest {
        self.state.root()
    }

    /// Returns the ordered non-TRUE execution roots represented by this witness.
    pub fn roots(&self) -> &[Digest] {
        &self.roots
    }

    /// Returns the hydrated deferred state used by precompile proving.
    pub fn state(&self) -> &DeferredState {
        &self.state
    }

    /// Consumes this witness and returns the hydrated deferred state used by precompile proving.
    pub fn into_state(self) -> DeferredState {
        self.state
    }

    /// Merges ordered singleton witnesses into one aggregate witness.
    ///
    /// All inputs are validated before any deferred state is consumed. Singleton eligibility means
    /// `roots.len() == 1`; execution provenance is not encoded or verified. Witnesses retaining
    /// multiple roots are rejected, so roots cannot be regrouped or merged recursively. The
    /// complete merged state is bounded by [`super::MAX_DEFERRED_ELEMENTS`].
    pub fn merge(witnesses: Vec<Self>) -> Result<Self, PrecompileWitnessError> {
        if witnesses.is_empty() {
            return Err(PrecompileWitnessError::EmptyMerge);
        }
        if witnesses.len() > MAX_PRECOMPILE_ROOTS {
            return Err(PrecompileWitnessError::TooManyRoots {
                roots: witnesses.len(),
                max: MAX_PRECOMPILE_ROOTS,
            });
        }

        for witness in &witnesses {
            witness.validate_singleton()?;
        }

        let roots = witnesses.iter().map(|witness| witness.roots[0]).collect::<Vec<_>>();
        let mut witnesses = witnesses.into_iter();
        let mut state = witnesses.next().expect("non-empty witness input was checked above").state;

        for witness in witnesses {
            state = state.merge(witness.state).map_err(PrecompileWitnessError::Merge)?;
        }

        let expected_root = roots
            .iter()
            .copied()
            .reduce(fold_deferred_root)
            .expect("non-empty witness input retains at least one root");
        if state.root() != expected_root {
            return Err(PrecompileWitnessError::RootMismatch);
        }

        Ok(Self { state, roots })
    }

    fn validate_singleton(&self) -> Result<(), PrecompileWitnessError> {
        if self.roots.len() != 1 {
            return Err(PrecompileWitnessError::NonSingleton);
        }
        self.validate()
    }

    pub(crate) fn validate(&self) -> Result<(), PrecompileWitnessError> {
        if self.roots.contains(&TRUE_DIGEST) {
            return Err(PrecompileWitnessError::TrueRoot);
        }
        if self.roots.iter().any(|root| self.state.get_node(root).is_none()) {
            return Err(PrecompileWitnessError::RootMismatch);
        }

        let expected_root = self
            .roots
            .iter()
            .copied()
            .reduce(fold_deferred_root)
            .expect("witness construction retains at least one root");
        if self.state.root() != expected_root {
            return Err(PrecompileWitnessError::RootMismatch);
        }

        Ok(())
    }
}

/// Errors produced while constructing or merging precompile witnesses.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileWitnessError {
    /// A witness cannot represent an empty deferred execution.
    #[error("precompile witness roots must differ from TRUE_DIGEST")]
    TrueRoot,

    /// A merge operation requires at least one singleton witness.
    #[error("cannot merge an empty precompile witness list")]
    EmptyMerge,
    /// The ordered root sequence exceeds the hard allocation and folding safety ceiling.
    #[error("precompile witness contains too many roots: found {roots}, maximum is {max}")]
    TooManyRoots { roots: usize, max: usize },
    /// Merge inputs must come directly from individual executions.
    #[error("precompile witness merge inputs must each contain exactly one root")]
    NonSingleton,
    /// The retained roots do not describe the hydrated deferred state.
    #[error("precompile witness roots do not match its deferred state")]
    RootMismatch,
    /// Sequential deferred-state aggregation failed.
    #[error("failed to merge deferred precompile states: {0}")]
    Merge(#[source] PrecompileError),
    /// Deferred wire rehydration failed.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;
    use crate::{
        Felt, ZERO,
        deferred::{
            DeferredContext, MAX_DEFERRED_ELEMENTS, Node, NodeType, Payload, Precompile,
            PrecompileRegistry, Tag, precompile_id,
        },
    };

    fn framework_state(statement_depth: usize) -> DeferredState {
        let mut state = DeferredState::default();
        let mut statement = TRUE_DIGEST;
        for _ in 0..statement_depth {
            statement = state.register(Node::and(statement, TRUE_DIGEST)).unwrap();
        }
        state.log_statement(statement).unwrap();
        state
    }

    fn singleton(statement_depth: usize) -> PrecompileWitness {
        PrecompileWitness::new(framework_state(statement_depth)).unwrap()
    }

    #[derive(Debug, Clone, Copy)]
    struct FixturePrecompile;

    impl FixturePrecompile {
        const NAME: &'static str = "precompile-witness-fixture";

        fn tag() -> Tag {
            Tag::precompile(precompile_id(Self::NAME), [ZERO; 3])
                .expect("fixture id is precompile-owned")
        }
    }

    impl Precompile for FixturePrecompile {
        fn name(&self) -> &'static str {
            Self::NAME
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
            Ok(Node::TRUE)
        }
    }

    fn fixture_witness() -> PrecompileWitness {
        let registry = Arc::new(PrecompileRegistry::new().with_precompile(FixturePrecompile));
        let mut state = DeferredState::new(registry).unwrap();
        let statement = state
            .register(Node::value(FixturePrecompile::tag(), [ZERO; 8]).unwrap())
            .unwrap();
        state.log_statement(statement).unwrap();
        PrecompileWitness::new(state).unwrap()
    }

    #[test]
    fn singleton_construction_rejects_true_and_retains_execution_root() {
        assert!(matches!(
            PrecompileWitness::new(DeferredState::default()),
            Err(PrecompileWitnessError::TrueRoot)
        ));

        let state = framework_state(1);
        let root = state.root();
        let witness = PrecompileWitness::new(state).unwrap();

        assert_eq!(witness.root(), root);
        assert_eq!(witness.roots(), &[root]);
        assert_eq!(witness.state().root(), root);
    }

    #[test]
    fn merge_rejects_empty_input() {
        assert!(matches!(
            PrecompileWitness::merge(Vec::new()),
            Err(PrecompileWitnessError::EmptyMerge)
        ));
    }

    #[test]
    fn merge_preserves_order_and_changes_the_aggregate_when_reversed() {
        let first = singleton(1);
        let second = singleton(2);
        let first_root = first.root();
        let second_root = second.root();

        let ordered = PrecompileWitness::merge(alloc::vec![first.clone(), second.clone()]).unwrap();
        let reversed = PrecompileWitness::merge(alloc::vec![second, first]).unwrap();

        assert_eq!(ordered.roots(), &[first_root, second_root]);
        assert_eq!(ordered.root(), fold_deferred_root(first_root, second_root));
        assert_eq!(reversed.roots(), &[second_root, first_root]);
        assert_eq!(reversed.root(), fold_deferred_root(second_root, first_root));
        assert_ne!(ordered.root(), reversed.root());
    }

    #[test]
    fn merge_preserves_duplicate_singleton_roots() {
        let witness = singleton(1);
        let root = witness.root();

        let merged = PrecompileWitness::merge(alloc::vec![witness.clone(), witness]).unwrap();

        assert_eq!(merged.roots(), &[root, root]);
        assert_eq!(merged.root(), fold_deferred_root(root, root));
    }

    #[test]
    fn merge_rejects_an_already_merged_input_during_prevalidation() {
        let merged = PrecompileWitness::merge(alloc::vec![singleton(1), singleton(2)]).unwrap();

        let error = PrecompileWitness::merge(alloc::vec![singleton(3), fixture_witness(), merged])
            .unwrap_err();

        assert!(matches!(error, PrecompileWitnessError::NonSingleton));
    }

    #[test]
    fn one_element_merge_is_a_singleton_identity() {
        let witness = singleton(1);
        let root = witness.root();
        let num_elements = witness.state().num_elements();

        let merged = PrecompileWitness::merge(alloc::vec![witness]).unwrap();

        assert_eq!(merged.root(), root);
        assert_eq!(merged.roots(), &[root]);
        assert_eq!(merged.state().num_elements(), num_elements);
        assert_eq!(merged.state().remaining_elements(), MAX_DEFERRED_ELEMENTS - num_elements);
    }

    #[test]
    fn merge_rejects_excessive_root_count() {
        let witnesses = alloc::vec![singleton(1); MAX_PRECOMPILE_ROOTS + 1];

        assert!(matches!(
            PrecompileWitness::merge(witnesses),
            Err(PrecompileWitnessError::TooManyRoots {
                roots,
                max: MAX_PRECOMPILE_ROOTS,
            }) if roots == MAX_PRECOMPILE_ROOTS + 1
        ));
    }
}
