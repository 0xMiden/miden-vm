//! Content-addressed deferred computation for VM hints.
//!
//! Deferred events let programs commit opaque statements during execution and leave their
//! semantic checks to installed [`Precompile`]s. The framework stores those commitments as a DAG
//! of [`Node`]s and a deferred root commitment that verifies by evaluating every logged statement
//! to TRUE.
//!
//! `miden-core` owns the data model, registry, state, and wire validation; the processor only
//! provides system-event plumbing.

mod claim;
mod node;
mod precompile;
mod precompile_registry;
mod state;
mod wire;
mod witness;

use alloc::boxed::Box;

pub use claim::DeferredClaim;
pub use node::{DataChunk, Digest, Node, NodeType, Payload, TRUE_DIGEST, Tag};
pub use precompile::Precompile;
pub use precompile_registry::PrecompileRegistry;
pub use state::{DeferredContext, DeferredState};
pub use wire::{DeferredStateWire, IntegrityError};
pub use witness::{PrecompileWitness, PrecompileWitnessError};

use crate::{
    Felt, Word,
    program::domain::{DEFERRED_AND_DOMAIN_ID, DEFERRED_CHUNKS_DOMAIN_ID, domain_selector},
};

/// The deferred root committed in public inputs.
pub type DeferredRoot = Digest;

/// Eidos domain selector for semantic AND nodes and rolling deferred-root folds.
pub const DEFERRED_AND_DOMAIN: Felt = domain_selector(DEFERRED_AND_DOMAIN_ID, 1);

/// Eidos domain selector for framework-owned CHUNKS nodes.
pub const DEFERRED_CHUNKS_DOMAIN: Felt = domain_selector(DEFERRED_CHUNKS_DOMAIN_ID, 1);

/// Fixed initial Eidos chaining value for deferred AND nodes and rolling-root folds.
///
/// This is
/// `Eidos::init_chaining_word(DEFERRED_AND_DOMAIN.as_canonical_u64() as u32, 8)`. It is spelled out
/// so the consensus-critical value remains a `const` usable by AIR definitions.
pub const DEFERRED_AND_INIT_CV: Word = Word::new([
    Felt::new_unchecked(4280581857109607169),
    Felt::new_unchecked(2688637132020383752),
    Felt::new_unchecked(1947077364412317696),
    Felt::new_unchecked(6620516959492505600),
]);

/// Hard maximum approximate number of field elements allowed in deferred state.
pub const MAX_DEFERRED_ELEMENTS: usize = 1 << 20;

/// Hard library safety ceiling for ordered precompile roots.
///
/// This bounds root-vector allocation and aggregate-root folding.
pub const MAX_PRECOMPILE_ROOTS: usize = 1 << 12;

/// Folds a verified deferred statement into the rolling deferred root.
pub fn fold_deferred_root(root: DeferredRoot, statement: Digest) -> DeferredRoot {
    Node::and(root, statement).digest()
}

// ERROR
// ================================================================================================

/// Coarse deferred-framework failures shared by deferred state and precompile evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeferredError {
    #[error("invalid or unknown deferred tag")]
    InvalidTag,
    #[error("referenced digest is not present in deferred state")]
    MissingNode,
    #[error("conflicting node definition for digest")]
    ConflictingNode,
    #[error("payload is not valid for the given tag")]
    InvalidPayload,
    #[error("equality assertion failed")]
    AssertionFailed,
    #[error("deferred insertion requires {num_elements} elements but only {max} remain")]
    DeferredStateTooLarge { num_elements: usize, max: usize },
    #[error("operation is not supported by this handler")]
    Unsupported,
    #[error("invalid deferred root transition: expected {expected:?}, got {actual:?}")]
    InvalidDeferredRootTransition { expected: Digest, actual: Digest },
}

/// Errors produced while evaluating deferred nodes through precompiles.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PrecompileError {
    /// A referenced child digest is not present in `DeferredState.nodes`.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// A tag is unknown or its payload shape is invalid for the decoded node type.
    #[error("node failed precompile validation")]
    InvalidNode,

    /// A precompile predicate evaluated to false.
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A framework-level error surfaced by a precompile evaluation.
    #[error(transparent)]
    Other(#[from] DeferredError),

    /// Adds the owning precompile's name to a tag or evaluation failure.
    ///
    /// Registry construction errors are setup-time panics and are not represented here.
    #[error("precompile `{name}`: {source}")]
    Precompile {
        name: &'static str,
        source: Box<PrecompileError>,
    },
}

impl PrecompileError {
    /// Returns the underlying failure without registry attribution wrappers.
    pub fn root(&self) -> &PrecompileError {
        match self {
            PrecompileError::Precompile { source, .. } => source.root(),
            other => other,
        }
    }

    pub(crate) fn with_precompile(name: &'static str, source: PrecompileError) -> Self {
        Self::Precompile { name, source: Box::new(source) }
    }
}

#[cfg(test)]
mod tests {
    use miden_crypto::hash::eidos::Eidos;

    use super::*;

    #[test]
    fn deferred_and_init_cv_matches_its_eidos_derivation() {
        assert_eq!(
            DEFERRED_AND_INIT_CV,
            Eidos::init_chaining_word(DEFERRED_AND_DOMAIN.as_canonical_u64() as u32, 8),
        );
    }
}
