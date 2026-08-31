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
pub use precompile::{Precompile, precompile_id};
pub use precompile_registry::PrecompileRegistry;
pub use state::{DeferredContext, DeferredState};
pub use wire::{DeferredStateWire, IntegrityError};
pub use witness::{PrecompileWitness, PrecompileWitnessError};

use crate::Word;

/// The deferred root committed in public inputs.
pub type DeferredRoot = Digest;

/// Fixed capacity word used to domain-separate deferred root folds.
pub const DEFERRED_ROOT_DOMAIN: Word = Word::new(Tag::AND.as_word());

/// Hard maximum approximate number of field elements allowed in deferred state.
pub const MAX_DEFERRED_ELEMENTS: usize = 1 << 20;

/// Hard maximum number of nodes stored in one deferred state.
///
/// This includes the implicit TRUE node, precompile initialization nodes, caller-registered nodes,
/// and canonical/helper nodes created during evaluation.
pub const MAX_DEFERRED_NODES: usize = 1 << 16;

/// Hard maximum structural depth reachable from a deferred root.
///
/// The root has depth zero, and each structural edge increases depth by one.
pub const MAX_DEFERRED_DAG_DEPTH: usize = 1 << 10;

/// Hard maximum logical byte capacity of one deferred data payload.
///
/// A [`DataChunk`] has eight field elements and represents 32 packed bytes, so this permits at
/// most 32,768 chunks in one data node.
pub const MAX_DEFERRED_DATA_BYTES: usize = 1 << 20;

/// Hard maximum number of structural digest pairs in one deferred pair-list payload.
pub const MAX_DEFERRED_PAIR_LIST_PAIRS: usize = 1 << 8;

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
    #[error("deferred insertion would store {num_nodes} nodes, maximum is {max}")]
    DeferredStateTooManyNodes { num_nodes: usize, max: usize },
    #[error("deferred node depth {depth} exceeds the maximum of {max}")]
    DeferredNodeTooDeep { depth: usize, max: usize },
    #[error("deferred data payload is {num_bytes} bytes, maximum is {max}")]
    DeferredDataTooLarge { num_bytes: usize, max: usize },
    #[error("deferred pair-list payload has {num_pairs} pairs, maximum is {max}")]
    DeferredPairListTooLarge { num_pairs: usize, max: usize },
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
