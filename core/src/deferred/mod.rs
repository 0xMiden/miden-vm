//! Content-addressed deferred computation for precompile-backed VM hints.
//!
//! Deferred events let programs commit opaque statements during execution and leave their
//! semantic checks to installed [`Precompile`]s. The framework stores those commitments as a DAG
//! of [`Node`]s and a transcript root that verifies by evaluating every logged statement to TRUE.
//!
//! `miden-core` owns the data model, registry, state, and wire validation; the processor only
//! provides system-event plumbing. Reference precompiles live in `crate::testing::precompile`.

mod node;
mod precompile;
mod precompile_registry;
mod state;
mod wire;

use alloc::boxed::Box;

pub use node::{DataChunk, Digest, Node, NodeType, Payload, TRUE_DIGEST, Tag};
pub use precompile::{Precompile, precompile_id};
pub use precompile_registry::PrecompileRegistry;
pub use state::{DeferredContext, DeferredState};
pub use wire::{DeferredStateWire, IntegrityError, TRUE_INDEX, WireEntry};

// ERROR
// ================================================================================================

/// Coarse deferred-framework failures shared by state and reference precompiles.
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
    #[error("invalid deferred root transition: expected {expected}, computed {actual}")]
    InvalidDeferredRootTransition { expected: Digest, actual: Digest },
    #[error("operation is not supported by this handler")]
    Unsupported,
}

/// Errors produced while evaluating deferred nodes through precompiles.
#[derive(Debug, thiserror::Error)]
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
