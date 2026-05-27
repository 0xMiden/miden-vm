//! Shared precompile vocabulary: node shapes and reducer errors.
//!
//! The processor stores deferred nodes opaquely. Tag ownership, shape validation, and recursive
//! evaluation live behind the [`Precompile`](super::Precompile)s in a
//! [`PrecompileRegistry`](super::PrecompileRegistry).

use alloc::boxed::Box;
use core::num::NonZeroU32;

// NODE TYPE
// ================================================================================================

/// Shape a precompile declares for a recognized tag.
///
/// The shape tells registration and wire validation whether a body is raw value data, two child
/// digests, or non-empty chunk data. Predicate status is not a shape; predicates succeed by
/// reducing to [`super::Node::TRUE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// One expression block of raw value data.
    Value,
    /// One expression block interpreted as two child digests.
    Join,
    /// Non-empty bulk data whose chunk count is fixed by the tag.
    Chunks(NonZeroU32),
}

// PRECOMPILE ERROR
// ================================================================================================

/// Errors produced while reducing deferred nodes through precompiles.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileError {
    /// A referenced child digest is not committed in the DAG.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// A tag is unknown or its payload shape is invalid for the decoded node type.
    #[error("node failed precompile validation")]
    InvalidNode,

    /// A precompile predicate evaluated to false.
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A framework-level error surfaced by a precompile reducer.
    #[error(transparent)]
    Other(#[from] super::DeferredError),

    /// Adds the owning precompile's name to a tag or reduction failure.
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
}
