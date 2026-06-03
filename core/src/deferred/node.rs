//! Shared precompile vocabulary: node shapes and evaluation errors.
//!
//! The processor stores deferred nodes opaquely. Tag ownership, shape validation, and recursive
//! evaluation live behind the [`Precompile`](super::Precompile)s in a
//! [`PrecompileRegistry`](super::PrecompileRegistry).

use alloc::boxed::Box;
use core::num::NonZeroU32;

use super::{DeferredError, Digest, Payload};

// NODE TYPE
// ================================================================================================

/// Shape a precompile declares for a recognized tag.
///
/// The shape tells registration and wire validation whether a body is non-empty opaque data or two
/// child digests. `True` is the framework sentinel owned exclusively by [`super::Tag::TRUE`];
/// precompiles never declare it. Predicate status is not a shape; predicates succeed by evaluating
/// to [`super::Node::TRUE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// The framework TRUE sentinel, with no data payload.
    True,
    /// Non-empty opaque data whose [`super::DataChunk`] count is fixed by the tag.
    Data(NonZeroU32),
    /// Two child digests.
    Join,
}

impl NodeType {
    /// Validates that a payload variant matches this declared shape.
    pub(crate) fn validate_payload(self, payload: &Payload) -> Result<(), DeferredError> {
        match self {
            Self::True if payload.is_true() => Ok(()),
            Self::Data(n)
                if payload.as_data().is_ok_and(|chunks| chunks.len() == n.get() as usize) =>
            {
                Ok(())
            },
            Self::Join if payload.as_join().is_ok() => Ok(()),
            _ => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns this payload's structural children, if the shape declares child references.
    pub(crate) fn children(
        self,
        payload: &Payload,
    ) -> Result<Option<(Digest, Digest)>, DeferredError> {
        match self {
            Self::Join => payload.as_join().map(Some),
            Self::True | Self::Data(_) => Ok(None),
        }
    }
}

// PRECOMPILE ERROR
// ================================================================================================

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
}
