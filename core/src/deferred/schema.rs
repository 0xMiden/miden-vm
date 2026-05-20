//! Vocabulary shared by the precompile layer: the [`PrecompileError`] type and the [`NodeType`]
//! tag-shape classifier.
//!
//! The processor maintains an opaque content-addressed store of nodes plus a single transcript
//! root pointer. Everything else — what tags exist, how to decode them, how to evaluate — lives
//! in the [`Precompile`](super::Precompile)s held by a
//! [`PrecompileRegistry`](super::PrecompileRegistry). The processor itself does not interpret
//! tag bytes; the registry dispatches on [`Tag::id`](super::Tag) and each precompile decodes
//! its own [`Tag::imm`](super::Tag) and drives recursive evaluation.

use alloc::boxed::Box;

// NODE TYPE
// ================================================================================================

/// Structural classification of a node, returned by
/// [`Precompile::decode`](super::Precompile::decode).
///
/// Captures both the in-memory body shape (Expression vs Chunk) AND, for the Expression case,
/// whether the 8 felts encode raw payload data or two child digests packed via
/// [`super::Payload::binary_op`]. This is the unit the wire format and rehydrate logic
/// dispatch on.
///
/// Predicate-ness is *not* encoded here — it is a property of a `reduce` outcome
/// ([`super::Node::is_true_node`] on the canonical), not of the tag's declared shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// 8 felts of raw payload data, no child digests. Self-evaluating value leaves (e.g.
    /// `Uint256` leaf, `MockHash` digest).
    Value,
    /// 8 felts encoding `lhs_digest || rhs_digest` — two child references. Covers binary ops,
    /// binary predicates, AND-nodes, and compound-canonical `new`-style leaves.
    Binary,
    /// `n` 8-felt chunks of bulk data, no child digests. Chunk-bodied leaves (e.g.
    /// `MockHash` preimage, `MockSig` verify).
    Chunks(u32),
}

// PRECOMPILE ERROR
// ================================================================================================

/// Errors returned by [`Precompile`](super::Precompile)s and the helpers that drive them.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileError {
    /// A digest referenced by an op-node payload is not in the DAG.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// The node failed validation: the tag did not decode, or the constructed payload variant
    /// disagrees with what `decode(tag)` returned. Also covers a tag whose `id` matches no
    /// registered precompile — including the empty registry, which rejects every tag.
    #[error("node failed precompile validation")]
    InvalidNode,

    /// A predicate node's two operands evaluated to disagreeing canonical forms (or some other
    /// precompile-defined predicate-evaluation failure).
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A precompile-defined error (typically wrapping the type-specific error of the
    /// precompile's reducer).
    #[error(transparent)]
    Other(#[from] super::DeferredError),

    /// A precompile in a [`PrecompileRegistry`](super::PrecompileRegistry) rejected a tag or
    /// failed to reduce a node it owns. Wraps the underlying cause with the offending
    /// precompile's name so dispatch failures are attributable.
    ///
    /// Registry *construction* errors (id-derivation drift, framework-reserved `ZERO` id,
    /// duplicate id) are not in this enum: they are setup-time programming errors and
    /// [`PrecompileRegistry::with_precompile`](super::PrecompileRegistry::with_precompile)
    /// panics on them.
    #[error("precompile `{name}`: {source}")]
    Precompile {
        name: &'static str,
        source: Box<PrecompileError>,
    },
}

impl PrecompileError {
    /// Peel any [`PrecompileError::Precompile`] wrappers and return the underlying cause. Useful
    /// in `matches!` assertions that care about the root failure, not which precompile raised it.
    pub fn root(&self) -> &PrecompileError {
        match self {
            PrecompileError::Precompile { source, .. } => source.root(),
            other => other,
        }
    }
}
