//! Vocabulary shared by the precompile layer: the [`PrecompileError`] type and the
//! [`NodeType`] / [`TagInfo`] tag-signature pair.
//!
//! The processor maintains an opaque content-addressed store of nodes plus a single transcript
//! root pointer. Everything else — what tags exist, how to decode them, how to evaluate — lives
//! in the [`Precompile`](super::Precompile)s held by a [`Precompiles`](super::Precompiles)
//! registry. The processor itself does not interpret tag bytes; the registry dispatches on
//! [`Tag::id`](super::Tag) and each precompile decodes its own [`Tag::imm`](super::Tag) and
//! drives recursive evaluation.

use alloc::boxed::Box;

use super::Tag;

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

    /// A precompile in a [`Precompiles`](super::Precompiles) registry rejected a tag or failed
    /// to reduce a node it owns. Wraps the underlying cause with the offending precompile's name
    /// so dispatch failures are attributable.
    #[error("precompile `{name}`: {source}")]
    Precompile {
        name: &'static str,
        source: Box<PrecompileError>,
    },

    /// A precompile's declared [`Precompile::id`](super::Precompile::id) is inconsistent with
    /// the id derived from its name. Registry construction-time programming error.
    #[error("precompile `{0}` declares an id inconsistent with its name derivation")]
    PrecompileIdMismatch(&'static str),

    /// Two precompiles in a registry resolve to the same id.
    #[error("duplicate precompile id in registry (`{0}` and `{1}`)")]
    DuplicatePrecompileId(&'static str, &'static str),
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
/// `NodeType` and `TagInfo::evaluates_to` are orthogonal: a `Binary` node can be either an
/// op (`evaluates_to == some_canonical_tag`), a predicate (`evaluates_to == TRUE_TAG`), or a
/// self-evaluating compound canonical such as `Group`'s `new` element (`evaluates_to == own_tag`).
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

// TAG INFO
// ================================================================================================

/// Type signature of a tag: what shape its body takes and what tag its canonical form carries.
///
/// - `evaluates_to == `[`super::TRUE_TAG`] marks the tag as a predicate — its `reduce` returns
///   [`super::true_node`] on success and [`PrecompileError::AssertionFailed`] on mismatch.
/// - `evaluates_to == self_tag` marks the tag as self-evaluating (a canonical leaf).
/// - Otherwise the tag describes an op whose canonical form bears the given tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    pub node_type: NodeType,
    pub evaluates_to: Tag,
}

impl TagInfo {
    /// Returns `true` iff this tag's canonical form is the TRUE sentinel — i.e. the tag
    /// describes a predicate.
    pub fn is_predicate(&self) -> bool {
        self.evaluates_to == super::TRUE_TAG
    }
}
