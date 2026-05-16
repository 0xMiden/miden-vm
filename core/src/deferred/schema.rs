//! The [`Schema`] trait — the entire semantic layer of the deferred-DAG subsystem.
//!
//! The processor maintains an opaque content-addressed store of nodes plus a single transcript
//! root pointer. Everything else — what tags exist, how to decode them, how to evaluate — lives
//! in a [`Schema`] impl that the user installs at processor construction. The processor itself
//! does not interpret tag bytes; the schema is responsible for tag decoding and recursive
//! evaluation.
//!
//! Composition is the user's job. Typically:
//!
//! ```ignore
//! enum AppSchema { Field0(Field0), Curve(Curve), Hash(Hash) }
//! impl Schema for AppSchema { /* delegate decode + reduce to the right variant */ }
//! ```

use super::{Digest, Node, Tag};

// SCHEMA ERROR
// ================================================================================================

/// Errors returned by [`Schema`] implementations and the helpers that drive them.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// No schema was installed on the processor; deferred events cannot be handled.
    #[error("no deferred-DAG schema installed on the processor")]
    NoSchemaInstalled,

    /// A digest referenced by an op-node payload is not in the DAG.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// The node failed schema validation: the tag did not decode, or the constructed
    /// payload variant disagrees with what `decode(tag)` returned.
    #[error("node failed schema validation")]
    InvalidNode,

    /// A predicate node's two operands evaluated to disagreeing canonical forms (or some other
    /// schema-defined predicate-evaluation failure).
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A schema-defined error (typically wrapping the type-specific error of the user's
    /// handler set).
    #[error(transparent)]
    Other(#[from] super::DeferredError),
}

// BODY SHAPE
// ================================================================================================

/// Structural shape of a node's body. Distinguishes the fixed-size 8-felt expression payload
/// from a variable-length chunk payload (`n` 8-felt blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyShape {
    /// 8-felt expression payload — leaves, op-nodes, and predicates.
    Expression,
    /// `n` 8-felt chunks — bulk-data leaves.
    Chunk(u32),
}

// TAG INFO
// ================================================================================================

/// Type signature of a tag: what shape its body takes and what tag its canonical form carries.
///
/// - `evaluates_to == `[`super::TRUE_TAG`] marks the tag as a predicate — its `reduce` returns
///   [`super::true_node`] on success and [`SchemaError::AssertionFailed`] on mismatch.
/// - `evaluates_to == self_tag` marks the tag as self-evaluating (a canonical leaf).
/// - Otherwise the tag describes an op whose canonical form bears the given tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    pub body: BodyShape,
    pub evaluates_to: super::Tag,
}

impl TagInfo {
    /// Returns `true` iff this tag's canonical form is the TRUE sentinel — i.e. the tag
    /// describes a predicate.
    pub fn is_predicate(&self) -> bool {
        self.evaluates_to == super::TRUE_TAG
    }
}

// REDUCE CTX
// ================================================================================================

/// Recursive context supplied to [`Schema::reduce`].
///
/// Two capabilities:
///
/// - [`resolve`](Self::resolve) — walk a child digest to its canonical form. The framework
///   reduces the child via `Schema::reduce` and interns both the input and the canonical along
///   the way, so `reduce` reads as a depth-first recursive function: "resolve lhs, resolve rhs,
///   combine." Because chunk-handling schemas canonicalise chunks to a digest-leaf expression,
///   parent op/assertion schemas only ever see expression-shaped canonical forms.
/// - [`intern`](Self::intern) — mint a brand-new canonical node into the DAG mid-`reduce`, and
///   get its digest back so the returned canonical can reference it by child digest. Required
///   for compound canonicals (e.g. a group element whose payload contains coordinate-leaf
///   digests that were just computed). Idempotent by digest; the framework does NOT re-reduce
///   the interned node, so it's the schema's responsibility to pass a node that is already in
///   canonical form (e.g. a self-evaluating leaf).
///
/// Why a trait (vs. a closure): `reduce` is itself recursive through `resolve` — the context's
/// implementation calls back into `Schema::reduce`. That requires a *named* type (a closure
/// can't pass itself to a function it calls). The trait is the seam between prover-side and
/// verifier-side reducers — both back onto [`crate::deferred::DeferredState`].
pub trait ReduceCtx {
    /// Walk `digest` to its canonical form. Errors with [`SchemaError::MissingNode`] if the
    /// digest is not in the DAG.
    fn resolve(&mut self, digest: Digest) -> Result<Node, SchemaError>;

    /// Intern `node` into the DAG and return its digest. `node` is assumed already canonical
    /// — the framework does not re-reduce it. Idempotent: interning the same node twice is a
    /// no-op.
    fn intern(&mut self, node: Node) -> Digest;
}

// SCHEMA TRAIT
// ================================================================================================

/// The user-installed schema driving the deferred-DAG subsystem.
///
/// Two methods own the entire semantic surface:
///
/// - [`decode`](Self::decode) inspects the 4-felt tag and returns the node's role
///   ([`NodeType`]). The tag alone fully determines this — payload is opaque to the schema at
///   classification time. A schema chooses its own tag encoding (e.g. `[type_prefix, role_marker,
///   length, …]`) and `decode` is the inverse.
/// - [`reduce`](Self::reduce) reduces a node to its canonical form, using a [`ReduceCtx`] to
///   recursively reduce each child digest it references and (if needed) mint canonical
///   auxiliary nodes whose digests appear in the returned canonical's payload. Schema-defined
///   payload-validity checks (e.g. "leaf limbs must be u32-canonical") live inside `reduce` —
///   they fire when the node is actually used, which keeps the trait surface to two methods.
///
/// `reduce` takes `&self` only — the schema is stateless from the driver's perspective. Any
/// per-schema memoization that ever becomes necessary should live in [`super::DeferredState`]
/// (or the verifier's witness-side equivalent) as a `digest → canonical` cache, since the
/// speedup is keyed on input digests and benefits any schema.
pub trait Schema: core::fmt::Debug + Send {
    /// Decodes the tag to its type signature: body shape and canonical-form tag.
    ///
    /// Returning `Err(SchemaError::InvalidNode)` rejects the tag entirely. Otherwise the
    /// returned [`TagInfo`] tells the framework (1) how to parse this tag's body
    /// ([`BodyShape::Expression`] for 8 felts vs [`BodyShape::Chunk`] for `n` 8-felt blocks),
    /// and (2) what tag this node's canonical form will bear after `reduce` — used both for
    /// the advice-push policy on evaluate (no push for predicates) and as a post-`reduce`
    /// sanity check.
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError>;

    /// Reduces `node` to its canonical form. The schema picks the child digests off
    /// `node.payload` and calls `ctx.resolve(d)` on each to get the corresponding canonical-form
    /// child node back. If the canonical form references *new* child digests (e.g. a producing
    /// op on a compound-canonical app), the schema calls `ctx.intern(child)` to mint them.
    ///
    /// Output type must match `decode(node.tag).evaluates_to`:
    /// - **Self-evaluating leaf** (`evaluates_to == node.tag`): the schema returns a clone of
    ///   the node, optionally first validating the payload (e.g. limb canonicality).
    /// - **Producing op** (`evaluates_to == some_canonical_tag`): the schema resolves its
    ///   children and combines them, returning a new node with the canonical tag. Compound
    ///   canonicals (those whose payload contains by-digest children) mint those children via
    ///   `ctx.intern`.
    /// - **Predicate** (`evaluates_to == TRUE_TAG`): the schema resolves its operands, checks
    ///   the predicate, and returns [`super::true_node`] on success or
    ///   [`SchemaError::AssertionFailed`] on mismatch.
    /// - **Chunk body**: typically reduces to a digest-leaf expression so chunk-as-child
    ///   appears to parent ops as a normal expression after canonicalisation.
    ///
    /// `node` is borrowed (not consumed) so the framework can intern it by-move after this call
    /// returns — saving a chunk-sized clone on every reduction.
    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError>;
}

// NOOP SCHEMA
// ================================================================================================

/// A schema that claims no tags.
///
/// Installed by default on every `miden_processor::FastProcessor`; any deferred event executed
/// without first installing a real schema surfaces [`SchemaError::NoSchemaInstalled`] (via
/// `decode` returning `Err`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSchema;

impl Schema for NoopSchema {
    fn decode(&self, _tag: Tag) -> Result<TagInfo, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }

    fn reduce(&self, _node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        deferred::{Payload, Tag},
    };

    const TEST_TAG: Tag = [
        Felt::new_unchecked(7),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ];

    /// A reduce-context that never gets called — used in schema-only tests.
    struct NeverCtx;
    impl ReduceCtx for NeverCtx {
        fn resolve(&mut self, _digest: Digest) -> Result<Node, SchemaError> {
            panic!("NoopSchema must not request any children");
        }
        fn intern(&mut self, _node: Node) -> Digest {
            panic!("NoopSchema must not mint any nodes");
        }
    }

    #[test]
    fn noop_schema_rejects_everything() {
        let schema = NoopSchema;
        let payload = Payload::new([Felt::from_u32(0); 8]);
        let node = Node::expression(TEST_TAG, payload);

        assert!(matches!(schema.decode(node.tag), Err(SchemaError::NoSchemaInstalled)));
        let err = schema.reduce(&node, &mut NeverCtx).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }
}
