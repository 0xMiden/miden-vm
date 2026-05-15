//! The [`Schema`] trait — the entire semantic layer of the deferred-DAG subsystem.
//!
//! The processor maintains an opaque content-addressed store of nodes plus a list of assertion
//! nodes and a running transcript. Everything else — what tags exist, how to decode them, how to
//! evaluate, how to compare — lives in a [`Schema`] impl that the user installs at processor
//! construction. The processor itself does not interpret tag bytes; the schema is responsible
//! for tag decoding and recursive evaluation.
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

    /// A digest referenced by an op-node or assertion payload is not in the DAG.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// The node failed schema validation: the tag did not decode, or the constructed
    /// payload variant disagrees with what `decode(tag)` returned.
    #[error("node failed schema validation")]
    InvalidNode,

    /// An assertion node's two operands evaluated to disagreeing canonical forms.
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A schema-defined error (typically wrapping the type-specific error of the user's
    /// handler set).
    #[error(transparent)]
    Other(#[from] super::DeferredError),
}

// NODE TYPE
// ================================================================================================

/// Classification returned by [`Schema::decode`] for a given tag.
///
/// The processor routes a registered node based on this verdict — into the DAG node map for
/// expressions and chunks, or into the assertion list (with transcript fold + verification) for
/// assertions. `Chunk(n)` carries the number of 8-felt chunks the tag declares, letting the
/// processor know how much memory to read for `adv.register_deferred_chunk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// A storable computation node (leaf or op). Inserted into `DeferredState::nodes`.
    Expression,
    /// A bulk-data leaf carrying `n` 8-felt chunks. Inserted into `DeferredState::nodes`.
    Chunk(u32),
    /// An equality-assertion record. Appended to `DeferredState::assertions`, folded into the
    /// running transcript, and verified via [`Schema::reduce`] before the handler returns.
    Assertion,
}

// BODY SHAPE
// ================================================================================================

/// Structural shape of a node's body. Distinguishes the fixed-size 8-felt expression payload
/// from a variable-length chunk payload (`n` 8-felt blocks).
///
/// Carried inside [`TagInfo`] as part of the future replacement for [`NodeType`]; today it's
/// also derivable from the existing enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyShape {
    /// 8-felt expression payload — leaves and binary-op nodes.
    Expression,
    /// `n` 8-felt chunks — bulk-data leaves.
    Chunk(u32),
}

// TAG INFO
// ================================================================================================

/// Type signature of a tag: what shape its body takes and what tag its canonical form
/// carries. Future replacement for [`NodeType`] (see step 7 of the refactor plan).
///
/// - `evaluates_to == `[`super::TRUE_TAG`] marks the tag as a predicate — its `reduce` returns
///   [`super::true_node`] on success.
/// - `evaluates_to == self_tag` marks the tag as self-evaluating (a canonical leaf).
/// - Otherwise the tag describes an op whose canonical form bears the given tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    pub body: BodyShape,
    pub evaluates_to: super::Tag,
}

// CHILD RESOLVER
// ================================================================================================

/// Recursive resolver supplied to [`Schema::reduce`].
///
/// A schema impl calls [`Self::resolve`] on each child digest it discovers in `node.payload`.
/// The resolver returns that child's *canonical* form — already fully reduced — letting
/// `reduce` read like a depth-first recursive function: "resolve lhs, resolve rhs, combine."
///
/// Because chunk-handling schemas canonicalise chunks to a digest-leaf expression in their
/// `reduce`, parent op/assertion schemas only ever see expression-shaped canonical forms — they
/// never have to pattern-match on chunk payloads themselves.
///
/// Why a trait (vs. a closure): `reduce` is itself recursive through the resolver — the
/// resolver's implementation calls back into `Schema::reduce`. That requires a *named* type
/// (a closure can't pass itself to a function it calls). The trait is also the seam between
/// the prover-side store ([`crate::deferred::DeferredState`]) and a future verifier-side store
/// backed by a [`super::DeferredWitness`] — same schema, different backend.
pub trait ChildResolver {
    fn resolve(&mut self, digest: Digest) -> Result<Node, SchemaError>;
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
/// - [`reduce`](Self::reduce) reduces a node to its canonical form, using a [`ChildResolver`] to
///   recursively reduce each child digest it references. Schema-defined payload-validity checks
///   (e.g. "leaf limbs must be u32-canonical") live inside `reduce` — they fire when the node is
///   actually used, which keeps the trait surface to two methods.
///
/// `reduce` takes `&self` only — the schema is stateless from the driver's perspective. Any
/// per-schema memoization that ever becomes necessary should live in [`super::DeferredState`]
/// (or the verifier's witness-side equivalent) as a `digest → canonical` cache, since the
/// speedup is keyed on input digests and benefits any schema.
pub trait Schema: core::fmt::Debug + Send {
    /// Decodes the tag to determine the node's role and (for chunks) length.
    ///
    /// Returning `Err(SchemaError::InvalidNode)` rejects the tag entirely. Otherwise the returned
    /// [`NodeType`] tells the processor where to route a node bearing this tag: expression and
    /// chunk variants land in the DAG node map; assertions are appended, folded into the
    /// transcript, and verified via [`Self::reduce`].
    fn decode(&self, tag: Tag) -> Result<NodeType, SchemaError>;

    /// Reduces `node` to its canonical form. The schema picks the child digests off
    /// `node.payload` and calls `children.resolve(d)` on each to get the corresponding
    /// canonical-form child node back.
    ///
    /// For an expression leaf the schema returns a clone of the node, optionally first
    /// validating the payload (e.g. limb canonicality). For a binary-op expression it resolves
    /// both children and combines them. For a chunk node it typically computes a non-native hash
    /// over the bulk data and returns an expression digest-leaf — so a chunk-as-child appears to
    /// the parent op/assertion schema as a normal expression after canonicalisation. For an
    /// assertion the schema compares the resolved operands and returns either a clone of `node`
    /// (on success) or [`SchemaError::AssertionFailed`] (on mismatch).
    ///
    /// `node` is borrowed (not consumed) so the framework can intern it by-move after this call
    /// returns — saving a chunk-sized clone on every reduction. Schemas that need to return the
    /// input unchanged (leaves and assertions) clone it cheaply (8-felt payload + tag).
    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError>;
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
    fn decode(&self, _tag: Tag) -> Result<NodeType, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }

    fn reduce(
        &self,
        _node: &Node,
        _children: &mut dyn ChildResolver,
    ) -> Result<Node, SchemaError> {
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

    /// A child resolver that never gets called — used in schema-only tests.
    struct NeverResolve;
    impl ChildResolver for NeverResolve {
        fn resolve(&mut self, _digest: Digest) -> Result<Node, SchemaError> {
            panic!("NoopSchema must not request any children");
        }
    }

    #[test]
    fn noop_schema_rejects_everything() {
        let schema = NoopSchema;
        let payload = Payload::new([Felt::from_u32(0); 8]);
        let node = Node::expression(TEST_TAG, payload);

        assert!(matches!(schema.decode(node.tag), Err(SchemaError::NoSchemaInstalled)));
        let err = schema.reduce(&node, &mut NeverResolve).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }
}
