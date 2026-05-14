//! The [`Schema`] trait — the entire semantic layer of the deferred-DAG subsystem.
//!
//! The processor maintains an opaque content-addressed store of `(tag, payload)` nodes plus a
//! list of assertion nodes and a running transcript. Everything else — what tags exist, how to
//! classify them, how to evaluate, how to compare — lives in a [`Schema`] impl that the user
//! installs at processor construction. The processor itself does not interpret tag bytes; the
//! schema is responsible for classification and recursive evaluation.
//!
//! Composition is the user's job. Typically:
//!
//! ```ignore
//! enum AppSchema { Field0(Field0), Curve(Curve), Hash(Hash) }
//! impl Schema for AppSchema { /* delegate is_valid + reduce to the right variant */ }
//! ```

use super::{Digest, Node};

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

    /// The node failed the schema's classification check (`Schema::is_valid` returned `None`).
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

/// Classification produced by [`Schema::is_valid`] at register time.
///
/// The processor routes the registered node based on this verdict — into the DAG node map for
/// expressions, or into the assertion list (with transcript fold + verification) for assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// A storable computation node (leaf or op). Inserted into `DeferredState::nodes`.
    Expression,
    /// An equality-assertion record. Appended to `DeferredState::assertions`, folded into the
    /// running transcript, and verified via [`Schema::reduce`] before the handler returns.
    Assertion,
}

// CHILD RESOLVER
// ================================================================================================

/// Recursive resolver supplied to [`Schema::reduce`].
///
/// A schema impl calls [`Self::resolve`] on each child digest it discovers in `node.payload`.
/// The resolver returns that child's *canonical* form — already fully reduced — letting
/// `reduce` read like a depth-first recursive function: "resolve lhs, resolve rhs, combine."
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
/// - [`is_valid`](Self::is_valid) classifies a node at register time. `None` rejects it.
/// - [`reduce`](Self::reduce) reduces a node to its canonical form, using a [`ChildResolver`]
///   to recursively reduce each child digest it references.
///
/// `reduce` takes `&self` only — the schema is stateless from the driver's perspective. Any
/// per-schema memoization that ever becomes necessary should live in [`DeferredState`] (or
/// the verifier's witness-side equivalent) as a `digest → canonical` cache, since the speedup
/// is keyed on input digests and benefits any schema.
pub trait Schema: core::fmt::Debug + Send {
    /// Classifies the node at register time.
    ///
    /// - `None` rejects the registration (maps to [`SchemaError::InvalidNode`]).
    /// - `Some(NodeType::Expression)` inserts the node into the DAG node map.
    /// - `Some(NodeType::Assertion)` appends the node to the assertion list, folds it into the
    ///   running transcript, and triggers verification via [`Self::reduce`].
    fn is_valid(&self, node: &Node) -> Option<NodeType>;

    /// Reduces `node` to its canonical form. The schema picks the child digests off
    /// `node.payload` and calls `children.resolve(d)` on each to get the corresponding
    /// canonical-form child node back.
    ///
    /// For expression nodes the return value is the canonical form. For assertion nodes the
    /// schema compares the resolved operands and returns either `node` itself (on success) or
    /// [`SchemaError::AssertionFailed`] (on mismatch).
    fn reduce(
        &self,
        node: Node,
        children: &mut dyn ChildResolver,
    ) -> Result<Node, SchemaError>;
}

// NOOP SCHEMA
// ================================================================================================

/// A schema that claims no tags.
///
/// Installed by default on every [`crate::FastProcessor`]; any deferred event executed without
/// first installing a real schema surfaces [`SchemaError::NoSchemaInstalled`] (via
/// `is_valid` returning `None`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSchema;

impl Schema for NoopSchema {
    fn is_valid(&self, _node: &Node) -> Option<NodeType> {
        None
    }

    fn reduce(
        &self,
        _node: Node,
        _children: &mut dyn ChildResolver,
    ) -> Result<Node, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Felt, deferred::{Payload, Tag}};

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
        let node = Node::new(TEST_TAG, payload);

        assert!(schema.is_valid(&node).is_none());
        let err = schema.reduce(node, &mut NeverResolve).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }
}
