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
//! impl Schema for AppSchema { /* delegate is_valid + eval to the right variant */ }
//! ```

use miden_core::deferred::Node;

use super::state::DeferredState;

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
    Other(#[from] miden_core::deferred::DeferredError),
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
    /// running transcript, and verified via [`Schema::eval`] before the handler returns.
    Assertion,
}

// SCHEMA TRAIT
// ================================================================================================

/// The user-installed schema driving the deferred-DAG subsystem.
///
/// Two methods own the entire semantic surface:
///
/// - [`is_valid`](Self::is_valid) classifies a node at register time. `None` rejects it.
/// - [`eval`](Self::eval) executes the node's semantics: for expressions it reduces to canonical
///   form; for assertions it evaluates both operands, compares them, and returns
///   [`SchemaError::AssertionFailed`] on mismatch. The processor uses `eval` for both purposes —
///   "reduce this node" and "verify this assertion" are the same call.
pub trait Schema: core::fmt::Debug + Send {
    /// Classifies the node at register time.
    ///
    /// - `None` rejects the registration (maps to [`SchemaError::InvalidNode`]).
    /// - `Some(NodeType::Expression)` inserts the node into the DAG node map.
    /// - `Some(NodeType::Assertion)` appends the node to the assertion list, folds it into the
    ///   running transcript, and triggers verification via [`Self::eval`].
    fn is_valid(&self, node: &Node) -> Option<NodeType>;

    /// Executes the semantics of `node`.
    ///
    /// For expression nodes this reduces `node` to its canonical form, recursing into children
    /// via `graph` as needed. For assertion nodes this evaluates the two operands referenced in
    /// `node.payload`, compares them, and returns [`SchemaError::AssertionFailed`] if they
    /// disagree. The return value is the canonical form for expressions, or simply `node`
    /// itself for assertions (the caller ignores it — verification is the side effect).
    ///
    /// `&mut self` lets implementations memoize evaluation across calls.
    fn eval(&mut self, graph: &DeferredState, node: Node) -> Result<Node, SchemaError>;
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

    fn eval(&mut self, _graph: &DeferredState, _node: Node) -> Result<Node, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }
}

#[cfg(test)]
mod tests {
    use miden_core::Felt;

    use super::*;

    const TEST_TAG: miden_core::deferred::Tag = [
        Felt::new_unchecked(7),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ];

    #[test]
    fn noop_schema_rejects_everything() {
        let mut schema = NoopSchema;
        let payload = miden_core::deferred::Payload::new([Felt::from_u32(0); 8]);
        let node = Node::new(TEST_TAG, payload);

        assert!(schema.is_valid(&node).is_none());
        let graph = DeferredState::new();
        let err = schema.eval(&graph, node).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }
}
