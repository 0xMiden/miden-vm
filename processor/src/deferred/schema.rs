//! The [`Schema`] trait — the entire semantic layer of the deferred-DAG subsystem.
//!
//! The processor maintains an opaque content-addressed store of `(tag, payload)` nodes plus a
//! queue of assertions. Everything else — what tags exist, how to evaluate, how to compare —
//! lives in a [`Schema`] impl that the user installs at processor construction. The processor
//! itself does not interpret tag bytes; the schema is responsible for tag recognition,
//! recursive evaluation, and equality.
//!
//! Composition is the user's job. Typically:
//!
//! ```ignore
//! enum AppSchema { Field0(Field0), Curve(Curve), Hash(Hash) }
//! impl Schema for AppSchema { /* delegate each method to the variant that responds_to(tag) */ }
//! ```

use alloc::vec::Vec;

use miden_core::{Felt, deferred::{Digest, Node}};

use super::state::DeferredState;

// SCHEMA ERROR
// ================================================================================================

/// Errors returned by [`Schema`] implementations and the helpers that drive them.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// No schema was installed on the processor; deferred events cannot be handled.
    #[error("no deferred-DAG schema installed on the processor")]
    NoSchemaInstalled,

    /// A digest referenced by an op-node payload or by an assertion is not in the DAG.
    #[error("deferred DAG is missing a node referenced during evaluation")]
    MissingNode,

    /// The node failed the schema's well-formedness check (`Schema::is_valid` returned false).
    #[error("node failed schema validation")]
    InvalidNode,

    /// `Schema::assert` reported the two nodes disagree (the bool was true).
    #[error("deferred assertion failed: values disagree")]
    AssertionFailed,

    /// A schema-defined error (typically wrapping the type-specific error of the user's
    /// handler set).
    #[error(transparent)]
    Other(#[from] miden_core::deferred::DeferredError),
}

// SCHEMA TRAIT
// ================================================================================================

/// The user-installed schema driving the deferred-DAG subsystem.
///
/// One `Schema` impl is installed on the processor via
/// [`crate::FastProcessor::with_schema`]. It owns:
///
/// - Tag recognition (`responds_to`) — used by composite schemas to route between sub-handlers.
/// - Node validation (`is_valid`) — called by the processor at `deferred_register` time.
/// - Recursive evaluation (`eval`) — reduces a node to its canonical form, walking children via
///   the graph view by digest.
/// - Equality (`assert`) — with a default implementation that evaluates both sides and compares
///   them as `Node` values; override if the canonical form is not bitwise-unique.
pub trait Schema: core::fmt::Debug + Send {
    /// Returns true if this schema claims the given tag.
    ///
    /// Used by composite (enum-dispatching) schemas to route between variants. The processor
    /// itself never calls this directly — it's a building block for composition.
    fn responds_to(&self, tag: [Felt; 4]) -> bool;

    /// Returns true if this node is well-formed and storable.
    ///
    /// Called by the processor at `deferred_register` time before insertion. Returning false
    /// maps to [`SchemaError::InvalidNode`] at the processor level.
    fn is_valid(&self, node: &Node) -> bool;

    /// Returns the child digests that `node`'s payload references.
    ///
    /// Used by the witness extractor to walk reachability from assertions. Leaf nodes return an
    /// empty `Vec`; op nodes return the digests they would recurse on during `eval`. The default
    /// implementation returns an empty `Vec`, which is correct for schemas with no internal
    /// references.
    fn children(&self, _node: &Node) -> Vec<Digest> {
        Vec::new()
    }

    /// Recursively reduces `node` to its canonical form.
    ///
    /// Child nodes are looked up by digest via `graph`. `&mut self` lets implementations
    /// memoize evaluation results across calls.
    fn eval(&mut self, graph: &DeferredState, node: Node) -> Result<Node, SchemaError>;

    /// Checks whether two nodes evaluate to the same canonical form.
    ///
    /// Returns `Ok(bool)` where the bool indicates *mismatch* — `Ok(true)` means the values
    /// disagree (the assertion would fail); `Ok(false)` means they agree (the assertion would
    /// pass). `Err(...)` is reserved for evaluation failures (a bug, not a soft mismatch).
    ///
    /// The default implementation evaluates both sides and compares the resulting nodes by
    /// bitwise equality. Override if the canonical form is non-unique (e.g. unreduced limbs
    /// that must be normalized before comparison).
    fn assert(
        &mut self,
        graph: &DeferredState,
        lhs: Node,
        rhs: Node,
    ) -> Result<bool, SchemaError> {
        let l = self.eval(graph, lhs)?;
        let r = self.eval(graph, rhs)?;
        Ok(l != r)
    }
}

// NOOP SCHEMA
// ================================================================================================

/// A schema that claims no tags.
///
/// Installed by default on every [`crate::FastProcessor`]; any deferred event executed without
/// first installing a real schema surfaces [`SchemaError::NoSchemaInstalled`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSchema;

impl Schema for NoopSchema {
    fn responds_to(&self, _tag: [Felt; 4]) -> bool {
        false
    }

    fn is_valid(&self, _node: &Node) -> bool {
        false
    }

    fn eval(&mut self, _graph: &DeferredState, _node: Node) -> Result<Node, SchemaError> {
        Err(SchemaError::NoSchemaInstalled)
    }
}

#[cfg(test)]
mod tests {
    use miden_core::Felt;

    use super::*;

    const TEST_TAG: [Felt; 4] = [
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

        assert!(!schema.responds_to(TEST_TAG));
        assert!(!schema.is_valid(&node));
        let graph = DeferredState::new();
        let err = schema.eval(&graph, node).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }

    #[test]
    fn default_assert_compares_canonical_forms() {
        // Trivial schema that returns nodes unchanged. Demonstrates the default `assert` impl
        // signaling mismatch (bool true) vs match (bool false).
        #[derive(Debug, Default)]
        struct Identity;
        impl Schema for Identity {
            fn responds_to(&self, _: [Felt; 4]) -> bool { true }
            fn is_valid(&self, _: &Node) -> bool { true }
            fn eval(&mut self, _: &DeferredState, node: Node) -> Result<Node, SchemaError> {
                Ok(node)
            }
        }

        let mut schema = Identity;
        let graph = DeferredState::new();
        let p_eq = miden_core::deferred::Payload::new([Felt::from_u32(0); 8]);
        let p_diff = miden_core::deferred::Payload::new([Felt::from_u32(1); 8]);

        let match_bool = schema
            .assert(&graph, Node::new(TEST_TAG, p_eq), Node::new(TEST_TAG, p_eq))
            .unwrap();
        assert!(!match_bool, "equal nodes should give bool=false (no mismatch)");

        let mismatch_bool = schema
            .assert(&graph, Node::new(TEST_TAG, p_eq), Node::new(TEST_TAG, p_diff))
            .unwrap();
        assert!(mismatch_bool, "different nodes should give bool=true (mismatch)");
    }
}
