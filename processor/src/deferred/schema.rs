//! The [`Schema`] trait — the entire semantic layer of the deferred-DAG subsystem.
//!
//! The processor maintains an opaque content-addressed store of `(tag, payload)` nodes plus a
//! list of assertion nodes and a running transcript. Everything else — what tags exist, how to
//! classify them, how to evaluate, how to compare — lives in a [`Schema`] impl that the user
//! installs at processor construction. The processor itself does not interpret tag bytes; the
//! schema is responsible for tag recognition, classification, recursive evaluation, and
//! equality.
//!
//! Composition is the user's job. Typically:
//!
//! ```ignore
//! enum AppSchema { Field0(Field0), Curve(Curve), Hash(Hash) }
//! impl Schema for AppSchema { /* delegate each method to the variant that responds_to(tag) */ }
//! ```

use alloc::vec::Vec;

use miden_core::{
    Word,
    deferred::{Digest, Node, Tag},
};

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

    /// The node failed the schema's classification check (`Schema::is_valid` returned `None`).
    #[error("node failed schema validation")]
    InvalidNode,

    /// `Schema::assert` reported the two operands disagree.
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
    /// running transcript, and verified via [`Schema::assert`] before the handler returns.
    Assertion,
}

// SCHEMA TRAIT
// ================================================================================================

/// The user-installed schema driving the deferred-DAG subsystem.
///
/// One `Schema` impl is installed on the processor via
/// [`crate::FastProcessor::with_schema`]. It owns:
///
/// - Tag recognition (`responds_to`) — used by composite schemas to route between sub-handlers.
/// - Node classification (`is_valid`) — called by the processor at `deferred_register` time;
///   `None` rejects the node, `Some(_)` declares whether it's an expression or assertion.
/// - Child enumeration (`children`) — used by witness extraction to walk reachability from
///   assertion payloads through the expression graph.
/// - Recursive evaluation (`eval`) — reduces a node to its canonical form, walking children via
///   the graph by digest.
/// - Equality (`assert`) — with a default implementation that treats an assertion node's
///   payload as `lhs_digest || rhs_digest`, evaluates both sides, and compares them.
pub trait Schema: core::fmt::Debug + Send {
    /// Returns true if this schema claims the given tag.
    ///
    /// Used by composite (enum-dispatching) schemas to route between variants. The processor
    /// itself never calls this directly — it's a building block for composition.
    fn responds_to(&self, tag: Tag) -> bool;

    /// Classifies the node at register time.
    ///
    /// - `None` rejects the registration (maps to [`SchemaError::InvalidNode`]).
    /// - `Some(NodeType::Expression)` inserts the node into the DAG node map.
    /// - `Some(NodeType::Assertion)` appends the node to the assertion list, folds it into the
    ///   running transcript, and triggers verification via [`Schema::assert`].
    fn is_valid(&self, node: &Node) -> Option<NodeType>;

    /// Returns the child digests that `node`'s payload references.
    ///
    /// Used by witness extraction to walk reachability from each assertion node into the
    /// expression graph. Expression leaves return an empty `Vec`; op nodes and assertion nodes
    /// return the digests their payload encodes. Default impl returns empty, which is correct
    /// for schemas with no internal references.
    fn children(&self, _node: &Node) -> Vec<Digest> {
        Vec::new()
    }

    /// Recursively reduces `node` to its canonical form.
    ///
    /// Child nodes are looked up by digest via `graph`. `&mut self` lets implementations
    /// memoize evaluation results across calls.
    fn eval(&mut self, graph: &DeferredState, node: Node) -> Result<Node, SchemaError>;

    /// Verifies an assertion node.
    ///
    /// `tag` is provided alongside `node` for ergonomic top-level dispatch — `tag == node.tag`
    /// at the call site. Returns `Ok(true)` on mismatch, `Ok(false)` on match, `Err` on
    /// evaluation failure.
    ///
    /// The default implementation treats `node.payload` as binary-op-shaped
    /// (`lhs_digest || rhs_digest`), evaluates both sides, and compares the resulting `Node`s
    /// bitwise. Override for non-binary assertions or for canonical forms that need
    /// normalization before comparison.
    fn assert(
        &mut self,
        graph: &DeferredState,
        _tag: Tag,
        node: Node,
    ) -> Result<bool, SchemaError> {
        let lhs_digest =
            Word::new([node.payload.0[0], node.payload.0[1], node.payload.0[2], node.payload.0[3]]);
        let rhs_digest =
            Word::new([node.payload.0[4], node.payload.0[5], node.payload.0[6], node.payload.0[7]]);
        let lhs = *graph.get(&lhs_digest).ok_or(SchemaError::MissingNode)?;
        let rhs = *graph.get(&rhs_digest).ok_or(SchemaError::MissingNode)?;
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
/// first installing a real schema surfaces [`SchemaError::NoSchemaInstalled`] (via
/// `is_valid` returning `None`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSchema;

impl Schema for NoopSchema {
    fn responds_to(&self, _tag: Tag) -> bool {
        false
    }

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
    use super::super::transaction::{DeferredMutation, HandlerTransaction};

    const TEST_TAG: Tag = [
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
        assert!(schema.is_valid(&node).is_none());
        let graph = DeferredState::new();
        let err = schema.eval(&graph, node).unwrap_err();
        assert!(matches!(err, SchemaError::NoSchemaInstalled));
    }

    #[test]
    fn default_assert_compares_canonical_forms() {
        // Identity schema: every node evaluates to itself. The default `assert` parses the
        // assertion node's payload as (lhs_digest, rhs_digest), fetches both from the graph, and
        // compares them after eval.
        #[derive(Debug, Default)]
        struct Identity;
        impl Schema for Identity {
            fn responds_to(&self, _: Tag) -> bool { true }
            fn is_valid(&self, _: &Node) -> Option<NodeType> { Some(NodeType::Expression) }
            fn eval(&mut self, _: &DeferredState, node: Node) -> Result<Node, SchemaError> {
                Ok(node)
            }
        }

        let mut schema = Identity;
        let mut graph = DeferredState::new();
        let p_eq = miden_core::deferred::Payload::new([Felt::from_u32(0); 8]);
        let p_diff = miden_core::deferred::Payload::new([Felt::from_u32(1); 8]);

        // Pre-insert three operand leaves keyed by their tag bytes (used as ad-hoc digests).
        let lhs_node = Node::new(TEST_TAG, p_eq);
        let rhs_eq_node = Node::new(TEST_TAG, p_eq);
        let rhs_diff_node = Node::new(TEST_TAG, p_diff);
        let lhs_digest = miden_core::deferred::hash_node(TEST_TAG, &p_eq);
        let rhs_eq_digest = lhs_digest;
        let rhs_diff_digest = miden_core::deferred::hash_node(TEST_TAG, &p_diff);

        graph
            .apply(&HandlerTransaction {
                deferred: alloc::vec![
                    DeferredMutation::InsertNode {
                        digest: lhs_digest,
                        node: lhs_node,
                    },
                    DeferredMutation::InsertNode {
                        digest: rhs_diff_digest,
                        node: rhs_diff_node,
                    },
                ],
                vm: alloc::vec::Vec::new(),
            })
            .unwrap();

        // Build an assertion node payload: lhs_digest || lhs_digest (equal case).
        let mut equal_payload = [Felt::from_u32(0); 8];
        equal_payload[..4].copy_from_slice(lhs_digest.as_elements());
        equal_payload[4..].copy_from_slice(rhs_eq_digest.as_elements());
        let _ = rhs_eq_node;
        let equal_node = Node::new(TEST_TAG, miden_core::deferred::Payload::new(equal_payload));
        let match_bool = schema.assert(&graph, TEST_TAG, equal_node).unwrap();
        assert!(!match_bool, "equal operands should give bool=false (no mismatch)");

        // And lhs_digest || rhs_diff_digest (mismatch case).
        let mut diff_payload = [Felt::from_u32(0); 8];
        diff_payload[..4].copy_from_slice(lhs_digest.as_elements());
        diff_payload[4..].copy_from_slice(rhs_diff_digest.as_elements());
        let diff_node = Node::new(TEST_TAG, miden_core::deferred::Payload::new(diff_payload));
        let mismatch_bool = schema.assert(&graph, TEST_TAG, diff_node).unwrap();
        assert!(mismatch_bool, "different operands should give bool=true (mismatch)");
    }
}
