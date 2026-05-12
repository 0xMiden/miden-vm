use crate::Word;

use super::{DeferredTag, Digest, Payload, TagKind};

/// A DAG node identified by `hash_node(tag, payload)`.
///
/// A node's [`Digest`] is the map key under which it is stored — it is never stored in the node
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub tag: DeferredTag,
    pub payload: Payload,
}

impl Node {
    pub fn new(tag: DeferredTag, payload: Payload) -> Self {
        Self { tag, payload }
    }

    /// For binary-op nodes, returns the `(lhs, rhs)` child digests stored in the payload's
    /// first four and last four felts. Leaves and assert-eq tags return `None`.
    pub fn binary_op_children(&self) -> Option<(Digest, Digest)> {
        if self.tag.kind() != TagKind::BinaryOp {
            return None;
        }
        let lhs =
            Word::new([self.payload.0[0], self.payload.0[1], self.payload.0[2], self.payload.0[3]]);
        let rhs =
            Word::new([self.payload.0[4], self.payload.0[5], self.payload.0[6], self.payload.0[7]]);
        Some((lhs, rhs))
    }
}

/// An equality assertion linking two DAG nodes by their digests.
///
/// The assertion's `tag` identifies which type's equality semantics apply. The assertion does not
/// store the evaluated values — those are recomputed by the verifier from the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    pub tag: DeferredTag,
    pub lhs: Digest,
    pub rhs: Digest,
}

impl Assertion {
    pub fn new(tag: DeferredTag, lhs: Digest, rhs: Digest) -> Self {
        Self { tag, lhs, rhs }
    }
}
