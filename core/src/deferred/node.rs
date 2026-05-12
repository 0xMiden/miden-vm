use super::{DeferredTag, Digest, Payload};

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
