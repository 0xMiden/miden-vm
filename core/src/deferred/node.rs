use super::{Digest, Payload, Tag};

/// A DAG node identified by `hash_node(tag, payload)`.
///
/// Both the tag and the payload are opaque 4-felt / 8-felt arrays at this layer; the installed
/// schema decides how to interpret them. A node's [`Digest`] is the map key under which it is
/// stored — it is never stored in the node itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub payload: Payload,
}

impl Node {
    pub fn new(tag: Tag, payload: Payload) -> Self {
        Self { tag, payload }
    }
}

/// An equality assertion linking two DAG nodes by their digests.
///
/// The assertion's `tag` is opaque — it is recorded for the verifier's benefit but the processor
/// does not interpret it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    pub tag: Tag,
    pub lhs: Digest,
    pub rhs: Digest,
}

impl Assertion {
    pub fn new(tag: Tag, lhs: Digest, rhs: Digest) -> Self {
        Self { tag, lhs, rhs }
    }
}
