use super::{Payload, Tag};

/// A DAG node identified by `hash_node(tag, payload)`.
///
/// Both the tag and the payload are opaque 4-felt / 8-felt arrays at this layer; the installed
/// schema decides how to interpret them. A node's [`super::Digest`] is the map key under which
/// it is stored — it is never stored in the node itself.
///
/// Assertions are also `Node`s — the schema classifies a node as either an expression or an
/// assertion at register time via its `is_valid` hook.
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
