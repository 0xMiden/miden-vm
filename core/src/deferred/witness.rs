use alloc::vec::Vec;

use super::{Assertion, Digest, Node};

/// External witness consumed by the deferred-DAG verifier.
///
/// Contains exactly the nodes reachable from the assertions, sorted deterministically, plus the
/// assertions themselves in insertion order. Reachability extraction lives in the processor and
/// fills this structure; v1 only defines the shape.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeferredWitness {
    pub nodes: Vec<(Digest, Node)>,
    pub assertions: Vec<Assertion>,
}

impl DeferredWitness {
    pub fn new(nodes: Vec<(Digest, Node)>, assertions: Vec<Assertion>) -> Self {
        Self { nodes, assertions }
    }
}
