use alloc::vec::Vec;

use miden_crypto::ZERO;

use super::{Digest, Node};
use crate::Word;

/// External witness consumed by the deferred-DAG verifier.
///
/// Contains:
/// - `nodes`: the expression-kind nodes reachable from the assertions, sorted deterministically.
/// - `assertions`: every assertion-kind node, in registration order.
/// - `transcript`: a single rolling Poseidon2 digest over the assertion stream, mirroring
///   [`crate::precompile::PrecompileTranscript`]. The verifier re-folds this from `assertions`
///   to check that the witness is complete and ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredWitness {
    pub nodes: Vec<(Digest, Node)>,
    pub assertions: Vec<Node>,
    pub transcript: Digest,
}

impl DeferredWitness {
    pub fn new(nodes: Vec<(Digest, Node)>, assertions: Vec<Node>, transcript: Digest) -> Self {
        Self { nodes, assertions, transcript }
    }
}

impl Default for DeferredWitness {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            assertions: Vec::new(),
            transcript: Word::new([ZERO; 4]),
        }
    }
}
