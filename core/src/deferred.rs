//! Content-addressed DAG of *deferred algebraic operations*.
//!
//! The deferred subsystem represents expensive precompile work (e.g. 256-bit non-native field
//! arithmetic, future curve ops) as a DAG of typed [`Node`]s addressed by their 4-felt Poseidon2
//! digest. The VM uses two generic system events (`DeferredRegister`, `DeferredEvaluate`) to
//! populate the DAG; an external prover later consumes a [`DeferredWitness`] containing the
//! reachable nodes and equality assertions.
//!
//! This crate (`miden-core`) defines only the shared data model. The processor-side state, event
//! handlers, and per-value-type semantics live in `miden-processor`.

use alloc::vec::Vec;

use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};

use crate::{Felt, Word};

/// Content-addressed digest of a [`Node`]. A 4-felt Poseidon2 output.
pub type Digest = Word;

/// A 4-felt opaque tag identifying a deferred node. Tags are not interpreted by `miden-core` or
/// by the processor — the installed schema imposes any structure (type prefix, op suffix, kind,
/// …) it needs.
pub type Tag = [Felt; 4];

// PAYLOAD
// ================================================================================================

/// 8-felt body of a [`Node`]. For a leaf, this is the value data; for a binary op, the first 4
/// felts are the lhs child digest and the last 4 are the rhs child digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payload(pub [Felt; 8]);

impl Payload {
    pub const fn new(felts: [Felt; 8]) -> Self {
        Self(felts)
    }

    pub fn as_felts(&self) -> &[Felt; 8] {
        &self.0
    }

    /// Builds a binary-op payload from two child digests in `(lhs, rhs)` order. Same convention
    /// is reused by assertion-kind nodes, which encode `lhs_digest || rhs_digest` in their
    /// 8-felt payload.
    pub fn binary_op(lhs: Digest, rhs: Digest) -> Self {
        let mut felts = [ZERO; 8];
        felts[0..4].copy_from_slice(lhs.as_elements());
        felts[4..8].copy_from_slice(rhs.as_elements());
        Self(felts)
    }
}

// NODE
// ================================================================================================

/// A DAG node identified by its [`Digest`].
///
/// Both the tag and the payload are opaque 4-felt / 8-felt arrays at this layer; the installed
/// schema decides how to interpret them. A node's digest is the map key under which it is
/// stored — it is never stored in the node itself.
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

    /// Canonical 4-felt Poseidon2 digest of this node.
    ///
    /// The 12-felt sponge state is laid out as `[payload[0..8] || tag[0..4]]`: the 8-felt
    /// payload occupies the rate, the 4-felt tag occupies the capacity. A single permutation
    /// produces the digest from the first 4 state elements. This matches the layout MASM uses
    /// when computing the same digest with one `hperm` instruction.
    pub fn digest(&self) -> Digest {
        let mut state = [ZERO; 12];
        state[0..8].copy_from_slice(self.payload.as_felts());
        state[8..12].copy_from_slice(&self.tag);
        Poseidon2::apply_permutation(&mut state);
        Word::new([state[0], state[1], state[2], state[3]])
    }
}

// WITNESS
// ================================================================================================

/// External witness consumed by the deferred-DAG verifier.
///
/// Contains:
/// - `nodes`: every expression-kind node the verifier needs to re-check the assertions, in
///   digest order. This includes both the nodes the program explicitly registered **and** every
///   canonical intermediate produced during `DeferredState::evaluate` (e.g. `(a+b) → leaf`).
///   The verifier does not re-execute the DAG — it checks each node is locally consistent
///   against its neighbors (an `ADD` op's payload digests, plus the canonical-leaf digest its
///   reduction names, must satisfy `eval_op`). Missing intermediates would leave the witness
///   referencing digests no node defines, so the prover must intern the whole reduction proof,
///   not just the final canonical answer.
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

// ERROR
// ================================================================================================

/// Errors raised by the deferred subsystem. Intentionally coarse for v1; refine as concrete
/// failure modes accumulate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeferredError {
    #[error("invalid or unknown deferred tag")]
    InvalidTag,
    #[error("referenced digest is not present in deferred state")]
    MissingNode,
    #[error("conflicting node definition for digest")]
    ConflictingNode,
    #[error("payload is not valid for the given tag")]
    InvalidPayload,
    #[error("equality assertion failed")]
    AssertionFailed,
    #[error("operation is not supported by this handler")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG_A: Tag = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ];
    const TAG_B: Tag = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
    ];

    fn payload(seed: u64) -> Payload {
        Payload::new([
            Felt::new_unchecked(seed),
            Felt::new_unchecked(seed.wrapping_add(1)),
            Felt::new_unchecked(seed.wrapping_add(2)),
            Felt::new_unchecked(seed.wrapping_add(3)),
            Felt::new_unchecked(seed.wrapping_add(4)),
            Felt::new_unchecked(seed.wrapping_add(5)),
            Felt::new_unchecked(seed.wrapping_add(6)),
            Felt::new_unchecked(seed.wrapping_add(7)),
        ])
    }

    #[test]
    fn digest_is_deterministic() {
        let n = Node::new(TAG_A, payload(42));
        assert_eq!(n.digest(), n.digest());
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        assert_ne!(Node::new(TAG_A, p).digest(), Node::new(TAG_B, p).digest());
    }

    #[test]
    fn payload_changes_digest() {
        assert_ne!(
            Node::new(TAG_A, payload(0)).digest(),
            Node::new(TAG_A, payload(1)).digest()
        );
    }
}
