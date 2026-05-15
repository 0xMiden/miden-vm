//! Content-addressed DAG of *deferred algebraic operations*.
//!
//! The deferred subsystem represents expensive precompile work (e.g. 256-bit non-native field
//! arithmetic, future curve ops, non-native hashes over bulk data) as a DAG of typed [`Node`]s
//! addressed by their 4-felt Poseidon2 digest. The VM uses three generic system events
//! (`DeferredRegister`, `DeferredRegisterChunk`, `DeferredEvaluate`) to populate the DAG; an
//! external prover later consumes a [`DeferredWitness`] containing the reachable nodes and
//! equality assertions.
//!
//! The full subsystem — data model, [`Schema`] trait, in-memory [`DeferredState`], and the
//! [`Field0Handler`] reference schema — lives here in `miden-core`. The processor only contributes
//! the system-event glue that bridges VM operand-stack reads to schema calls.

mod schema;
mod state;

pub use schema::{ChildResolver, NodeType, NoopSchema, Schema, SchemaError};
pub use state::DeferredState;

// Reference `Field0Handler` schema — pinned in here to keep `core/tests/deferred_field0.rs` and
// the unit tests in this crate exercising the public deferred API only. Gated so it isn't
// part of the production surface.
#[cfg(any(test, feature = "testing"))]
mod field0;
use alloc::{sync::Arc, vec::Vec};

#[cfg(any(test, feature = "testing"))]
pub use field0::Field0Handler;
use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};

use crate::{Felt, Word};

/// Content-addressed digest of a [`Node`]. A 4-felt Poseidon2 output.
pub type Digest = Word;

/// A 4-felt opaque tag identifying a deferred node. Tags are not interpreted by `miden-core` or
/// by the processor — the installed schema decodes any structure (type prefix, op suffix, kind,
/// chunk length, …) it needs out of the tag's four felts.
pub type Tag = [Felt; 4];

/// An 8-felt block — the Poseidon2 rate, and the bulk-data unit of a chunk node. A `ChunkNode`
/// carries `n` chunks; its digest is the linear hash of those `8n` felts with the tag as the
/// IV (capacity).
pub type Chunk = [Felt; 8];

// PAYLOAD
// ================================================================================================

/// 8-felt body of an expression or assertion node. For a leaf, this is the value data; for a
/// binary op, the first 4 felts are the lhs child digest and the last 4 are the rhs child digest.
/// Assertion payloads follow the same `lhs_digest || rhs_digest` convention as binary ops.
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
    /// is reused by assertion nodes, which encode `lhs_digest || rhs_digest` in their 8-felt
    /// payload.
    pub fn binary_op(lhs: Digest, rhs: Digest) -> Self {
        let mut felts = [ZERO; 8];
        felts[0..4].copy_from_slice(lhs.as_elements());
        felts[4..8].copy_from_slice(rhs.as_elements());
        Self(felts)
    }

    /// Splits a binary-op or assertion payload into its two child digests in `(lhs, rhs)` order.
    /// Inverse of [`Self::binary_op`]; convenient for schema `reduce` implementations that walk
    /// children.
    pub fn binary_op_children(&self) -> (Digest, Digest) {
        let lhs = Word::new([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let rhs = Word::new([self.0[4], self.0[5], self.0[6], self.0[7]]);
        (lhs, rhs)
    }
}

// NODE
// ================================================================================================

/// A DAG node identified by its [`Digest`].
///
/// The tag is opaque at this layer — the installed [`Schema`] decodes it. The payload comes in
/// three shapes ([`NodePayload`]):
/// - `Expression(Payload)` — leaves and op-nodes that live in `DeferredState::nodes`.
/// - `Chunk(Arc<[Chunk]>)` — bulk-data leaves; `n` (number of 8-felt chunks) is `chunks.len()`
///   and is also encoded into the tag, so the digest binds it. Stored behind an `Arc` so cloning
///   a chunk node (when interning, resolving children, or extracting the witness) is an atomic
///   ref-count bump rather than a deep copy of the bulk data.
/// - `Assertion(Payload)` — equality / verification records that live in
///   `DeferredState::assertions`.
///
/// The role (Expression / Chunk / Assertion) is determined by the tag via [`Schema::decode`].
/// The variant in the constructed [`Node`] must match what `decode(tag)` returns; mismatches are
/// rejected at register time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub payload: NodePayload,
}

/// Variant of a [`Node`]'s body. The variant tag *is* the structural role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodePayload {
    /// Leaves and op-nodes. 8-felt payload.
    Expression(Payload),
    /// Bulk-data leaves. `n = chunks.len()`, also encoded in the tag. `Arc`-shared so the bulk
    /// data is never deep-copied during interning or resolution.
    Chunk(Arc<[Chunk]>),
    /// Equality / verification records. 8-felt payload, same `lhs_digest || rhs_digest` shape as
    /// binary-op expressions.
    Assertion(Payload),
}

impl Node {
    /// Build an expression node (leaf or op).
    pub fn expression(tag: Tag, payload: Payload) -> Self {
        Self { tag, payload: NodePayload::Expression(payload) }
    }

    /// Build an assertion node.
    pub fn assertion(tag: Tag, payload: Payload) -> Self {
        Self { tag, payload: NodePayload::Assertion(payload) }
    }

    /// Build a chunk node from `n = chunks.len()` rate-sized blocks of bulk data. Accepts
    /// anything that converts into `Arc<[Chunk]>` — typically a `Vec<Chunk>` from the processor
    /// handler, or a slice literal in tests.
    pub fn chunk(tag: Tag, chunks: impl Into<Arc<[Chunk]>>) -> Self {
        Self { tag, payload: NodePayload::Chunk(chunks.into()) }
    }

    /// Returns the 8-felt payload for expression and assertion nodes. Returns `None` for chunk
    /// nodes, which don't have a fixed-size payload.
    pub fn payload_felts(&self) -> Option<&Payload> {
        match &self.payload {
            NodePayload::Expression(p) | NodePayload::Assertion(p) => Some(p),
            NodePayload::Chunk(_) => None,
        }
    }

    /// Returns the 8-felt payload of an expression node. Returns `None` for chunk and assertion
    /// nodes. Useful for schema `reduce` arms that operate on leaf or op-node payloads
    /// specifically.
    pub fn expression_payload(&self) -> Option<&Payload> {
        match &self.payload {
            NodePayload::Expression(p) => Some(p),
            NodePayload::Chunk(_) | NodePayload::Assertion(_) => None,
        }
    }

    /// Canonical 4-felt Poseidon2 digest of this node.
    ///
    /// Sponge state is laid out as `[rate || tag]` — the tag occupies the 4-felt capacity. For
    /// expression and assertion nodes, the 8-felt payload fills the rate and a single permutation
    /// produces the digest. For chunk nodes, each 8-felt chunk overwrites the rate and the
    /// permutation iterates `n` times (linear hash); the empty `n == 0` case still applies one
    /// permutation so the digest binds the tag.
    ///
    /// For `n == 1` the chunk digest is byte-identical to the equivalent Expression digest with
    /// the same tag and payload.
    pub fn digest(&self) -> Digest {
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&self.tag);
        match &self.payload {
            NodePayload::Expression(p) | NodePayload::Assertion(p) => {
                state[0..8].copy_from_slice(p.as_felts());
                Poseidon2::apply_permutation(&mut state);
            },
            NodePayload::Chunk(chunks) if chunks.is_empty() => {
                // n=0: one permutation so the empty digest still binds to the tag.
                Poseidon2::apply_permutation(&mut state);
            },
            NodePayload::Chunk(chunks) => {
                for c in chunks.iter() {
                    state[0..8].copy_from_slice(c);
                    Poseidon2::apply_permutation(&mut state);
                }
            },
        }
        Word::new([state[0], state[1], state[2], state[3]])
    }
}

// WITNESS
// ================================================================================================

/// External witness consumed by the deferred-DAG verifier.
///
/// Contains:
/// - `nodes`: every expression-kind and chunk-kind node the verifier needs to re-check the
///   assertions, in digest order. This includes both the nodes the program explicitly registered
///   **and** every canonical intermediate produced during `DeferredState::evaluate` (e.g.
///   `(a+b) → leaf`). The verifier does not re-execute the DAG — it checks each node is locally
///   consistent against its neighbors (an `ADD` op's payload digests, plus the canonical-leaf
///   digest its reduction names, must satisfy `eval_op`). Missing intermediates would leave the
///   witness referencing digests no node defines, so the prover must intern the whole reduction
///   proof, not just the final canonical answer.
/// - `assertions`: every assertion-kind node, in registration order.
/// - `transcript`: a single rolling Poseidon2 digest over the assertion stream, mirroring
///   [`crate::precompile::PrecompileTranscript`]. The verifier re-folds this from `assertions` to
///   check that the witness is complete and ordered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
        let n = Node::expression(TAG_A, payload(42));
        assert_eq!(n.digest(), n.digest());
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        assert_ne!(Node::expression(TAG_A, p).digest(), Node::expression(TAG_B, p).digest());
    }

    #[test]
    fn payload_changes_digest() {
        assert_ne!(
            Node::expression(TAG_A, payload(0)).digest(),
            Node::expression(TAG_A, payload(1)).digest(),
        );
    }

    #[test]
    fn chunk_n1_matches_expression_with_same_tag_and_payload() {
        // Single-chunk digest is the same body as Expression: rate := payload, capacity := tag,
        // one permutation, take state[0..4].
        let p = payload(123);
        let expr = Node::expression(TAG_A, p);
        let chunk = Node::chunk(TAG_A, vec![p.0]);
        assert_eq!(expr.digest(), chunk.digest());
    }

    #[test]
    fn chunk_n0_binds_tag() {
        // Empty chunk still applies one permutation, so different tags produce different digests.
        let chunk_a = Node::chunk(TAG_A, vec![]);
        let chunk_b = Node::chunk(TAG_B, vec![]);
        assert_ne!(chunk_a.digest(), chunk_b.digest());
    }

    #[test]
    fn chunk_n3_matches_manual_linear_hash() {
        let chunks: Vec<Chunk> = (0..3).map(|i| payload(100 + i * 8).0).collect();
        let chunk = Node::chunk(TAG_A, chunks.clone());

        // Manual computation: capacity = tag, iterate over chunks overwriting rate.
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&TAG_A);
        for c in &chunks {
            state[0..8].copy_from_slice(c);
            Poseidon2::apply_permutation(&mut state);
        }
        let expected = Word::new([state[0], state[1], state[2], state[3]]);
        assert_eq!(chunk.digest(), expected);
    }
}
