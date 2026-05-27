//! Content-addressed deferred computation for precompile-backed VM hints.
//!
//! Deferred events let programs commit opaque statements during execution and leave their
//! semantic checks to installed [`Precompile`]s. The framework stores those commitments as a DAG
//! of [`Node`]s and a transcript root that verifies by reducing every logged statement to TRUE.
//!
//! `miden-core` owns the data model, registry, state, and wire validation; the processor only
//! provides system-event plumbing. Reference precompiles live in `crate::testing::precompile`.

mod node;
mod precompile;
mod precompile_schema;
mod state;
mod wire;

use alloc::sync::Arc;

use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};
pub use node::{NodeType, PrecompileError};
pub use precompile::{Precompile, precompile_id};
pub use precompile_schema::PrecompileRegistry;
pub use state::{DeferredState, WitnessBuilder};
pub use wire::{DeferredStateWire, IntegrityError, TRUE_INDEX, WireBody, WireEntry};

use crate::{Felt, Word};

/// Stable address of a deferred [`Node`], computed as a 4-felt Poseidon2 digest.
pub type Digest = Word;

/// Identifies the precompile that owns a node and carries its local immediates.
///
/// `id == ZERO` is framework-owned for TRUE and transcript AND nodes. The remaining three felts
/// are opaque to the framework and are decoded only by the owning [`Precompile`]. The canonical
/// layout is `[id, arg0, arg1, arg2]` for hashing and wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub id: Felt,
    pub args: [Felt; 3],
}

impl Tag {
    /// Framework-owned tag for TRUE and transcript AND nodes; no precompile may use id `ZERO`.
    pub const TRUE: Tag = Tag { id: ZERO, args: [ZERO; 3] };

    /// Creates a tag from a precompile id and its three local immediates.
    pub const fn new(id: Felt, args: [Felt; 3]) -> Self {
        Self { id, args }
    }

    /// Returns the canonical layout used by hashing and wire encoding.
    pub const fn as_word(&self) -> [Felt; 4] {
        [self.id, self.args[0], self.args[1], self.args[2]]
    }

    /// Restores a tag from the canonical 4-felt layout.
    pub const fn from_word(w: [Felt; 4]) -> Self {
        Self { id: w[0], args: [w[1], w[2], w[3]] }
    }
}

/// One Poseidon2 rate block, used as the unit of chunk-bodied deferred leaves.
pub type Chunk = [Felt; 8];

/// Virtual root for an empty transcript and the terminal of the AND-chain.
///
/// This is not the digest of [`Node::TRUE`]: nodes always hash through Poseidon2, while this zero
/// word is only the verifier's sentinel for "no prior statements." Use [`Node::is_true_node`] for
/// predicate results and compare against this value only for transcript-chain terminals.
pub const TRUE_DIGEST: Digest = Word::new([ZERO; 4]);

// PAYLOAD
// ================================================================================================

/// In-memory body of a deferred node.
///
/// Expressions carry one rate block, either as raw value data or as `lhs_digest || rhs_digest`.
/// Chunks carry one or more rate blocks for bulk data; the tag also records the expected count so
/// the digest binds the shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Expression([Felt; 8]),
    Chunk(Arc<[Chunk]>),
}

impl Payload {
    /// Creates an expression payload from one 8-felt rate block.
    pub const fn new(felts: [Felt; 8]) -> Self {
        Self::Expression(felts)
    }

    /// Creates an expression payload that references two child digests.
    pub fn join(lhs: Digest, rhs: Digest) -> Self {
        let mut felts = [ZERO; 8];
        felts[0..4].copy_from_slice(lhs.as_elements());
        felts[4..8].copy_from_slice(rhs.as_elements());
        Self::Expression(felts)
    }

    /// Creates a chunk payload for bulk data committed by a tag-declared non-zero length.
    ///
    /// # Panics
    /// In debug builds, if `chunks` is empty. Untrusted wire input is rejected before reaching
    /// this constructor.
    pub fn chunks(chunks: impl Into<Arc<[Chunk]>>) -> Self {
        let chunks = chunks.into();
        debug_assert!(!chunks.is_empty(), "chunk node must carry at least one chunk");
        Self::Chunk(chunks)
    }

    /// Returns the expression block, or [`DeferredError::InvalidPayload`] for chunk bodies.
    pub fn as_felts(&self) -> Result<&[Felt; 8], DeferredError> {
        match self {
            Self::Expression(felts) => Ok(felts),
            Self::Chunk(_) => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns the chunk blocks, or [`DeferredError::InvalidPayload`] for expression bodies.
    pub fn as_chunks(&self) -> Result<&[Chunk], DeferredError> {
        match self {
            Self::Chunk(chunks) => Ok(chunks),
            Self::Expression(_) => Err(DeferredError::InvalidPayload),
        }
    }

    /// Splits a join-shaped expression into `(lhs, rhs)` child digests.
    pub fn join_children(&self) -> Result<(Digest, Digest), DeferredError> {
        let f = self.as_felts()?;
        let lhs = Word::new([f[0], f[1], f[2], f[3]]);
        let rhs = Word::new([f[4], f[5], f[6], f[7]]);
        Ok((lhs, rhs))
    }
}

// NODE
// ================================================================================================

/// A deferred DAG entry whose meaning is supplied by its tag's precompile.
///
/// The framework validates only the declared [`NodeType`]. Value semantics, producing ops, and
/// predicates all live in the owning [`Precompile`]. A predicate succeeds by reducing to
/// [`Node::TRUE`], so callers can handle every canonical result as an ordinary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub payload: Payload,
}

impl Node {
    /// Canonical TRUE node returned by predicates that verify successfully.
    pub const TRUE: Node = Node {
        tag: Tag::TRUE,
        payload: Payload::Expression([ZERO; 8]),
    };

    /// Creates an expression-bodied node from an already-shaped payload.
    pub fn expression(tag: Tag, payload: Payload) -> Self {
        Self { tag, payload }
    }

    /// Creates an expression-bodied leaf from raw payload data.
    pub fn leaf(tag: Tag, felts: [Felt; 8]) -> Self {
        Self::expression(tag, Payload::new(felts))
    }

    /// Creates a join-shaped node that references two child digests.
    pub fn join(tag: Tag, lhs: Digest, rhs: Digest) -> Self {
        Self::expression(tag, Payload::join(lhs, rhs))
    }

    /// Creates a transcript AND step from the previous root and statement digest.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self::join(Tag::TRUE, lhs, rhs)
    }

    /// Creates a chunk-bodied node from one or more rate blocks.
    ///
    /// # Panics
    /// In debug builds, if `chunks` is empty. Processor and wire paths reject zero-length chunks
    /// before constructing a node.
    pub fn chunk(tag: Tag, chunks: impl Into<Arc<[Chunk]>>) -> Self {
        let chunks = chunks.into();
        debug_assert!(!chunks.is_empty(), "chunk node must carry at least one chunk");
        Self { tag, payload: Payload::Chunk(chunks) }
    }

    /// Returns whether this node is structurally the canonical TRUE result.
    ///
    /// This checks the zero tag and zero expression body, not the digest. That keeps predicate
    /// success distinct from the virtual [`TRUE_DIGEST`] transcript terminal.
    pub fn is_true_node(&self) -> bool {
        self.tag == Tag::TRUE && matches!(&self.payload, Payload::Expression(f) if *f == [ZERO; 8])
    }

    /// Computes the canonical digest used by both host code and in-circuit wrappers.
    ///
    /// Expression nodes hash one `[payload || tag]` Poseidon2 state; chunk nodes stream each
    /// 8-felt chunk with the same tag capacity. [`Node::TRUE`] hashes normally, so its digest is
    /// not [`TRUE_DIGEST`], which is only the virtual transcript terminal.
    pub fn digest(&self) -> Digest {
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&self.tag.as_word());
        match &self.payload {
            Payload::Expression(f) => {
                state[0..8].copy_from_slice(f);
                Poseidon2::apply_permutation(&mut state);
            },
            Payload::Chunk(chunks) => {
                for c in chunks.iter() {
                    state[0..8].copy_from_slice(c);
                    Poseidon2::apply_permutation(&mut state);
                }
            },
        }
        Word::new([state[0], state[1], state[2], state[3]])
    }
}

// ERROR
// ================================================================================================

/// Coarse deferred-framework failures shared by state and reference precompiles.
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
    use alloc::vec::Vec;

    use super::*;

    const TAG_A: Tag = Tag {
        id: Felt::new_unchecked(1),
        args: [Felt::new_unchecked(0); 3],
    };
    const TAG_B: Tag = Tag {
        id: Felt::new_unchecked(1),
        args: [Felt::new_unchecked(0), Felt::new_unchecked(1), Felt::new_unchecked(0)],
    };

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
        let n = Node::leaf(TAG_A, *payload(42).as_felts().unwrap());
        assert_eq!(n.digest(), n.digest());
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        assert_ne!(
            Node::leaf(TAG_A, *p.as_felts().unwrap()).digest(),
            Node::leaf(TAG_B, *p.as_felts().unwrap()).digest()
        );
    }

    #[test]
    fn payload_changes_digest() {
        assert_ne!(
            Node::leaf(TAG_A, *payload(0).as_felts().unwrap()).digest(),
            Node::leaf(TAG_A, *payload(1).as_felts().unwrap()).digest(),
        );
    }

    #[test]
    fn chunk_n1_matches_expression_with_same_tag_and_payload() {
        // Single-chunk digest is the same body as Expression: rate := payload, capacity := tag,
        // one permutation, take state[0..4].
        let p = payload(123);
        let felts = *p.as_felts().unwrap();
        let expr = Node::leaf(TAG_A, felts);
        let chunk = Node::chunk(TAG_A, vec![felts]);
        assert_eq!(expr.digest(), chunk.digest());
    }

    #[test]
    fn chunk_n3_matches_manual_linear_hash() {
        let chunks: Vec<Chunk> =
            (0..3).map(|i| *payload(100 + i * 8).as_felts().unwrap()).collect();
        let chunk = Node::chunk(TAG_A, chunks.clone());

        // Manual computation: capacity = tag, iterate over chunks overwriting rate.
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&TAG_A.as_word());
        for c in &chunks {
            state[0..8].copy_from_slice(c);
            Poseidon2::apply_permutation(&mut state);
        }
        let expected = Word::new([state[0], state[1], state[2], state[3]]);
        assert_eq!(chunk.digest(), expected);
    }

    #[test]
    fn true_tag_and_digest_are_zero_word() {
        assert_eq!(Tag::TRUE, Tag { id: ZERO, args: [ZERO; 3] });
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));
    }

    #[test]
    fn true_node_has_zero_tag_and_zero_expression_payload() {
        let n = Node::TRUE;
        assert_eq!(n.tag, Tag::TRUE);
        match &n.payload {
            Payload::Expression(f) => assert_eq!(*f, [ZERO; 8]),
            Payload::Chunk(_) => panic!("Node::TRUE must be expression-bodied"),
        }
        assert!(n.is_true_node());
    }

    #[test]
    fn poseidon2_does_not_fix_zero() {
        // Load-bearing for the unified-transcript refactor: because Poseidon2's round
        // constants are non-zero, applying the permutation to the all-zero state does NOT
        // return all zeros. Consequence: `Node::TRUE.digest() != TRUE_DIGEST`, and the
        // framework keeps these two concepts separate (see TRUE_DIGEST docs and
        // `true_node_digest_matches_in_circuit_merge` below).
        let mut state = [ZERO; 12];
        Poseidon2::apply_permutation(&mut state);
        let rate0 = Word::new([state[0], state[1], state[2], state[3]]);
        assert_ne!(rate0, Word::new([ZERO; 4]));
    }

    #[test]
    fn true_node_hashes_normally_via_poseidon2() {
        // TRUE-node is not digest-special-cased: it hashes through Poseidon2 like any other
        // node, producing a specific non-zero word. This keeps `Node::digest()` honest to the
        // in-circuit hasher — critical for AND-nodes interned by `DeferredState::log` (where the
        // in-circuit hasher computes the same `merge(0, 0)` value).
        assert_ne!(Node::TRUE.digest(), TRUE_DIGEST);
    }

    #[test]
    fn true_node_digest_equals_and_of_true_true() {
        // AND(TRUE, TRUE) and the TRUE sentinel share the structural shape
        // `Node { tag: Tag::TRUE, payload: Expression([0; 8]) }`, so their digests are equal
        // (both run the same Poseidon2 permutation). This is logically consistent (AND of two
        // TRUEs IS TRUE) and load-bearing for the recursive-proof use case where the program
        // logs a sub-proof's transcript whose root happens to be TRUE_DIGEST.
        let and_true_true = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and_true_true.digest(), Node::TRUE.digest());
    }

    #[test]
    fn clone_yields_consistent_digest() {
        // A clone's digest matches the source's — `Clone` is a structural copy.
        let n = Node::leaf(TAG_A, *payload(33).as_felts().unwrap());
        let d1 = n.digest();
        let cloned = n;
        let d2 = cloned.digest();
        assert_eq!(d1, d2);
    }
}
