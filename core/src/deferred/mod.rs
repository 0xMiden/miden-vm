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
mod precompile_registry;
mod state;
mod wire;

use alloc::sync::Arc;

use miden_crypto::{ONE, ZERO, hash::poseidon2::Poseidon2};
pub use node::{NodeType, PrecompileError};
pub use precompile::{Precompile, precompile_id};
pub use precompile_registry::PrecompileRegistry;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
pub use state::{DeferredState, WitnessBuilder};
pub use wire::{DeferredStateWire, IntegrityError, TRUE_INDEX, WireEntry};

use crate::{
    Felt, Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// Stable address of a deferred [`Node`], computed as a 4-felt Poseidon2 digest.
pub type Digest = Word;

/// Identifies the precompile that owns a node and carries its local immediates.
///
/// Framework ids are reserved for built-in nodes: `0` is TRUE and `1` is semantic AND. The
/// remaining three felts are opaque to the framework and are decoded only by the owning
/// [`Precompile`]. The canonical layout is `[id, arg0, arg1, arg2]` for hashing and wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Tag {
    pub id: Felt,
    pub args: [Felt; 3],
}

impl Tag {
    /// Framework-owned tag for the canonical TRUE node.
    pub const TRUE: Tag = Tag { id: ZERO, args: [ZERO; 3] };

    /// Framework-owned tag for semantic conjunction nodes.
    pub const AND: Tag = Tag { id: ONE, args: [ZERO; 3] };

    /// Returns whether an id is reserved by the deferred framework.
    pub fn is_framework_reserved_id(id: Felt) -> bool {
        id == ZERO || id == ONE
    }

    /// Returns whether this tag belongs to the framework namespace.
    pub fn is_framework_reserved(&self) -> bool {
        Self::is_framework_reserved_id(self.id)
    }

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

impl Serializable for Tag {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for felt in &self.as_word() {
            felt.write_into(target);
        }
    }
}

impl Deserializable for Tag {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::from_word([
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ]))
    }

    fn min_serialized_size() -> usize {
        4 * Felt::min_serialized_size()
    }
}

/// One Poseidon2 rate block, used as the unit of chunk-bodied deferred leaves.
pub type Chunk = [Felt; 8];

/// Digest of [`Node::TRUE`], root for an empty transcript, and terminal of the AND-chain.
///
/// TRUE is an always-present framework node with digest zero. Wire encoding still reserves index 0
/// for this digest instead of serializing the TRUE node as a normal entry.
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

    /// Creates a structural transcript AND step from the previous root and statement digest.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self::join(Tag::AND, lhs, rhs)
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
    /// The canonical TRUE node is the exact zero tag with an all-zero expression body; its digest
    /// is [`TRUE_DIGEST`].
    pub fn is_true_node(&self) -> bool {
        self.tag == Tag::TRUE && matches!(&self.payload, Payload::Expression(f) if *f == [ZERO; 8])
    }

    /// Returns a rough serialized field-element footprint for budget accounting.
    pub fn num_elements(&self) -> usize {
        let payload_elements = match &self.payload {
            Payload::Expression(_) => 8,
            Payload::Chunk(chunks) => 8usize.saturating_mul(chunks.len()),
        };
        4usize.saturating_add(payload_elements)
    }

    /// Computes the canonical digest used by both host code and in-circuit wrappers.
    ///
    /// [`Node::TRUE`] is the distinguished zero-digest framework node. All other expression nodes
    /// hash one `[payload || tag]` Poseidon2 state; chunk nodes stream each 8-felt chunk with the
    /// same tag capacity. Transcript AND nodes use [`Tag::AND`] as their capacity.
    pub fn digest(&self) -> Digest {
        if self.is_true_node() {
            return TRUE_DIGEST;
        }

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
        id: Felt::new_unchecked(42),
        args: [Felt::new_unchecked(0); 3],
    };
    const TAG_B: Tag = Tag {
        id: Felt::new_unchecked(42),
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
    fn digest_binds_tag_and_payload() {
        let p = *payload(7).as_felts().unwrap();
        let same = Node::leaf(TAG_A, p);
        let different_tag = Node::leaf(TAG_B, p);
        let different_payload = Node::leaf(TAG_A, *payload(8).as_felts().unwrap());

        assert_ne!(same.digest(), different_tag.digest());
        assert_ne!(same.digest(), different_payload.digest());
    }

    #[test]
    fn chunk_n1_matches_expression_with_same_tag_and_payload() {
        // Single-chunk digest is the same body as Expression: rate := payload, capacity := tag,
        // one permutation, take state[0..4].
        let felts = *payload(123).as_felts().unwrap();
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
    fn framework_true_node_is_canonical() {
        assert_eq!(Tag::TRUE, Tag { id: ZERO, args: [ZERO; 3] });
        assert_eq!(Tag::AND, Tag { id: ONE, args: [ZERO; 3] });
        assert_eq!(Tag::TRUE.as_word(), [ZERO, ZERO, ZERO, ZERO]);
        assert_eq!(Tag::AND.as_word(), [ONE, ZERO, ZERO, ZERO]);
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));

        let true_node = Node::TRUE;
        assert_eq!(true_node.tag, Tag::TRUE);
        assert!(matches!(&true_node.payload, Payload::Expression(f) if *f == [ZERO; 8]));
        assert!(true_node.is_true_node());
        assert_eq!(true_node.digest(), TRUE_DIGEST);
    }

    #[test]
    fn and_of_true_true_hashes_as_distinct_structural_node() {
        let and_true_true = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and_true_true.tag, Tag::AND);
        assert_ne!(and_true_true.digest(), TRUE_DIGEST);
        assert_ne!(and_true_true.digest(), Node::TRUE.digest());
    }
}
