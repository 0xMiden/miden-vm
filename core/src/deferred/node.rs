//! Deferred node model: tags, payloads, shapes, and content-addressed digests.

use alloc::{sync::Arc, vec::Vec};
use core::num::NonZeroU32;

use miden_crypto::{ONE, ZERO, hash::poseidon2::Poseidon2};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::DeferredError;
use crate::{
    Felt, Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// Stable address of a deferred [`Node`], computed as a 4-felt Poseidon2 digest.
pub type Digest = Word;

/// One Poseidon2 rate block, used as the unit of deferred data payloads.
pub type DataChunk = [Felt; 8];

/// Digest of [`Node::TRUE`], root for an empty transcript, and terminal of the AND-chain.
///
/// TRUE is an always-present framework node with digest zero. Wire encoding reserves index 0 for
/// this digest instead of serializing TRUE as an explicit entry.
pub const TRUE_DIGEST: Digest = Word::new([ZERO; 4]);

// TAG
// ================================================================================================

/// Identifies the precompile that owns a node and carries its local immediates.
///
/// Framework ids are reserved for built-in nodes: `0` is TRUE and `1` is semantic AND. The
/// remaining three felts are opaque to the framework and are decoded only by the owning
/// [`super::Precompile`]. The canonical layout is `[id, arg0, arg1, arg2]` for hashing and wire
/// encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Tag {
    id: Felt,
    args: [Felt; 3],
}

impl Tag {
    pub(crate) const FELT_LEN: usize = 4;

    /// Framework-owned tag for the canonical TRUE node.
    pub const TRUE: Tag = Tag { id: ZERO, args: [ZERO; 3] };

    /// Framework-owned tag for semantic conjunction nodes.
    pub const AND: Tag = Tag { id: ONE, args: [ZERO; 3] };

    /// Returns whether an id is reserved by the deferred framework.
    pub(crate) fn is_framework_reserved_id(id: Felt) -> bool {
        id == ZERO || id == ONE
    }

    /// Returns whether this tag belongs to the framework namespace.
    pub(crate) fn is_framework_reserved(&self) -> bool {
        Self::is_framework_reserved_id(self.id)
    }

    /// Creates a tag from a precompile id and its three local immediates.
    ///
    /// Framework ids are reserved for [`Tag::TRUE`] and [`Tag::AND`]. Use [`Tag::from_word`] only
    /// for raw stack/wire decoding that must preserve untrusted tags before validation.
    pub fn precompile(id: Felt, args: [Felt; 3]) -> Result<Self, DeferredError> {
        if Self::is_framework_reserved_id(id) {
            return Err(DeferredError::InvalidTag);
        }
        Ok(Self { id, args })
    }

    /// Returns the precompile/framework id component.
    pub(crate) const fn id(&self) -> Felt {
        self.id
    }

    /// Returns the three local immediate arguments.
    pub(crate) const fn args(&self) -> [Felt; 3] {
        self.args
    }

    /// Returns the canonical layout used by hashing and wire encoding.
    pub const fn as_word(&self) -> [Felt; 4] {
        [self.id, self.args[0], self.args[1], self.args[2]]
    }

    /// Restores a tag from the canonical 4-felt layout without validation.
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
        Self::FELT_LEN * Felt::min_serialized_size()
    }
}

// PAYLOAD
// ================================================================================================

/// In-memory body of a deferred node.
///
/// TRUE has no payload data. Data nodes carry one or more opaque [`DataChunk`]s. Join nodes carry
/// two child digests explicitly rather than interpreting raw data as edges.
///
/// The representation is private: external precompiles can inspect payloads through accessors, but
/// cannot fabricate framework TRUE, empty data, or unchecked joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload(PayloadRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum PayloadRepr {
    /// The framework TRUE sentinel; carries no data.
    True,
    /// Non-empty opaque data.
    Data(Arc<[DataChunk]>),
    /// Two child digests.
    Join { lhs: Digest, rhs: Digest },
}

impl Payload {
    /// Creates a single-chunk data payload (`Data(1)`).
    fn value(chunk: DataChunk) -> Self {
        Self(PayloadRepr::Data(alloc::vec![chunk].into()))
    }

    /// Creates a data payload from a non-empty chunk collection.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty.
    fn try_data(chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        let chunks = chunks.into();
        if chunks.is_empty() {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(Self(PayloadRepr::Data(chunks)))
    }

    /// Creates a join payload that references two child digests.
    fn join(lhs: Digest, rhs: Digest) -> Self {
        Self(PayloadRepr::Join { lhs, rhs })
    }

    /// Returns this payload's data chunks, or [`DeferredError::InvalidPayload`] for TRUE and joins.
    pub fn as_data(&self) -> Result<&[DataChunk], DeferredError> {
        match &self.0 {
            PayloadRepr::Data(chunks) => Ok(chunks),
            PayloadRepr::True | PayloadRepr::Join { .. } => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns the single data chunk for value-like `Data(1)` payloads.
    pub fn as_value(&self) -> Result<&DataChunk, DeferredError> {
        match self.as_data()? {
            [chunk] => Ok(chunk),
            _ => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns the child digests for join payloads.
    pub fn as_join(&self) -> Result<(Digest, Digest), DeferredError> {
        match &self.0 {
            PayloadRepr::Join { lhs, rhs } => Ok((*lhs, *rhs)),
            PayloadRepr::True | PayloadRepr::Data(_) => Err(DeferredError::InvalidPayload),
        }
    }
}

// NODE
// ================================================================================================

/// A deferred DAG entry whose meaning is supplied by its tag's precompile.
///
/// The framework validates only the declared [`NodeType`]. Value semantics, producing ops, and
/// predicates all live in the owning [`super::Precompile`]. A predicate succeeds by evaluating to
/// [`Node::TRUE`], so callers can handle every canonical result as an ordinary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    tag: Tag,
    payload: Payload,
}

impl Node {
    pub(crate) const DIGEST_FELT_LEN: usize = 4;
    pub(crate) const DATA_CHUNK_FELT_LEN: usize = 8;
    pub(crate) const JOIN_FELT_LEN: usize = Tag::FELT_LEN + 2 * Self::DIGEST_FELT_LEN;

    /// Canonical TRUE node returned by predicates that verify successfully.
    pub const TRUE: Node = Node {
        tag: Tag::TRUE,
        payload: Payload(PayloadRepr::True),
    };

    /// Creates a value-like one-chunk data node (`Data(1)`).
    pub fn value(tag: Tag, chunk: DataChunk) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::value(chunk) })
    }

    /// Creates a data node from a non-empty chunk collection.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty and
    /// [`DeferredError::InvalidTag`] if `tag` uses a framework-reserved id.
    pub fn try_data(tag: Tag, chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::try_data(chunks)? })
    }

    /// Creates a join-shaped node that references two child digests.
    pub fn join(tag: Tag, lhs: Digest, rhs: Digest) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::join(lhs, rhs) })
    }

    /// Creates a structural transcript AND step from the previous root and statement digest.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self {
            tag: Tag::AND,
            payload: Payload::join(lhs, rhs),
        }
    }

    fn require_precompile_tag(tag: Tag) -> Result<Tag, DeferredError> {
        if tag.is_framework_reserved() {
            return Err(DeferredError::InvalidTag);
        }
        Ok(tag)
    }

    /// Returns this node's tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns this node's payload.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Returns this node's payload if the node has `tag`.
    pub fn payload_for_tag(&self, tag: Tag) -> Result<&Payload, DeferredError> {
        if self.tag != tag {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(&self.payload)
    }

    /// Returns whether this node is structurally the canonical TRUE result.
    pub fn is_true(&self) -> bool {
        matches!(self.payload.0, PayloadRepr::True) && self.tag == Tag::TRUE
    }

    /// Returns the field-element length of this node's canonical external representation.
    pub fn felt_len(&self) -> usize {
        match &self.payload.0 {
            PayloadRepr::True => Tag::FELT_LEN,
            PayloadRepr::Data(data) => Tag::FELT_LEN
                .checked_add(
                    Self::DATA_CHUNK_FELT_LEN
                        .checked_mul(data.len())
                        .expect("data felt count overflow"),
                )
                .expect("node felt count overflow"),
            PayloadRepr::Join { .. } => Self::JOIN_FELT_LEN,
        }
    }

    /// Returns the storage/budget footprint for durable state accounting.
    pub(crate) fn storage_felt_len(&self) -> usize {
        match &self.payload.0 {
            PayloadRepr::True => 0,
            PayloadRepr::Data(data) => Tag::FELT_LEN
                .checked_add(
                    Self::DATA_CHUNK_FELT_LEN
                        .checked_mul(data.len())
                        .expect("data felt count overflow"),
                )
                .expect("node felt count overflow"),
            PayloadRepr::Join { .. } => Self::JOIN_FELT_LEN,
        }
    }

    /// Appends this node's canonical external representation to `target`.
    pub fn write_into_felts(&self, target: &mut Vec<Felt>) {
        target.extend_from_slice(&self.tag.as_word());
        match &self.payload.0 {
            PayloadRepr::True => {},
            PayloadRepr::Data(data) => {
                for chunk in data.iter() {
                    target.extend_from_slice(chunk);
                }
            },
            PayloadRepr::Join { lhs, rhs } => {
                target.extend_from_slice(lhs.as_elements());
                target.extend_from_slice(rhs.as_elements());
            },
        }
    }

    /// Returns this node's canonical external representation.
    pub fn to_felts(&self) -> Vec<Felt> {
        let mut felts = Vec::with_capacity(self.felt_len());
        self.write_into_felts(&mut felts);
        felts
    }

    /// Computes the canonical digest used by both host code and in-circuit wrappers.
    pub fn digest(&self) -> Digest {
        match &self.payload.0 {
            PayloadRepr::True => {
                assert_eq!(self.tag, Tag::TRUE, "TRUE payload is only valid for Node::TRUE");
                TRUE_DIGEST
            },
            PayloadRepr::Data(data) => {
                let mut state = [ZERO; 12];
                state[Self::DATA_CHUNK_FELT_LEN..Self::DATA_CHUNK_FELT_LEN + Tag::FELT_LEN]
                    .copy_from_slice(&self.tag.as_word());
                for chunk in data.iter() {
                    state[0..Self::DATA_CHUNK_FELT_LEN].copy_from_slice(chunk);
                    Poseidon2::apply_permutation(&mut state);
                }
                Word::new([state[0], state[1], state[2], state[3]])
            },
            PayloadRepr::Join { lhs, rhs } => {
                let mut state = [ZERO; 12];
                state[0..Self::DIGEST_FELT_LEN].copy_from_slice(lhs.as_elements());
                state[Self::DIGEST_FELT_LEN..2 * Self::DIGEST_FELT_LEN]
                    .copy_from_slice(rhs.as_elements());
                state[Self::DATA_CHUNK_FELT_LEN..Self::DATA_CHUNK_FELT_LEN + Tag::FELT_LEN]
                    .copy_from_slice(&self.tag.as_word());
                Poseidon2::apply_permutation(&mut state);
                Word::new([state[0], state[1], state[2], state[3]])
            },
        }
    }
}

// NODE TYPE
// ================================================================================================

/// Shape a precompile declares for a recognized tag.
///
/// The shape tells registration and wire validation whether a body is non-empty opaque data or two
/// child digests. `True` is the framework sentinel owned exclusively by [`Tag::TRUE`]; precompiles
/// never declare it. Predicate status is not a shape; predicates succeed by evaluating to
/// [`Node::TRUE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// The framework TRUE sentinel, with no data payload.
    True,
    /// Non-empty opaque data whose [`DataChunk`] count is fixed by the tag.
    Data(NonZeroU32),
    /// Two child digests.
    Join,
}

impl NodeType {
    /// Shape for a value-like single-chunk data node (`Data(1)`).
    pub const fn value() -> Self {
        Self::Data(NonZeroU32::MIN)
    }

    /// Shape for a data node with a non-zero chunk count.
    pub fn data_chunks(n: u32) -> Option<Self> {
        NonZeroU32::new(n).map(Self::Data)
    }

    /// Validates that a node's payload matches this declared shape.
    pub(crate) fn validate_node(self, node: &Node) -> Result<(), DeferredError> {
        match self {
            Self::True if node.is_true() => Ok(()),
            Self::Data(n)
                if node.payload.as_data().is_ok_and(|chunks| chunks.len() == n.get() as usize) =>
            {
                Ok(())
            },
            Self::Join if node.payload.as_join().is_ok() => Ok(()),
            _ => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns this node's structural children, if the shape declares child references.
    pub(crate) fn children(self, node: &Node) -> Result<Option<(Digest, Digest)>, DeferredError> {
        match self {
            Self::Join => node.payload.as_join().map(Some),
            Self::True | Self::Data(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    const TAG_A: Tag = Tag::from_word([Felt::new_unchecked(42), ZERO, ZERO, ZERO]);
    const TAG_B: Tag =
        Tag::from_word([Felt::new_unchecked(42), ZERO, Felt::new_unchecked(1), ZERO]);

    fn block(seed: u64) -> DataChunk {
        core::array::from_fn(|i| Felt::new_unchecked(seed.wrapping_add(i as u64)))
    }

    #[test]
    fn tag_precompile_rejects_framework_reserved_ids_but_from_word_is_raw() {
        assert_eq!(Tag::precompile(Tag::TRUE.id(), [ZERO; 3]), Err(DeferredError::InvalidTag));
        assert_eq!(Tag::precompile(Tag::AND.id(), [ZERO; 3]), Err(DeferredError::InvalidTag));

        let raw_true = Tag::from_word([ZERO, Felt::new_unchecked(9), ZERO, ZERO]);
        assert_eq!(raw_true.id(), Tag::TRUE.id());
        assert_eq!(raw_true.args(), [Felt::new_unchecked(9), ZERO, ZERO]);
    }

    #[test]
    fn public_node_constructors_reject_framework_reserved_tags() {
        let chunk = block(1);
        assert_eq!(Node::value(Tag::TRUE, chunk), Err(DeferredError::InvalidTag));
        assert_eq!(Node::try_data(Tag::AND, alloc::vec![chunk]), Err(DeferredError::InvalidTag));
        assert_eq!(Node::join(Tag::AND, TRUE_DIGEST, TRUE_DIGEST), Err(DeferredError::InvalidTag));

        let and = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and.tag(), Tag::AND);
        assert_eq!(and.payload().as_join().unwrap(), (TRUE_DIGEST, TRUE_DIGEST));
    }

    #[test]
    fn true_node_has_no_data_and_serializes_to_tag_only() {
        assert_eq!(Tag::TRUE, Tag::from_word([ZERO, ZERO, ZERO, ZERO]));
        assert_eq!(Tag::AND, Tag::from_word([ONE, ZERO, ZERO, ZERO]));
        assert_eq!(Tag::TRUE.as_word(), [ZERO, ZERO, ZERO, ZERO]);
        assert_eq!(Tag::AND.as_word(), [ONE, ZERO, ZERO, ZERO]);
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));

        let true_node = Node::TRUE;
        assert_eq!(true_node.tag(), Tag::TRUE);
        assert!(true_node.is_true());
        assert_eq!(true_node.digest(), TRUE_DIGEST);
        assert_eq!(true_node.felt_len(), Tag::FELT_LEN);
        assert_eq!(true_node.to_felts(), Tag::TRUE.as_word());
        assert_eq!(true_node.storage_felt_len(), 0);
        assert!(true_node.payload().as_data().is_err());
        assert!(true_node.payload().as_value().is_err());
    }

    #[test]
    fn data_is_non_empty() {
        // Empty data cannot be constructed: TRUE is the only zero-payload node.
        assert!(Payload::try_data(Vec::<DataChunk>::new()).is_err());
        assert!(Node::try_data(TAG_A, Vec::<DataChunk>::new()).is_err());

        let node = Node::try_data(TAG_A, alloc::vec![block(1), block(9)]).unwrap();
        assert_eq!(node.payload().as_data().unwrap(), &[block(1), block(9)][..]);
    }

    #[test]
    fn value_is_data_one() {
        let chunk = block(5);
        let node = Node::value(TAG_A, chunk).unwrap();

        // A value is exactly Data(1): a single data chunk, not a separate framework shape.
        assert_eq!(node.payload().as_data().unwrap().len(), 1);
        assert_eq!(node.payload().as_value().unwrap(), &chunk);

        // Its external representation is `tag || one chunk`.
        assert_eq!(node.felt_len(), Tag::FELT_LEN + Node::DATA_CHUNK_FELT_LEN);
        let mut expected = TAG_A.as_word().to_vec();
        expected.extend_from_slice(&chunk);
        assert_eq!(node.to_felts(), expected);

        // Data(1) and the same single chunk wrapped as multi-chunk data digest identically.
        let multi = Node::try_data(TAG_A, alloc::vec![chunk]).unwrap();
        assert_eq!(node.digest(), multi.digest());
    }

    #[test]
    fn data_with_many_chunks_is_not_a_value() {
        let node = Node::try_data(TAG_A, alloc::vec![block(1), block(9)]).unwrap();
        assert!(node.payload().as_value().is_err());
        assert_eq!(node.payload().as_data().unwrap().len(), 2);
        assert_eq!(node.felt_len(), Tag::FELT_LEN + Node::DATA_CHUNK_FELT_LEN * 2);
    }

    #[test]
    fn digest_binds_tag_and_payload() {
        let chunk = block(7);
        let same = Node::value(TAG_A, chunk).unwrap();
        let different_tag = Node::value(TAG_B, chunk).unwrap();
        let different_payload = Node::value(TAG_A, block(8)).unwrap();

        assert_ne!(same.digest(), different_tag.digest());
        assert_ne!(same.digest(), different_payload.digest());
    }

    #[test]
    fn data_digest_is_linear_hash_over_chunks() {
        let chunks = alloc::vec![block(100), block(108), block(116)];
        let node = Node::try_data(TAG_A, chunks.clone()).unwrap();

        // Capacity = tag, then absorb each chunk into the rate with one permutation per chunk.
        let mut state = [ZERO; 12];
        state[Node::DATA_CHUNK_FELT_LEN..Node::DATA_CHUNK_FELT_LEN + Tag::FELT_LEN]
            .copy_from_slice(&TAG_A.as_word());
        for c in &chunks {
            state[0..Node::DATA_CHUNK_FELT_LEN].copy_from_slice(c);
            Poseidon2::apply_permutation(&mut state);
        }
        let expected = Word::new([state[0], state[1], state[2], state[3]]);
        assert_eq!(node.digest(), expected);
    }

    #[test]
    fn join_serializes_and_digests_over_two_children() {
        let lhs = Node::value(TAG_A, block(1)).unwrap().digest();
        let rhs = Node::value(TAG_A, block(2)).unwrap().digest();
        let join = Node::join(TAG_B, lhs, rhs).unwrap();

        assert_eq!(join.payload().as_join().unwrap(), (lhs, rhs));
        assert!(join.payload().as_data().is_err());

        // External representation is `tag || lhs || rhs`.
        assert_eq!(join.felt_len(), Node::JOIN_FELT_LEN);
        let mut expected = TAG_B.as_word().to_vec();
        expected.extend_from_slice(lhs.as_elements());
        expected.extend_from_slice(rhs.as_elements());
        assert_eq!(join.to_felts(), expected);

        // Join digest = permute([lhs, rhs, tag]).
        let mut state = [ZERO; 12];
        state[0..Node::DIGEST_FELT_LEN].copy_from_slice(lhs.as_elements());
        state[Node::DIGEST_FELT_LEN..2 * Node::DIGEST_FELT_LEN].copy_from_slice(rhs.as_elements());
        state[Node::DATA_CHUNK_FELT_LEN..Node::DATA_CHUNK_FELT_LEN + Tag::FELT_LEN]
            .copy_from_slice(&TAG_B.as_word());
        Poseidon2::apply_permutation(&mut state);
        assert_eq!(join.digest(), Word::new([state[0], state[1], state[2], state[3]]));
    }
}
