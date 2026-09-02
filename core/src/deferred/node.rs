//! Deferred node model: tags, payloads, shapes, and content-addressed digests.

use alloc::{sync::Arc, vec::Vec};
use core::mem::size_of;

use miden_crypto::{ONE, ZERO, hash::eidos::Eidos};

use super::{DEFERRED_AND_DOMAIN, DEFERRED_CHUNKS_DOMAIN, DeferredError};
use crate::{
    Felt, Word,
    program::domain::{MAX_EIDOS_INIT_VALUE, has_domain_selector_encoding},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::bytes_to_packed_u32_elements,
};

/// Stable address of a deferred [`Node`], computed as a 4-felt Eidos digest.
pub type Digest = Word;

/// One eight-Felt Eidos block, used as the unit of deferred data payloads.
pub type DataChunk = [Felt; 8];

/// Digest of [`Node::TRUE`], root for an empty deferred state, and terminal of the AND-chain.
///
/// TRUE is an always-present framework node with digest zero. Wire encoding reserves index 0 for
/// this digest instead of serializing TRUE as an explicit entry.
pub const TRUE_DIGEST: Digest = Word::new([ZERO; 4]);

// TAG
// ================================================================================================

/// Identifies the precompile that owns a node and carries its two local parameters.
///
/// Framework ids are reserved for built-in nodes: `0` is TRUE, `1` is semantic AND, and
/// `2` is opaque framework chunks. The next two felts are interpreted only by the owning
/// [`super::Precompile`]. The fourth tag felt is reserved and must be zero, preserving the
/// word-aligned stack and wire representation. The canonical layout is
/// `[selector, arg0, arg1, 0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    id: Felt,
    args: [Felt; 2],
    reserved: Felt,
}

impl Tag {
    pub(crate) const FELT_LEN: usize = 4;
    const CHUNKS_ID: Felt = Felt::new_unchecked(2);

    /// Framework-owned tag for the canonical TRUE node.
    pub const TRUE: Tag = Tag {
        id: ZERO,
        args: [ZERO; 2],
        reserved: ZERO,
    };

    /// Framework-owned tag for semantic conjunction nodes.
    pub const AND: Tag = Tag { id: ONE, args: [ZERO; 2], reserved: ZERO };

    /// Framework-owned tag for opaque chunk-list data nodes.
    pub const CHUNKS: Tag = Tag {
        id: Self::CHUNKS_ID,
        args: [ZERO; 2],
        reserved: ZERO,
    };

    /// Returns whether an id is reserved by the deferred framework.
    pub(crate) fn is_framework_reserved_id(id: Felt) -> bool {
        id == ZERO || id == ONE || id == Self::CHUNKS_ID
    }

    /// Returns whether this tag belongs to the framework namespace.
    pub(crate) fn is_framework_reserved(&self) -> bool {
        Self::is_framework_reserved_id(self.id)
    }

    /// Creates a tag from a registered precompile selector and its two local parameters.
    ///
    /// Framework ids are reserved for [`Tag::TRUE`], [`Tag::AND`], and [`Tag::CHUNKS`]. Use
    /// [`Tag::from_word`] only for raw stack/wire decoding that must preserve untrusted tags before
    /// validation.
    pub fn precompile(id: Felt, args: [Felt; 2]) -> Result<Self, DeferredError> {
        if Self::is_framework_reserved_id(id)
            || !has_domain_selector_encoding(id)
            || args.iter().any(|arg| arg.as_canonical_u64() > u64::from(MAX_EIDOS_INIT_VALUE))
        {
            return Err(DeferredError::InvalidTag);
        }
        Ok(Self { id, args, reserved: ZERO })
    }

    /// Returns the precompile/framework id component.
    pub const fn id(&self) -> Felt {
        self.id
    }

    /// Returns the two local parameters.
    pub const fn args(&self) -> [Felt; 2] {
        self.args
    }

    /// Returns whether the reserved fourth tag lane is canonical zero.
    pub fn has_canonical_reserved_lane(&self) -> bool {
        self.reserved == ZERO
    }

    /// Returns whether every tag value can be injected into an Eidos initial CV without carry.
    pub fn has_canonical_init_values(&self) -> bool {
        self.id.as_canonical_u64() <= u64::from(MAX_EIDOS_INIT_VALUE)
            && self
                .args
                .iter()
                .all(|arg| arg.as_canonical_u64() <= u64::from(MAX_EIDOS_INIT_VALUE))
    }

    /// Returns the canonical layout used by hashing and wire encoding.
    pub const fn as_word(&self) -> [Felt; 4] {
        [self.id, self.args[0], self.args[1], self.reserved]
    }

    /// Restores a tag from the canonical 4-felt layout without validation.
    pub const fn from_word(w: [Felt; 4]) -> Self {
        Self {
            id: w[0],
            args: [w[1], w[2]],
            reserved: w[3],
        }
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
/// Payloads have four representations:
///
/// - TRUE: the framework sentinel, carrying no data.
/// - Data: one or more opaque [`DataChunk`]s.
/// - Join: one [`DataChunk`] containing two child digests (`lhs || rhs`).
/// - PairList: one or more structural digest pairs, each chunked as `lhs || rhs`.
///
/// The representation is private: external precompiles can inspect payloads through accessors, but
/// cannot fabricate framework TRUE, empty data, or unchecked structural payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload(PayloadRepr);

#[derive(Debug, Clone, PartialEq, Eq)]
enum PayloadRepr {
    /// The framework TRUE sentinel; carries no data.
    True,
    /// Non-empty opaque data.
    Data(Arc<[DataChunk]>),
    /// Two child digests encoded as `lhs || rhs`.
    Join(DataChunk),
    /// Non-empty structural digest pairs, stored as chunks `lhs || rhs`.
    PairList(Arc<[DataChunk]>),
}

impl Payload {
    /// Creates a single-chunk data payload.
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
        let [l0, l1, l2, l3] = lhs.into_elements();
        let [r0, r1, r2, r3] = rhs.into_elements();
        Self(PayloadRepr::Join([l0, l1, l2, l3, r0, r1, r2, r3]))
    }

    /// Creates a pair-list payload from a non-empty collection of structural digest pairs.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `pairs` is empty.
    fn try_pair_list(pairs: impl Into<Arc<[(Digest, Digest)]>>) -> Result<Self, DeferredError> {
        let pairs = pairs.into();
        let chunks = pairs
            .iter()
            .map(|(lhs, rhs)| Self::pair_to_chunk(*lhs, *rhs))
            .collect::<Vec<_>>();
        Self::try_pair_list_chunks(chunks)
    }

    /// Creates a pair-list payload from non-empty chunks encoded as `lhs || rhs`.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty.
    fn try_pair_list_chunks(chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        let chunks = chunks.into();
        if chunks.is_empty() {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(Self(PayloadRepr::PairList(chunks)))
    }

    fn pair_to_chunk(lhs: Digest, rhs: Digest) -> DataChunk {
        let [l0, l1, l2, l3] = lhs.into_elements();
        let [r0, r1, r2, r3] = rhs.into_elements();
        [l0, l1, l2, l3, r0, r1, r2, r3]
    }

    fn chunk_to_pair([l0, l1, l2, l3, r0, r1, r2, r3]: DataChunk) -> (Digest, Digest) {
        (Digest::new([l0, l1, l2, l3]), Digest::new([r0, r1, r2, r3]))
    }

    /// Returns this payload's canonical 8-felt blocks.
    ///
    /// - TRUE returns no blocks.
    /// - Data returns its stored chunks.
    /// - Join returns one block containing `lhs || rhs`.
    /// - PairList returns one block per pair, each containing `lhs || rhs`.
    pub fn as_chunks(&self) -> &[DataChunk] {
        match &self.0 {
            PayloadRepr::True => &[],
            PayloadRepr::Data(chunks) | PayloadRepr::PairList(chunks) => chunks,
            PayloadRepr::Join(chunk) => core::slice::from_ref(chunk),
        }
    }

    /// Returns this payload's data chunks.
    ///
    /// - Data returns its stored chunks.
    /// - TRUE, Join, and PairList return [`DeferredError::InvalidPayload`].
    pub fn as_data(&self) -> Result<&[DataChunk], DeferredError> {
        match &self.0 {
            PayloadRepr::Data(chunks) => Ok(chunks),
            PayloadRepr::True | PayloadRepr::Join(_) | PayloadRepr::PairList(_) => {
                Err(DeferredError::InvalidPayload)
            },
        }
    }

    /// Returns the single data chunk for value-like payloads.
    ///
    /// - One-chunk Data returns that chunk.
    /// - Multi-chunk Data, TRUE, Join, and PairList return [`DeferredError::InvalidPayload`].
    pub fn as_value(&self) -> Result<&DataChunk, DeferredError> {
        match self.as_data()? {
            [chunk] => Ok(chunk),
            _ => Err(DeferredError::InvalidPayload),
        }
    }

    /// Returns the child digests for join payloads.
    ///
    /// - Join returns `(lhs, rhs)`.
    /// - TRUE, Data, and PairList return [`DeferredError::InvalidPayload`].
    pub fn as_join(&self) -> Result<(Digest, Digest), DeferredError> {
        match &self.0 {
            PayloadRepr::Join([l0, l1, l2, l3, r0, r1, r2, r3]) => {
                Ok((Digest::new([*l0, *l1, *l2, *l3]), Digest::new([*r0, *r1, *r2, *r3])))
            },
            PayloadRepr::True | PayloadRepr::Data(_) | PayloadRepr::PairList(_) => {
                Err(DeferredError::InvalidPayload)
            },
        }
    }

    fn pair_list_chunks(&self) -> Result<&[DataChunk], DeferredError> {
        match &self.0 {
            PayloadRepr::PairList(chunks) => Ok(chunks),
            PayloadRepr::True | PayloadRepr::Data(_) | PayloadRepr::Join(_) => {
                Err(DeferredError::InvalidPayload)
            },
        }
    }

    /// Returns the structural digest pairs for pair-list payloads.
    ///
    /// - PairList decodes and returns its pairs in payload order.
    /// - TRUE, Data, and Join return [`DeferredError::InvalidPayload`].
    pub fn as_pair_list(&self) -> Result<Vec<(Digest, Digest)>, DeferredError> {
        Ok(self
            .pair_list_chunks()?
            .iter()
            .map(|chunk| Self::chunk_to_pair(*chunk))
            .collect())
    }

    /// Returns this payload's structural child digests in payload order.
    ///
    /// - TRUE and Data return no children.
    /// - Join returns `lhs`, then `rhs`.
    /// - PairList returns `lhs0`, `rhs0`, `lhs1`, `rhs1`, ...
    fn children(&self) -> Vec<Digest> {
        match &self.0 {
            PayloadRepr::Join([l0, l1, l2, l3, r0, r1, r2, r3]) => {
                alloc::vec![Digest::new([*l0, *l1, *l2, *l3]), Digest::new([*r0, *r1, *r2, *r3]),]
            },
            PayloadRepr::PairList(chunks) => chunks
                .iter()
                .flat_map(|chunk| {
                    let (lhs, rhs) = Self::chunk_to_pair(*chunk);
                    [lhs, rhs]
                })
                .collect(),
            PayloadRepr::True | PayloadRepr::Data(_) => Vec::new(),
        }
    }
}

// NODE
// ================================================================================================

/// A deferred DAG entry whose meaning is supplied by a framework tag or owning
/// [`super::Precompile`].
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
    pub(crate) const DATA_CHUNK_FELT_LEN: usize = 8;

    /// Number of little-endian bytes represented by one [`DataChunk`].
    ///
    /// Each of the eight field elements stores one packed `u32`, so a chunk carries 32 bytes.
    pub const PACKED_BYTES_PER_CHUNK: usize = Self::DATA_CHUNK_FELT_LEN * size_of::<u32>();

    /// Canonical TRUE node returned by predicates that verify successfully.
    pub const TRUE: Node = Node {
        tag: Tag::TRUE,
        payload: Payload(PayloadRepr::True),
    };

    /// Creates a value-like single-chunk data node.
    ///
    /// Returns [`DeferredError::InvalidTag`] if `tag` is not a canonical precompile tag.
    pub fn value(tag: Tag, chunk: DataChunk) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::value(chunk) })
    }

    /// Creates a data node from a non-empty chunk collection.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty and
    /// [`DeferredError::InvalidTag`] if `tag` is not a canonical precompile tag.
    pub fn try_data(tag: Tag, chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::try_data(chunks)? })
    }

    /// Creates a framework-owned opaque chunk-list data node.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty.
    pub fn chunks(chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        Ok(Self {
            tag: Tag::CHUNKS,
            payload: Payload::try_data(chunks)?,
        })
    }

    /// Creates a framework-owned opaque chunk-list data node from bytes.
    ///
    /// Bytes are packed little-endian into `u32` field elements, padded with zero felts to a
    /// non-empty multiple of one [`DataChunk`], and wrapped in the framework [`Tag::CHUNKS`] node.
    /// Empty byte strings therefore encode as a single all-zero chunk.
    pub fn chunks_from_bytes(bytes: &[u8]) -> Self {
        let mut felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(Self::DATA_CHUNK_FELT_LEN).max(1);
        felts.resize(n_chunks * Self::DATA_CHUNK_FELT_LEN, ZERO);
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let chunks = felts
            .as_chunks::<{ Self::DATA_CHUNK_FELT_LEN }>()
            .0
            .iter()
            .map(|chunk| core::array::from_fn(|i| chunk[i]))
            .collect::<Vec<_>>();
        Self::chunks(chunks).expect("chunks_from_bytes always creates at least one chunk")
    }

    /// Creates a join-shaped node that references two child digests.
    ///
    /// Returns [`DeferredError::InvalidTag`] if `tag` is not a canonical precompile tag.
    pub fn join(tag: Tag, lhs: Digest, rhs: Digest) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self { tag, payload: Payload::join(lhs, rhs) })
    }

    /// Creates a pair-list-shaped node that references one or more structural digest pairs.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `pairs` is empty and
    /// [`DeferredError::InvalidTag`] if `tag` is not a canonical precompile tag.
    pub fn try_pair_list(
        tag: Tag,
        pairs: impl Into<Arc<[(Digest, Digest)]>>,
    ) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self {
            tag,
            payload: Payload::try_pair_list(pairs)?,
        })
    }

    /// Creates a pair-list-shaped node from non-empty chunks encoded as `lhs_digest || rhs_digest`.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty and
    /// [`DeferredError::InvalidTag`] if `tag` is not a canonical precompile tag.
    pub fn try_pair_list_chunks(
        tag: Tag,
        chunks: impl Into<Arc<[DataChunk]>>,
    ) -> Result<Self, DeferredError> {
        let tag = Self::require_precompile_tag(tag)?;
        Ok(Self {
            tag,
            payload: Payload::try_pair_list_chunks(chunks)?,
        })
    }

    /// Creates a structural deferred-root AND step from the previous root and statement digest.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self {
            tag: Tag::AND,
            payload: Payload::join(lhs, rhs),
        }
    }

    fn require_precompile_tag(tag: Tag) -> Result<Tag, DeferredError> {
        if tag.is_framework_reserved()
            || !has_domain_selector_encoding(tag.id())
            || !tag.has_canonical_reserved_lane()
            || !tag.has_canonical_init_values()
        {
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

    /// Returns this node's structural child digests in payload order.
    ///
    /// This is infallible because [`Node`] constructors determine the payload representation:
    ///
    /// - data and TRUE nodes have no children;
    /// - join nodes yield `lhs`, then `rhs`;
    /// - pair-list nodes yield `lhs0`, `rhs0`, `lhs1`, `rhs1`, ...
    pub(crate) fn children(&self) -> impl Iterator<Item = Digest> + '_ {
        self.payload.children().into_iter()
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
        matches!(&self.payload.0, PayloadRepr::True) && self.tag == Tag::TRUE
    }

    /// Returns the field-element length of this node's canonical external representation.
    pub fn felt_len(&self) -> usize {
        Tag::FELT_LEN
            .checked_add(
                Self::DATA_CHUNK_FELT_LEN
                    .checked_mul(self.payload.as_chunks().len())
                    .expect("payload felt count overflow"),
            )
            .expect("node felt count overflow")
    }

    /// Returns the storage/budget footprint for durable state accounting.
    pub(crate) fn storage_felt_len(&self) -> usize {
        if self.is_true() { 0 } else { self.felt_len() }
    }

    /// Appends this node's canonical external representation to `target`.
    pub fn write_into_felts(&self, target: &mut Vec<Felt>) {
        target.extend_from_slice(&self.tag.as_word());
        for chunk in self.payload.as_chunks() {
            target.extend_from_slice(chunk);
        }
    }

    /// Returns this node's canonical external representation.
    pub fn to_felts(&self) -> Vec<Felt> {
        let mut felts = Vec::with_capacity(self.felt_len());
        self.write_into_felts(&mut felts);
        felts
    }

    /// Computes the canonical digest used by both host code and Miden VM programs.
    pub fn digest(&self) -> Digest {
        if matches!(&self.payload.0, PayloadRepr::True) {
            assert_eq!(self.tag, Tag::TRUE, "TRUE payload is only valid for Node::TRUE");
            return TRUE_DIGEST;
        }

        let chunks = self.payload.as_chunks();
        if self.tag == Tag::AND {
            let [chunk] = chunks else {
                unreachable!("AND nodes always contain exactly one digest pair")
            };
            return Eidos::hash_elements_in_domain(chunk, DEFERRED_AND_DOMAIN);
        }
        if self.tag == Tag::CHUNKS {
            let logical_len = Self::DATA_CHUNK_FELT_LEN
                .checked_mul(chunks.len())
                .and_then(|len| u32::try_from(len).ok())
                .expect("deferred CHUNKS felt length must fit in u32");
            let mut cv = Eidos::init_chaining_word(
                DEFERRED_CHUNKS_DOMAIN.as_canonical_u64() as u32,
                logical_len,
            );
            for chunk in chunks {
                cv = Eidos::compress(cv, *chunk);
            }
            return cv;
        }

        // Precompile-owned nodes bind their registered selector, complete payload length, and two
        // local arguments into the initial chaining value. The payload is an aligned sequence of
        // complete Eidos blocks.
        assert!(
            self.tag.has_canonical_reserved_lane(),
            "deferred tag reserved lane must be zero"
        );
        assert!(self.tag.has_canonical_init_values(), "deferred tag values must fit in u32");
        let payload_len = Self::DATA_CHUNK_FELT_LEN
            .checked_mul(chunks.len())
            .and_then(|len| u32::try_from(len).ok())
            .expect("deferred node payload length must fit in u32");
        let [arg0, arg1] = self.tag.args();
        let mut cv = Eidos::init_chaining_word_with_params(
            self.tag.id().as_canonical_u64() as u32,
            [payload_len, arg0.as_canonical_u64() as u32, arg1.as_canonical_u64() as u32],
        );
        for chunk in chunks {
            cv = Eidos::compress(cv, *chunk);
        }
        cv
    }
}

// NODE TYPE
// ================================================================================================

/// Framework shape a precompile declares for a recognized tag.
///
/// The shape tells registration and wire validation whether a body is non-empty opaque data, two
/// child digests, or a non-empty list of digest pairs. It intentionally does not carry
/// data/pair-list arity. Any semantic length encoded by a precompile's tag, such as a hash preimage
/// byte length, is checked during precompile evaluation. `True` is the framework sentinel owned
/// exclusively by [`Tag::TRUE`];
/// precompiles never declare it. Predicate status is not a shape; predicates succeed by evaluating
/// to [`Node::TRUE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// The framework TRUE sentinel, with no data payload.
    True,
    /// Non-empty opaque data.
    Data,
    /// Two child digests.
    Join,
    /// Non-empty structural digest pairs.
    PairList,
}

impl NodeType {
    /// Validates that a node's payload matches this declared framework shape.
    pub(crate) fn validate_node(self, node: &Node) -> Result<(), DeferredError> {
        match self {
            Self::True if node.is_true() => Ok(()),
            Self::Data if node.payload.as_data().is_ok() => Ok(()),
            Self::Join if node.payload.as_join().is_ok() => Ok(()),
            Self::PairList if node.payload.pair_list_chunks().is_ok() => Ok(()),
            _ => Err(DeferredError::InvalidPayload),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::deferred::precompile::test_precompile_selector;

    const TAG_A: Tag = Tag::from_word([test_precompile_selector(1), ZERO, ZERO, ZERO]);
    const TAG_B: Tag =
        Tag::from_word([test_precompile_selector(1), ZERO, Felt::new_unchecked(1), ZERO]);

    fn block(seed: u64) -> DataChunk {
        core::array::from_fn(|i| Felt::new_unchecked(seed.wrapping_add(i as u64)))
    }

    #[test]
    fn tag_precompile_rejects_reserved_and_unregistered_selectors_but_from_word_is_raw() {
        assert_eq!(Tag::precompile(Tag::TRUE.id(), [ZERO; 2]), Err(DeferredError::InvalidTag));
        assert_eq!(Tag::precompile(Tag::AND.id(), [ZERO; 2]), Err(DeferredError::InvalidTag));
        assert_eq!(Tag::precompile(Tag::CHUNKS.id(), [ZERO; 2]), Err(DeferredError::InvalidTag));
        assert_eq!(
            Tag::precompile(Tag::CHUNKS.id(), [Felt::new_unchecked(9), ZERO]),
            Err(DeferredError::InvalidTag)
        );
        assert_eq!(
            Tag::precompile(Felt::from_u32(u32::from(crate::operations::opcodes::JOIN)), [ZERO; 2],),
            Err(DeferredError::InvalidTag)
        );
        assert_eq!(
            Tag::precompile(Felt::from_u32(0x100), [ZERO; 2]),
            Err(DeferredError::InvalidTag)
        );

        let raw_true = Tag::from_word([ZERO, Felt::new_unchecked(9), ZERO, ZERO]);
        assert_eq!(raw_true.id(), Tag::TRUE.id());
        assert_eq!(raw_true.args(), [Felt::new_unchecked(9), ZERO]);
        assert!(raw_true.has_canonical_reserved_lane());

        let raw_chunks = Tag::from_word([Tag::CHUNKS.id(), Felt::new_unchecked(9), ZERO, ZERO]);
        assert_eq!(raw_chunks.id(), Tag::CHUNKS.id());
        assert_eq!(raw_chunks.args(), [Felt::new_unchecked(9), ZERO]);
        assert!(raw_chunks.has_canonical_reserved_lane());
    }

    #[test]
    fn tag_precompile_accepts_full_u32_selector_and_arguments() {
        let max = Felt::from_u32(u32::MAX);
        let tag = Tag::precompile(max, [max; 2]).expect("u32::MAX is a valid framing value");
        assert_eq!(tag.as_word(), [max, max, max, ZERO]);
    }

    #[test]
    fn public_node_constructors_reject_framework_reserved_tags() {
        let chunk = block(1);
        assert_eq!(Node::value(Tag::TRUE, chunk), Err(DeferredError::InvalidTag));
        assert_eq!(Node::try_data(Tag::AND, alloc::vec![chunk]), Err(DeferredError::InvalidTag));
        assert_eq!(Node::try_data(Tag::CHUNKS, alloc::vec![chunk]), Err(DeferredError::InvalidTag));
        assert_eq!(Node::join(Tag::AND, TRUE_DIGEST, TRUE_DIGEST), Err(DeferredError::InvalidTag));
        assert_eq!(
            Node::try_pair_list(Tag::AND, alloc::vec![(TRUE_DIGEST, TRUE_DIGEST)]),
            Err(DeferredError::InvalidTag)
        );

        let and = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and.tag(), Tag::AND);
        assert_eq!(and.payload().as_join().unwrap(), (TRUE_DIGEST, TRUE_DIGEST));
    }

    #[test]
    fn public_node_constructors_reject_noncanonical_precompile_tags() {
        let chunk = block(1);
        let too_large = Felt::new_unchecked(u64::from(u32::MAX) + 1);
        let malformed = [
            Tag::from_word([Felt::new_unchecked(42), ZERO, ZERO, ONE]),
            Tag::from_word([
                Felt::from_u32(u32::from(crate::operations::opcodes::JOIN)),
                ZERO,
                ZERO,
                ZERO,
            ]),
            Tag::from_word([too_large, ZERO, ZERO, ZERO]),
            Tag::from_word([test_precompile_selector(1), too_large, ZERO, ZERO]),
            Tag::from_word([test_precompile_selector(1), ZERO, too_large, ZERO]),
        ];

        for tag in malformed {
            assert_eq!(Node::value(tag, chunk), Err(DeferredError::InvalidTag));
            assert_eq!(Node::try_data(tag, alloc::vec![chunk]), Err(DeferredError::InvalidTag));
            assert_eq!(Node::join(tag, TRUE_DIGEST, TRUE_DIGEST), Err(DeferredError::InvalidTag));
            assert_eq!(
                Node::try_pair_list(tag, alloc::vec![(TRUE_DIGEST, TRUE_DIGEST)]),
                Err(DeferredError::InvalidTag)
            );
            assert_eq!(
                Node::try_pair_list_chunks(tag, alloc::vec![chunk]),
                Err(DeferredError::InvalidTag)
            );
        }
    }

    #[test]
    fn true_node_has_no_data_and_serializes_to_tag_only() {
        assert_eq!(Tag::TRUE, Tag::from_word([ZERO, ZERO, ZERO, ZERO]));
        assert_eq!(Tag::AND, Tag::from_word([ONE, ZERO, ZERO, ZERO]));
        assert_eq!(Tag::CHUNKS, Tag::from_word([Felt::new_unchecked(2), ZERO, ZERO, ZERO]));
        assert_eq!(Tag::TRUE.as_word(), [ZERO, ZERO, ZERO, ZERO]);
        assert_eq!(Tag::AND.as_word(), [ONE, ZERO, ZERO, ZERO]);
        assert_eq!(Tag::CHUNKS.as_word(), [Felt::new_unchecked(2), ZERO, ZERO, ZERO]);
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
        assert!(NodeType::Data.validate_node(&node).is_ok());
    }

    #[test]
    fn chunks_is_framework_data_and_non_empty() {
        assert_eq!(Node::chunks(Vec::<DataChunk>::new()), Err(DeferredError::InvalidPayload));

        let chunks = alloc::vec![block(1), block(9)];
        let node = Node::chunks(chunks.clone()).unwrap();
        assert_eq!(node.tag(), Tag::CHUNKS);
        assert_eq!(node.payload().as_data().unwrap(), &chunks[..]);
        assert!(NodeType::Data.validate_node(&node).is_ok());

        let mut expected = Tag::CHUNKS.as_word().to_vec();
        expected.extend_from_slice(&chunks[0]);
        expected.extend_from_slice(&chunks[1]);
        assert_eq!(node.to_felts(), expected);

        let precompile_data = Node::try_data(TAG_A, chunks).unwrap();
        assert_ne!(node.digest(), precompile_data.digest());
    }

    #[test]
    fn chunks_from_bytes_packs_little_endian_u32s_and_zero_pads() {
        assert_eq!(Node::PACKED_BYTES_PER_CHUNK, 32);

        let empty = Node::chunks_from_bytes(&[]);
        assert_eq!(empty.tag(), Tag::CHUNKS);
        assert_eq!(empty.payload().as_data().unwrap(), &[[ZERO; 8]][..]);

        let node = Node::chunks_from_bytes(&[1, 2, 3, 4, 5]);
        let chunks = node.payload().as_data().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], Felt::from_u32(u32::from_le_bytes([1, 2, 3, 4])));
        assert_eq!(chunks[0][1], Felt::from_u32(5));
        assert_eq!(&chunks[0][2..], &[ZERO; 6]);

        let long_bytes = (0u8..33).collect::<Vec<_>>();
        let long = Node::chunks_from_bytes(&long_bytes);
        let chunks = long.payload().as_data().unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0][0], Felt::from_u32(u32::from_le_bytes([0, 1, 2, 3])));
        assert_eq!(chunks[0][7], Felt::from_u32(u32::from_le_bytes([28, 29, 30, 31])));
        assert_eq!(chunks[1][0], Felt::from_u32(32));
        assert_eq!(&chunks[1][1..], &[ZERO; 7]);
    }

    #[test]
    fn value_is_data_one() {
        let chunk = block(5);
        let node = Node::value(TAG_A, chunk).unwrap();

        // A value is a single data chunk, not a separate framework shape.
        assert_eq!(node.payload().as_data().unwrap().len(), 1);
        assert_eq!(node.payload().as_value().unwrap(), &chunk);

        // Its external representation is `tag || one chunk`.
        assert_eq!(node.felt_len(), Tag::FELT_LEN + Node::DATA_CHUNK_FELT_LEN);
        let mut expected = TAG_A.as_word().to_vec();
        expected.extend_from_slice(&chunk);
        assert_eq!(node.to_felts(), expected);

        // A single data chunk digests the same way whether constructed through value or data APIs.
        let multi = Node::try_data(TAG_A, alloc::vec![chunk]).unwrap();
        assert_eq!(node.digest(), multi.digest());
    }

    #[test]
    fn data_shape_does_not_imply_one_chunk() {
        let node = Node::try_data(TAG_A, alloc::vec![block(1), block(9)]).unwrap();
        assert!(NodeType::Data.validate_node(&node).is_ok());
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
    fn join_round_trips_children_and_serializes() {
        let lhs = Node::value(TAG_A, block(1)).unwrap().digest();
        let rhs = Node::value(TAG_A, block(2)).unwrap().digest();
        let join = Node::join(TAG_B, lhs, rhs).unwrap();

        assert_eq!(join.payload().as_join().unwrap(), (lhs, rhs));
        assert!(join.payload().as_data().is_err());

        let mut payload = [ZERO; Node::DATA_CHUNK_FELT_LEN];
        payload[..Word::NUM_ELEMENTS].copy_from_slice(lhs.as_elements());
        payload[Word::NUM_ELEMENTS..].copy_from_slice(rhs.as_elements());

        // External representation is `tag || lhs || rhs`.
        assert_eq!(join.felt_len(), Tag::FELT_LEN + Node::DATA_CHUNK_FELT_LEN);
        let mut expected = TAG_B.as_word().to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(join.to_felts(), expected);

        assert_eq!(join.payload().as_chunks(), &[payload][..]);
    }

    #[test]
    fn pair_list_is_non_empty() {
        assert!(Payload::try_pair_list(Vec::<(Digest, Digest)>::new()).is_err());
        assert!(Node::try_pair_list(TAG_A, Vec::<(Digest, Digest)>::new()).is_err());
        assert!(Node::try_pair_list_chunks(TAG_A, Vec::<DataChunk>::new()).is_err());

        let lhs = Node::value(TAG_A, block(1)).unwrap().digest();
        let rhs = Node::value(TAG_A, block(2)).unwrap().digest();
        let node = Node::try_pair_list(TAG_A, alloc::vec![(lhs, rhs)]).unwrap();
        assert_eq!(node.payload().as_pair_list().unwrap(), alloc::vec![(lhs, rhs)]);
    }

    #[test]
    fn pair_list_round_trips_pairs_children_and_serializes() {
        let scalar_0 = Node::value(TAG_A, block(1)).unwrap().digest();
        let point_0 = Node::value(TAG_A, block(2)).unwrap().digest();
        let scalar_1 = Node::value(TAG_A, block(3)).unwrap().digest();
        let point_1 = Node::value(TAG_A, block(4)).unwrap().digest();
        let pairs = alloc::vec![(scalar_0, point_0), (scalar_1, point_1)];
        let node = Node::try_pair_list(TAG_B, pairs.clone()).unwrap();

        assert_eq!(node.payload().as_pair_list().unwrap(), pairs);
        assert!(node.payload().as_data().is_err());
        assert!(node.payload().as_join().is_err());
        assert_eq!(
            node.children().collect::<Vec<_>>(),
            alloc::vec![scalar_0, point_0, scalar_1, point_1]
        );

        let mut chunk_0 = [ZERO; Node::DATA_CHUNK_FELT_LEN];
        chunk_0[..Word::NUM_ELEMENTS].copy_from_slice(scalar_0.as_elements());
        chunk_0[Word::NUM_ELEMENTS..].copy_from_slice(point_0.as_elements());
        let mut chunk_1 = [ZERO; Node::DATA_CHUNK_FELT_LEN];
        chunk_1[..Word::NUM_ELEMENTS].copy_from_slice(scalar_1.as_elements());
        chunk_1[Word::NUM_ELEMENTS..].copy_from_slice(point_1.as_elements());

        assert_eq!(node.felt_len(), Tag::FELT_LEN + Node::DATA_CHUNK_FELT_LEN * 2);
        let mut expected = TAG_B.as_word().to_vec();
        expected.extend_from_slice(&chunk_0);
        expected.extend_from_slice(&chunk_1);
        assert_eq!(node.to_felts(), expected);
        assert_eq!(node.payload().as_chunks(), &[chunk_0, chunk_1][..]);

        let data_node = Node::try_data(TAG_B, alloc::vec![chunk_0, chunk_1]).unwrap();
        assert_eq!(node.digest(), data_node.digest(), "pair-list digest uses chunk hash layout");

        assert!(NodeType::PairList.validate_node(&node).is_ok());
        assert!(NodeType::Data.validate_node(&node).is_err());
    }
}
