//! Deferred node model: frames, payloads, shapes, and content-addressed digests.

use alloc::{sync::Arc, vec::Vec};
use core::mem::size_of;

use miden_crypto::{
    ZERO,
    hash::eidos::{Eidos, EidosDomain, EidosFrame},
};

use super::{DEFERRED_AND_FRAME, DeferredError, deferred_chunks_frame};
use crate::{
    Felt, Word,
    program::domain::{DeferredAndDomain, DeferredChunksDomain},
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

/// A deferred DAG entry interpreted by the framework or by the precompile that owns its frame.
///
/// The framework validates only the declared [`NodeType`]. Value semantics, producing ops, and
/// predicates all live in the owning [`super::Precompile`]. A predicate succeeds by evaluating to
/// [`Node::TRUE`], so callers can handle every canonical result as an ordinary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    frame: Option<EidosFrame>,
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
        frame: None,
        payload: Payload(PayloadRepr::True),
    };

    /// Creates a value-like single-chunk data node.
    ///
    /// Returns [`DeferredError::InvalidFrame`] if `frame` uses a framework domain.
    pub fn value(frame: EidosFrame, chunk: DataChunk) -> Result<Self, DeferredError> {
        let frame = Self::require_precompile_frame(frame)?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::value(chunk),
        })
    }

    /// Creates a data node from a non-empty chunk collection.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty and
    /// [`DeferredError::InvalidFrame`] if `frame` uses a framework domain.
    pub fn try_data(
        frame: EidosFrame,
        chunks: impl Into<Arc<[DataChunk]>>,
    ) -> Result<Self, DeferredError> {
        let frame = Self::require_precompile_frame(frame)?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::try_data(chunks)?,
        })
    }

    /// Creates a framework-owned opaque chunk-list data node.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty or its encoded Felt length
    /// does not fit in a `u32`.
    pub fn chunks(chunks: impl Into<Arc<[DataChunk]>>) -> Result<Self, DeferredError> {
        let chunks = chunks.into();
        let frame = Self::chunks_frame_for_len(chunks.len())?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::try_data(chunks)?,
        })
    }

    fn chunks_frame_for_len(n_chunks: usize) -> Result<EidosFrame, DeferredError> {
        let n_chunks = u32::try_from(n_chunks).map_err(|_| DeferredError::InvalidPayload)?;
        if n_chunks == 0 || n_chunks > u32::MAX / Self::DATA_CHUNK_FELT_LEN as u32 {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(deferred_chunks_frame(n_chunks))
    }

    fn chunks_frame_for_byte_len(n_bytes: usize) -> Result<EidosFrame, DeferredError> {
        let n_chunks = n_bytes.div_ceil(Self::PACKED_BYTES_PER_CHUNK).max(1);
        Self::chunks_frame_for_len(n_chunks)
    }

    /// Tries to create a framework-owned opaque chunk-list data node from bytes.
    ///
    /// Bytes are packed little-endian into `u32` field elements, padded with zero felts to a
    /// non-empty multiple of one [`DataChunk`], and wrapped in a `DEFERRED_CHUNKS` frame.
    /// Empty byte strings therefore encode as a single all-zero chunk.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if the encoded Felt length does not fit in a
    /// `u32`.
    pub fn try_chunks_from_bytes(bytes: &[u8]) -> Result<Self, DeferredError> {
        let frame = Self::chunks_frame_for_byte_len(bytes.len())?;
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
        Ok(Self {
            frame: Some(frame),
            payload: Payload::try_data(chunks)?,
        })
    }

    /// Creates a framework-owned opaque chunk-list data node from bytes.
    ///
    /// Bytes are packed little-endian into `u32` field elements, padded with zero felts to a
    /// non-empty multiple of one [`DataChunk`], and wrapped in a `DEFERRED_CHUNKS` frame.
    /// Empty byte strings therefore encode as a single all-zero chunk.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is longer than `32 * (u32::MAX / 8)` bytes. Use
    /// [`Node::try_chunks_from_bytes`] for untrusted input.
    pub fn chunks_from_bytes(bytes: &[u8]) -> Self {
        Self::try_chunks_from_bytes(bytes)
            .expect("chunks_from_bytes requires its encoded Felt length to fit in a u32")
    }

    /// Creates a join-shaped node that references two child digests.
    ///
    /// Returns [`DeferredError::InvalidFrame`] if `frame` uses a framework domain.
    pub fn join(frame: EidosFrame, lhs: Digest, rhs: Digest) -> Result<Self, DeferredError> {
        let frame = Self::require_precompile_frame(frame)?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::join(lhs, rhs),
        })
    }

    /// Creates a pair-list-shaped node that references one or more structural digest pairs.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `pairs` is empty and
    /// [`DeferredError::InvalidFrame`] if `frame` uses a framework domain.
    pub fn try_pair_list(
        frame: EidosFrame,
        pairs: impl Into<Arc<[(Digest, Digest)]>>,
    ) -> Result<Self, DeferredError> {
        let frame = Self::require_precompile_frame(frame)?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::try_pair_list(pairs)?,
        })
    }

    /// Creates a pair-list-shaped node from non-empty chunks encoded as `lhs_digest || rhs_digest`.
    ///
    /// Returns [`DeferredError::InvalidPayload`] if `chunks` is empty and
    /// [`DeferredError::InvalidFrame`] if `frame` uses a framework domain.
    pub fn try_pair_list_chunks(
        frame: EidosFrame,
        chunks: impl Into<Arc<[DataChunk]>>,
    ) -> Result<Self, DeferredError> {
        let frame = Self::require_precompile_frame(frame)?;
        Ok(Self {
            frame: Some(frame),
            payload: Payload::try_pair_list_chunks(chunks)?,
        })
    }

    /// Creates a structural deferred-root AND step from the previous root and statement digest.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self {
            frame: Some(DEFERRED_AND_FRAME),
            payload: Payload::join(lhs, rhs),
        }
    }

    fn require_precompile_frame(frame: EidosFrame) -> Result<EidosFrame, DeferredError> {
        if frame.domain() == DeferredAndDomain::TAG || frame.domain() == DeferredChunksDomain::TAG {
            return Err(DeferredError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Returns this node's frame, or `None` for the TRUE sentinel.
    pub fn frame(&self) -> Option<EidosFrame> {
        self.frame
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

    /// Returns this node's payload if the node has `frame`.
    pub fn payload_for_frame(&self, frame: EidosFrame) -> Result<&Payload, DeferredError> {
        if self.frame != Some(frame) {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(&self.payload)
    }

    /// Returns whether this node is structurally the canonical TRUE result.
    pub fn is_true(&self) -> bool {
        matches!(&self.payload.0, PayloadRepr::True) && self.frame.is_none()
    }

    /// Returns the field-element length of this node's canonical external representation.
    pub fn felt_len(&self) -> usize {
        EidosFrame::FELT_LEN
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
        let frame = self.frame.map(EidosFrame::as_word).unwrap_or_default();
        target.extend_from_slice(&frame.into_elements());
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
            assert!(self.frame.is_none(), "TRUE payload is only valid for Node::TRUE");
            return TRUE_DIGEST;
        }

        let frame = self.frame.expect("non-TRUE deferred nodes have a frame");
        let mut cv = frame.initial_chaining_word();
        for chunk in self.payload.as_chunks() {
            cv = Eidos::compress(cv, *chunk);
        }
        cv
    }
}

// NODE TYPE
// ================================================================================================

/// Framework shape a precompile declares for a recognized frame.
///
/// The shape tells registration and wire validation whether a body is non-empty opaque data, two
/// child digests, or a non-empty list of digest pairs. It intentionally does not carry
/// data/pair-list arity. Any semantic length encoded by a frame parameter, such as a hash preimage
/// byte length, is checked by the owning precompile during validation or evaluation. `True` is the
/// framework sentinel owned exclusively by [`Node::TRUE`];
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
    use crate::deferred::precompile::test_precompile_domain_tag;

    const FRAME_A: EidosFrame = EidosFrame::new(test_precompile_domain_tag(1), [0; 3]);
    const FRAME_B: EidosFrame = EidosFrame::new(test_precompile_domain_tag(1), [0, 1, 0]);

    fn block(seed: u64) -> DataChunk {
        core::array::from_fn(|i| Felt::new_unchecked(seed.wrapping_add(i as u64)))
    }

    #[test]
    fn frame_accepts_full_u32_parameters() {
        let frame = EidosFrame::new(test_precompile_domain_tag(1), [u32::MAX; 3]);
        assert_eq!(frame.params(), [u32::MAX; 3]);
        assert_eq!(EidosFrame::from_word(frame.as_word()), Some(frame));
    }

    #[test]
    fn public_node_constructors_reject_framework_frames() {
        let chunk = block(1);
        let chunks_frame = deferred_chunks_frame(1);
        assert_eq!(Node::value(DEFERRED_AND_FRAME, chunk), Err(DeferredError::InvalidFrame));
        assert_eq!(
            Node::try_data(DEFERRED_AND_FRAME, alloc::vec![chunk]),
            Err(DeferredError::InvalidFrame)
        );
        assert_eq!(
            Node::try_data(chunks_frame, alloc::vec![chunk]),
            Err(DeferredError::InvalidFrame)
        );
        assert_eq!(
            Node::join(DEFERRED_AND_FRAME, TRUE_DIGEST, TRUE_DIGEST),
            Err(DeferredError::InvalidFrame)
        );
        assert_eq!(
            Node::try_pair_list(DEFERRED_AND_FRAME, alloc::vec![(TRUE_DIGEST, TRUE_DIGEST)]),
            Err(DeferredError::InvalidFrame)
        );

        let and = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and.frame(), Some(DEFERRED_AND_FRAME));
        assert_eq!(and.payload().as_join().unwrap(), (TRUE_DIGEST, TRUE_DIGEST));
    }

    #[test]
    fn true_node_has_no_data_and_serializes_to_zero_word_in_frame_slot() {
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));

        let true_node = Node::TRUE;
        assert_eq!(true_node.frame(), None);
        assert!(true_node.is_true());
        assert_eq!(true_node.digest(), TRUE_DIGEST);
        assert_eq!(true_node.felt_len(), EidosFrame::FELT_LEN);
        assert_eq!(true_node.to_felts(), alloc::vec![ZERO; EidosFrame::FELT_LEN]);
        assert_eq!(true_node.storage_felt_len(), 0);
        assert!(true_node.payload().as_data().is_err());
        assert!(true_node.payload().as_value().is_err());
    }

    #[test]
    fn data_is_non_empty() {
        // Empty data cannot be constructed: TRUE is the only zero-payload node.
        assert!(Payload::try_data(Vec::<DataChunk>::new()).is_err());
        assert!(Node::try_data(FRAME_A, Vec::<DataChunk>::new()).is_err());

        let node = Node::try_data(FRAME_A, alloc::vec![block(1), block(9)]).unwrap();
        assert_eq!(node.payload().as_data().unwrap(), &[block(1), block(9)][..]);
        assert!(NodeType::Data.validate_node(&node).is_ok());
    }

    #[test]
    fn chunks_is_framework_data_and_non_empty() {
        assert_eq!(Node::chunks(Vec::<DataChunk>::new()), Err(DeferredError::InvalidPayload));
        assert_eq!(
            Node::chunks_frame_for_len((u32::MAX / Node::DATA_CHUNK_FELT_LEN as u32 + 1) as usize),
            Err(DeferredError::InvalidPayload)
        );

        let chunks = alloc::vec![block(1), block(9)];
        let node = Node::chunks(chunks.clone()).unwrap();
        assert_eq!(node.frame(), Some(deferred_chunks_frame(2)));
        assert_eq!(node.payload().as_data().unwrap(), &chunks[..]);
        assert!(NodeType::Data.validate_node(&node).is_ok());

        let mut expected = deferred_chunks_frame(2).as_word().as_elements().to_vec();
        expected.extend_from_slice(&chunks[0]);
        expected.extend_from_slice(&chunks[1]);
        assert_eq!(node.to_felts(), expected);

        let precompile_data = Node::try_data(FRAME_A, chunks).unwrap();
        assert_ne!(node.digest(), precompile_data.digest());
    }

    #[test]
    fn chunks_from_bytes_packs_little_endian_u32s_and_zero_pads() {
        assert_eq!(Node::PACKED_BYTES_PER_CHUNK, 32);

        let empty = Node::try_chunks_from_bytes(&[]).unwrap();
        assert_eq!(empty.frame(), Some(deferred_chunks_frame(1)));
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

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn chunks_from_bytes_checks_encoded_length_before_allocating() {
        let max_chunks = u32::MAX / Node::DATA_CHUNK_FELT_LEN as u32;
        let max_bytes = max_chunks as usize * Node::PACKED_BYTES_PER_CHUNK;

        assert_eq!(
            Node::chunks_frame_for_byte_len(max_bytes),
            Ok(deferred_chunks_frame(max_chunks))
        );
        assert_eq!(
            Node::chunks_frame_for_byte_len(max_bytes + 1),
            Err(DeferredError::InvalidPayload)
        );
    }

    #[test]
    fn value_is_data_one() {
        let chunk = block(5);
        let node = Node::value(FRAME_A, chunk).unwrap();

        // A value is a single data chunk, not a separate framework shape.
        assert_eq!(node.payload().as_data().unwrap().len(), 1);
        assert_eq!(node.payload().as_value().unwrap(), &chunk);

        // Its external representation is `frame || one chunk`.
        assert_eq!(node.felt_len(), EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN);
        let mut expected = FRAME_A.as_word().as_elements().to_vec();
        expected.extend_from_slice(&chunk);
        assert_eq!(node.to_felts(), expected);

        // A single data chunk digests the same way whether constructed through value or data APIs.
        let multi = Node::try_data(FRAME_A, alloc::vec![chunk]).unwrap();
        assert_eq!(node.digest(), multi.digest());
    }

    #[test]
    fn data_shape_does_not_imply_one_chunk() {
        let node = Node::try_data(FRAME_A, alloc::vec![block(1), block(9)]).unwrap();
        assert!(NodeType::Data.validate_node(&node).is_ok());
        assert!(node.payload().as_value().is_err());
        assert_eq!(node.payload().as_data().unwrap().len(), 2);
        assert_eq!(node.felt_len(), EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN * 2);
    }

    #[test]
    fn digest_binds_frame_and_payload() {
        let chunk = block(7);
        let same = Node::value(FRAME_A, chunk).unwrap();
        let different_frame = Node::value(FRAME_B, chunk).unwrap();
        let different_payload = Node::value(FRAME_A, block(8)).unwrap();

        assert_ne!(same.digest(), different_frame.digest());
        assert_ne!(same.digest(), different_payload.digest());
    }

    #[test]
    fn join_round_trips_children_and_serializes() {
        let lhs = Node::value(FRAME_A, block(1)).unwrap().digest();
        let rhs = Node::value(FRAME_A, block(2)).unwrap().digest();
        let join = Node::join(FRAME_B, lhs, rhs).unwrap();

        assert_eq!(join.payload().as_join().unwrap(), (lhs, rhs));
        assert!(join.payload().as_data().is_err());

        let mut payload = [ZERO; Node::DATA_CHUNK_FELT_LEN];
        payload[..Word::NUM_ELEMENTS].copy_from_slice(lhs.as_elements());
        payload[Word::NUM_ELEMENTS..].copy_from_slice(rhs.as_elements());

        // External representation is `frame || lhs || rhs`.
        assert_eq!(join.felt_len(), EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN);
        let mut expected = FRAME_B.as_word().as_elements().to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(join.to_felts(), expected);

        assert_eq!(join.payload().as_chunks(), &[payload][..]);
    }

    #[test]
    fn pair_list_is_non_empty() {
        assert!(Payload::try_pair_list(Vec::<(Digest, Digest)>::new()).is_err());
        assert!(Node::try_pair_list(FRAME_A, Vec::<(Digest, Digest)>::new()).is_err());
        assert!(Node::try_pair_list_chunks(FRAME_A, Vec::<DataChunk>::new()).is_err());

        let lhs = Node::value(FRAME_A, block(1)).unwrap().digest();
        let rhs = Node::value(FRAME_A, block(2)).unwrap().digest();
        let node = Node::try_pair_list(FRAME_A, alloc::vec![(lhs, rhs)]).unwrap();
        assert_eq!(node.payload().as_pair_list().unwrap(), alloc::vec![(lhs, rhs)]);
    }

    #[test]
    fn pair_list_round_trips_pairs_children_and_serializes() {
        let scalar_0 = Node::value(FRAME_A, block(1)).unwrap().digest();
        let point_0 = Node::value(FRAME_A, block(2)).unwrap().digest();
        let scalar_1 = Node::value(FRAME_A, block(3)).unwrap().digest();
        let point_1 = Node::value(FRAME_A, block(4)).unwrap().digest();
        let pairs = alloc::vec![(scalar_0, point_0), (scalar_1, point_1)];
        let node = Node::try_pair_list(FRAME_B, pairs.clone()).unwrap();

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

        assert_eq!(node.felt_len(), EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN * 2);
        let mut expected = FRAME_B.as_word().as_elements().to_vec();
        expected.extend_from_slice(&chunk_0);
        expected.extend_from_slice(&chunk_1);
        assert_eq!(node.to_felts(), expected);
        assert_eq!(node.payload().as_chunks(), &[chunk_0, chunk_1][..]);

        let data_node = Node::try_data(FRAME_B, alloc::vec![chunk_0, chunk_1]).unwrap();
        assert_eq!(node.digest(), data_node.digest(), "pair-list digest uses chunk hash layout");

        assert!(NodeType::PairList.validate_node(&node).is_ok());
        assert!(NodeType::Data.validate_node(&node).is_err());
    }
}
