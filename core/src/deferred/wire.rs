//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a canonical, topologically ordered stream of the explicit DAG entries needed to
//! open an externally committed deferred root. Wire index 0 is reserved for the implicit TRUE node;
//! entry `i` has wire index `i + 1`, and join entries may only reference TRUE or earlier entries.
//! Empty wire opens [`TRUE_DIGEST`]; otherwise the root is the digest of the final entry.
//!
//! Rehydration decodes the untrusted stream into ordinary [`DeferredState`] nodes, rejects
//! non-canonical/dangling wire by comparing with [`DeferredState::to_wire`], and finally evaluates
//! the implicit root to repopulate evaluation memos. Binding that root to execution is a caller
//! responsibility: compare the returned state's root to the externally committed root.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    sync::Arc,
    vec::Vec,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    DataChunk, DeferredError, DeferredState, Digest, Node, NodeType, PrecompileError,
    PrecompileRegistry, TRUE_DIGEST, Tag,
};
use crate::{
    Felt, ZERO,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// CONSTANTS
// ================================================================================================

/// Reserved index for the always-known [`super::TRUE_DIGEST`] / [`super::Node::TRUE`] node.
pub const TRUE_INDEX: u32 = 0;

// WIRE ENTRY
// ================================================================================================

/// One explicit deferred DAG entry in topological wire order.
///
/// Wire index 0 is implicit TRUE. `entries[i]` has wire index `i + 1`. Join children must reference
/// `TRUE_INDEX` or an earlier entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WireEntry {
    /// Non-empty data payload interpreted by the tag's precompile; a one-chunk entry is a value.
    Data { tag: Tag, chunks: Vec<DataChunk> },
    /// Two child references resolved against `TRUE_INDEX` or earlier wire indices.
    Join { tag: Tag, lhs: u32, rhs: u32 },
}

// DEFERRED STATE WIRE
// ================================================================================================

/// Wire representation of a deferred root opening.
///
/// The root is implicit: empty `entries` opens [`TRUE_DIGEST`], otherwise the root is the digest of
/// the last entry. Accepted wire must be topologically ordered, root-last, duplicate-free,
/// canonical, and semantically valid under the installed [`PrecompileRegistry`]. Callers bind the
/// wire to execution by comparing the returned state's root to an externally committed root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeferredStateWire {
    pub entries: Vec<WireEntry>,
}

impl DeferredStateWire {
    /// Serializes the root-reachable DAG into deterministic wire form.
    pub(crate) fn from_state(state: &DeferredState) -> Result<Self, IntegrityError> {
        let mut build = WireEncoder::default();
        build.visit_state_digest(state, state.root())?;
        Ok(Self { entries: build.entries })
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    pub(crate) fn rehydrate(
        &self,
        precompiles: Arc<PrecompileRegistry>,
        max_elements: usize,
    ) -> Result<DeferredState, IntegrityError> {
        let (entries, root) = WireDecoder::new(self, precompiles.as_ref())?.decode()?;
        let mut state = DeferredState::new(Arc::clone(&precompiles), max_elements)?;

        // Register entries in strict topological wire order. Join children have already been
        // decoded to earlier digests, so ordinary DeferredState registration enforces the
        // same child-closure and budget rules as execution.
        for (digest, node) in entries {
            let registered = state.register(node)?;
            if registered != digest {
                return Err(IntegrityError::InvalidStructure);
            }
        }

        state.root = root;

        // `to_wire` emits the deterministic root-reachable closure. Equality makes the accepted
        // format strict: root-last, canonical DFS order, and no dangling or duplicate
        // entries.
        if state.to_wire()? != *self {
            return Err(IntegrityError::InvalidStructure);
        }

        if state.evaluate_digest(root)? != TRUE_DIGEST {
            return Err(IntegrityError::RootNotTrue);
        }

        Ok(state)
    }
}

// INTEGRITY ERROR
// ================================================================================================

/// Reasons untrusted wire data failed deferred-state rehydration.
///
/// Any variant rejects the proof witness under the installed `PrecompileRegistry`. Structural wire
/// details intentionally collapse into [`Self::InvalidStructure`]; callers only need to distinguish
/// malformed/non-canonical openings, root mismatches, semantic root failures, and budget failures.
/// The enum is not `Clone`/`Eq` because evaluation failures carry opaque precompile errors.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// The wire/state structure is malformed or not the canonical root-last opening.
    #[error("invalid or non-canonical deferred wire/state structure")]
    InvalidStructure,
    /// Root evaluation failed under the installed precompile registry.
    #[error("deferred root failed evaluation: {0}")]
    EvaluationFailed(#[source] PrecompileError),
    /// The root evaluated, but not to the canonical TRUE node.
    #[error("deferred root evaluated to a non-TRUE canonical form")]
    RootNotTrue,
    /// Rehydrating the wire would exceed the configured deferred-state budget.
    #[error("deferred insertion requires {num_elements} elements but only {max} remain")]
    DeferredStateTooLarge { num_elements: usize, max: usize },
}

impl From<PrecompileError> for IntegrityError {
    fn from(err: PrecompileError) -> Self {
        if let PrecompileError::Other(DeferredError::DeferredStateTooLarge { num_elements, max }) =
            err.root()
        {
            Self::DeferredStateTooLarge { num_elements: *num_elements, max: *max }
        } else {
            Self::EvaluationFailed(err)
        }
    }
}

// WIRE REHYDRATION
// ================================================================================================

struct WireDecoder<'a> {
    wire: &'a DeferredStateWire,
    precompiles: &'a PrecompileRegistry,
    entries: Vec<(Digest, Node)>,
    index_to_digest: Vec<Digest>,
    seen_digests: BTreeSet<Digest>,
}

impl<'a> WireDecoder<'a> {
    fn new(
        wire: &'a DeferredStateWire,
        precompiles: &'a PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let total_nodes =
            1usize.checked_add(wire.entries.len()).ok_or(IntegrityError::InvalidStructure)?;

        let mut index_to_digest = Vec::with_capacity(total_nodes);
        let mut seen_digests = BTreeSet::new();
        index_to_digest.push(TRUE_DIGEST);
        seen_digests.insert(TRUE_DIGEST);

        Ok(Self {
            wire,
            precompiles,
            entries: Vec::with_capacity(wire.entries.len()),
            index_to_digest,
            seen_digests,
        })
    }

    fn decode(mut self) -> Result<(Vec<(Digest, Node)>, Digest), IntegrityError> {
        for entry in &self.wire.entries {
            let node = match entry {
                WireEntry::Data { tag, chunks } => self.decode_data_entry(*tag, chunks)?,
                WireEntry::Join { tag, lhs, rhs } => self.decode_join_entry(*tag, *lhs, *rhs)?,
            };
            self.push_entry(node)?;
        }

        let root = *self.index_to_digest.last().expect("digest table is seeded with TRUE_DIGEST");
        Ok((self.entries, root))
    }

    fn decode_data_entry(&self, tag: Tag, chunks: &[DataChunk]) -> Result<Node, IntegrityError> {
        // The tag — never the wire — fixes the chunk count, and `Tag::TRUE`/`Tag::AND` decode to
        // non-data shapes, so explicit TRUE/join tags are rejected here.
        let node_type = self
            .precompiles
            .decode_node_type(tag)
            .map_err(|_| IntegrityError::InvalidStructure)?;
        let NodeType::Data(n) = node_type else {
            return Err(IntegrityError::InvalidStructure);
        };
        if chunks.len() != n.get() as usize {
            return Err(IntegrityError::InvalidStructure);
        }
        let node =
            Node::try_data(tag, chunks.to_vec()).map_err(|_| IntegrityError::InvalidStructure)?;
        node_type.validate_node(&node).map_err(|_| IntegrityError::InvalidStructure)?;
        Ok(node)
    }

    fn decode_join_entry(&self, tag: Tag, lhs: u32, rhs: u32) -> Result<Node, IntegrityError> {
        let lhs = self.resolve_index(lhs)?;
        let rhs = self.resolve_index(rhs)?;
        let node = if tag == Tag::AND {
            Node::and(lhs, rhs)
        } else {
            Node::join(tag, lhs, rhs).map_err(|_| IntegrityError::InvalidStructure)?
        };
        let node_type = self
            .precompiles
            .decode_node_type(node.tag())
            .map_err(|_| IntegrityError::InvalidStructure)?;
        node_type.validate_node(&node).map_err(|_| IntegrityError::InvalidStructure)?;
        match node_type {
            NodeType::Join => Ok(node),
            NodeType::True | NodeType::Data(_) => Err(IntegrityError::InvalidStructure),
        }
    }

    fn resolve_index(&self, idx: u32) -> Result<Digest, IntegrityError> {
        self.index_to_digest
            .get(idx as usize)
            .copied()
            .ok_or(IntegrityError::InvalidStructure)
    }

    fn push_entry(&mut self, node: Node) -> Result<(), IntegrityError> {
        if node.is_true() {
            return Err(IntegrityError::InvalidStructure);
        }

        let digest = node.digest();
        if !self.seen_digests.insert(digest) {
            return Err(IntegrityError::InvalidStructure);
        }

        let index = self.index_to_digest.len();
        if index > u32::MAX as usize {
            return Err(IntegrityError::InvalidStructure);
        }

        self.entries.push((digest, node));
        self.index_to_digest.push(digest);
        Ok(())
    }
}

// WIRE ENCODING
// ================================================================================================

/// Encoder for the canonical topological wire format used by [`super::DeferredState::to_wire`].
#[derive(Default)]
struct WireEncoder {
    seen: BTreeSet<Digest>,
    by_digest: BTreeMap<Digest, u32>,
    entries: Vec<WireEntry>,
}

impl WireEncoder {
    fn visit_state_digest(
        &mut self,
        state: &DeferredState,
        digest: Digest,
    ) -> Result<(), IntegrityError> {
        enum Frame {
            Enter(Digest),
            Emit(Digest),
        }

        let mut stack = Vec::from([Frame::Enter(digest)]);
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Enter(digest) => {
                    if digest == TRUE_DIGEST || !self.seen.insert(digest) {
                        continue;
                    }

                    let node = state.get_node(&digest).ok_or(IntegrityError::InvalidStructure)?;
                    let node_type = state
                        .registry()
                        .decode_node_type(node.tag())
                        .map_err(|_| IntegrityError::InvalidStructure)?;
                    node_type.validate_node(node).map_err(|_| IntegrityError::InvalidStructure)?;

                    stack.push(Frame::Emit(digest));
                    if let NodeType::Join = node_type {
                        let (lhs, rhs) = node_type
                            .children(node)
                            .map_err(|_| IntegrityError::InvalidStructure)?
                            .expect("join node type has children");
                        stack.push(Frame::Enter(rhs));
                        stack.push(Frame::Enter(lhs));
                    } else if let NodeType::True = node_type {
                        return Err(IntegrityError::InvalidStructure);
                    }
                },
                Frame::Emit(digest) => {
                    let node = state.get_node(&digest).ok_or(IntegrityError::InvalidStructure)?;
                    let node_type = state
                        .registry()
                        .decode_node_type(node.tag())
                        .map_err(|_| IntegrityError::InvalidStructure)?;
                    let entry = match node_type {
                        NodeType::Data(_) => WireEntry::Data {
                            tag: node.tag(),
                            chunks: node
                                .payload()
                                .as_data()
                                .map_err(|_| IntegrityError::InvalidStructure)?
                                .to_vec(),
                        },
                        NodeType::Join => {
                            let (lhs, rhs) = node_type
                                .children(node)
                                .map_err(|_| IntegrityError::InvalidStructure)?
                                .expect("join node type has children");
                            let lhs = self.index_for(lhs)?;
                            let rhs = self.index_for(rhs)?;
                            WireEntry::Join { tag: node.tag(), lhs, rhs }
                        },
                        NodeType::True => return Err(IntegrityError::InvalidStructure),
                    };
                    self.push_entry(digest, entry)?;
                },
            }
        }

        Ok(())
    }

    fn index_for(&self, digest: Digest) -> Result<u32, IntegrityError> {
        if digest == TRUE_DIGEST {
            return Ok(TRUE_INDEX);
        }
        self.by_digest.get(&digest).copied().ok_or(IntegrityError::InvalidStructure)
    }

    fn push_entry(&mut self, digest: Digest, entry: WireEntry) -> Result<(), IntegrityError> {
        let next_index =
            self.entries.len().checked_add(1).ok_or(IntegrityError::InvalidStructure)?;
        let next_index = u32::try_from(next_index).map_err(|_| IntegrityError::InvalidStructure)?;
        self.entries.push(entry);
        self.by_digest.insert(digest, next_index);
        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for WireEntry {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Data { tag, chunks } => {
                target.write_u8(0);
                tag.write_into(target);
                target.write_usize(chunks.len());
                for chunk in chunks {
                    for felt in chunk {
                        felt.write_into(target);
                    }
                }
            },
            Self::Join { tag, lhs, rhs } => {
                target.write_u8(1);
                tag.write_into(target);
                target.write_u32(*lhs);
                target.write_u32(*rhs);
            },
        }
    }
}

impl Deserializable for WireEntry {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;
        match discriminant {
            0 => {
                let tag = Tag::read_from(source)?;
                let chunk_count = source.read_usize()?;
                let chunks = source
                    .read_many_iter::<WireDataChunk>(chunk_count)?
                    .map(|chunk| chunk.map(|chunk| chunk.0))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Data { tag, chunks })
            },
            1 => {
                let tag = Tag::read_from(source)?;
                let lhs = source.read_u32()?;
                let rhs = source.read_u32()?;
                Ok(Self::Join { tag, lhs, rhs })
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "invalid deferred wire entry discriminant: {other}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        1
    }
}

struct WireDataChunk(DataChunk);

impl Deserializable for WireDataChunk {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut chunk = [ZERO; Node::DATA_CHUNK_FELT_LEN];
        for felt in &mut chunk {
            *felt = Felt::read_from(source)?;
        }
        Ok(Self(chunk))
    }

    fn min_serialized_size() -> usize {
        Node::DATA_CHUNK_FELT_LEN * Felt::min_serialized_size()
    }
}

impl Serializable for DeferredStateWire {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.entries.len());
        for entry in &self.entries {
            entry.write_into(target);
        }
    }
}

impl Deserializable for DeferredStateWire {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let entry_count = source.read_usize()?;
        let entries = source.read_many_iter::<WireEntry>(entry_count)?.collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{
        Felt,
        serde::{ByteWriter, Serializable},
    };

    fn felts(seed: u64) -> [Felt; 8] {
        core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64))
    }

    fn tag(seed: u64) -> Tag {
        Tag::from_word(felts(seed)[..4].try_into().unwrap())
    }

    fn wire(entries: Vec<WireEntry>) -> DeferredStateWire {
        DeferredStateWire { entries }
    }

    fn assert_wire_round_trips(wire: DeferredStateWire) {
        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);
    }

    /// The proof-transit format must round-trip every entry variant and the empty root opening.
    #[test]
    fn wire_serialize_round_trip_all_entries() {
        assert_wire_round_trips(wire(alloc::vec![
            WireEntry::Data {
                tag: tag(1),
                chunks: alloc::vec![felts(10)]
            },
            WireEntry::Data {
                tag: tag(2),
                chunks: alloc::vec![felts(20), felts(30)],
            },
            WireEntry::Join { tag: tag(3), lhs: 1, rhs: TRUE_INDEX },
        ]));
        assert_wire_round_trips(DeferredStateWire::default());
    }

    fn encoded_entry_count(entry_count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_usize(entry_count);
        bytes
    }

    #[test]
    fn wire_rejects_over_budget_entry_count() {
        assert!(DeferredStateWire::read_from_bytes(&encoded_entry_count(usize::MAX)).is_err());
    }

    #[test]
    fn wire_rejects_over_budget_data_chunk_count() {
        let mut bytes = Vec::new();
        bytes.write_usize(1);
        bytes.write_u8(0); // Data entry discriminant
        tag(1).write_into(&mut bytes);
        bytes.write_usize(usize::MAX);

        assert!(DeferredStateWire::read_from_bytes(&bytes).is_err());
    }
}
