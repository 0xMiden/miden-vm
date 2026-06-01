//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a canonical, topologically ordered stream of the materialized DAG entries needed to
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
    vec::Vec,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    Chunk, DeferredError, DeferredState, Digest, Node, NodeType, Payload, PrecompileError,
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

/// One materialized deferred DAG entry in topological wire order.
///
/// Wire index 0 is implicit TRUE. `entries[i]` has wire index `i + 1`. Join children must reference
/// `TRUE_INDEX` or an earlier entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WireEntry {
    /// One expression block interpreted as precompile value data.
    Value { tag: Tag, block: Chunk },
    /// Fixed-count chunk payload interpreted by the tag's precompile.
    Chunks { tag: Tag, blocks: Vec<Chunk> },
    /// One expression block interpreted as two child references.
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
    pub(crate) fn from_state(
        state: &DeferredState,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut build = WireEncoder::default();
        build.visit_state_digest(state, state.root(), precompiles)?;
        Ok(Self { entries: build.entries })
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    pub(crate) fn rehydrate(
        &self,
        precompiles: &PrecompileRegistry,
        max_elements: usize,
    ) -> Result<DeferredState, IntegrityError> {
        let (entries, root) = decode_wire_entries(self, precompiles)?;
        rebuild_state_from_wire(self, entries, root, precompiles, max_elements)
    }
}

// WIRE REHYDRATION
// ================================================================================================

fn decode_wire_tag_type(
    precompiles: &PrecompileRegistry,
    tag: Tag,
) -> Result<NodeType, IntegrityError> {
    if tag == Tag::TRUE {
        Ok(NodeType::Value)
    } else if tag == Tag::AND {
        Ok(NodeType::Join)
    } else {
        precompiles.decode(tag).map_err(|_| IntegrityError::InvalidStructure)
    }
}

fn decode_wire_node_type(
    precompiles: &PrecompileRegistry,
    node: &Node,
) -> Result<NodeType, IntegrityError> {
    let node_type = decode_wire_tag_type(precompiles, node.tag)?;
    if node.tag == Tag::TRUE && !node.is_true_node() {
        return Err(IntegrityError::InvalidStructure);
    }
    Ok(node_type)
}

fn map_rehydrate_error(err: PrecompileError) -> IntegrityError {
    if let PrecompileError::Other(DeferredError::DeferredStateTooLarge { num_elements, max }) =
        err.root()
    {
        IntegrityError::DeferredStateTooLarge { num_elements: *num_elements, max: *max }
    } else {
        IntegrityError::EvaluationFailed(err)
    }
}

fn decode_wire_entries(
    wire: &DeferredStateWire,
    precompiles: &PrecompileRegistry,
) -> Result<(Vec<(Digest, Node)>, Digest), IntegrityError> {
    let total_nodes =
        1usize.checked_add(wire.entries.len()).ok_or(IntegrityError::InvalidStructure)?;

    let mut entries = Vec::with_capacity(wire.entries.len());
    let mut index_to_digest = Vec::with_capacity(total_nodes);
    let mut seen_digests = BTreeSet::new();
    index_to_digest.push(TRUE_DIGEST);
    seen_digests.insert(TRUE_DIGEST);

    for entry in &wire.entries {
        let node = decode_wire_entry(entry, &index_to_digest, precompiles)?;
        push_decoded_entry(&mut entries, &mut index_to_digest, &mut seen_digests, node)?;
    }

    let root = *index_to_digest.last().expect("digest table is seeded with TRUE_DIGEST");
    Ok((entries, root))
}

fn decode_wire_entry(
    entry: &WireEntry,
    index_to_digest: &[Digest],
    precompiles: &PrecompileRegistry,
) -> Result<Node, IntegrityError> {
    match entry {
        WireEntry::Value { tag, block } => {
            let node = Node::leaf(*tag, *block);
            let node_type = decode_wire_node_type(precompiles, &node)?;
            expect_wire_type(&node, node_type, NodeType::Value)?;
            Ok(node)
        },
        WireEntry::Chunks { tag, blocks } => {
            let node_type = decode_wire_tag_type(precompiles, *tag)?;
            let NodeType::Chunks(n) = node_type else {
                return Err(IntegrityError::InvalidStructure);
            };
            if blocks.len() != n.get() as usize {
                return Err(IntegrityError::InvalidStructure);
            }
            Ok(Node::chunk(*tag, blocks.clone()))
        },
        WireEntry::Join { tag, lhs, rhs } => {
            let lhs = resolve_wire_index(index_to_digest, *lhs)?;
            let rhs = resolve_wire_index(index_to_digest, *rhs)?;
            let node = Node::join(*tag, lhs, rhs);
            let node_type = decode_wire_node_type(precompiles, &node)?;
            expect_wire_type(&node, node_type, NodeType::Join)?;
            Ok(node)
        },
    }
}

fn expect_wire_type(
    node: &Node,
    actual: NodeType,
    expected: NodeType,
) -> Result<(), IntegrityError> {
    if node.is_true_node() {
        return Err(IntegrityError::InvalidStructure);
    }
    if actual != expected {
        return Err(IntegrityError::InvalidStructure);
    }
    Ok(())
}

fn resolve_wire_index(index_to_digest: &[Digest], idx: u32) -> Result<Digest, IntegrityError> {
    index_to_digest
        .get(idx as usize)
        .copied()
        .ok_or(IntegrityError::InvalidStructure)
}

fn push_decoded_entry(
    entries: &mut Vec<(Digest, Node)>,
    index_to_digest: &mut Vec<Digest>,
    seen_digests: &mut BTreeSet<Digest>,
    node: Node,
) -> Result<(), IntegrityError> {
    if node.is_true_node() {
        return Err(IntegrityError::InvalidStructure);
    }

    let digest = node.digest();
    if !seen_digests.insert(digest) {
        return Err(IntegrityError::InvalidStructure);
    }

    let index = index_to_digest.len();
    if index > u32::MAX as usize {
        return Err(IntegrityError::InvalidStructure);
    }

    entries.push((digest, node));
    index_to_digest.push(digest);
    Ok(())
}

fn rebuild_state_from_wire(
    wire: &DeferredStateWire,
    entries: Vec<(Digest, Node)>,
    root: Digest,
    precompiles: &PrecompileRegistry,
    max_elements: usize,
) -> Result<DeferredState, IntegrityError> {
    let mut state = DeferredState::new(max_elements);

    // Register entries in strict topological wire order. Join children have already been decoded to
    // earlier digests, so ordinary DeferredState registration enforces the same child-closure and
    // budget rules as execution.
    for (digest, node) in entries {
        let registered = state.register(precompiles, node).map_err(map_rehydrate_error)?;
        if registered != digest {
            return Err(IntegrityError::InvalidStructure);
        }
    }

    state.root = root;

    // `to_wire` emits the deterministic root-reachable closure. Equality makes the accepted format
    // strict: root-last, canonical DFS order, and no dangling or duplicate entries.
    if state.to_wire(precompiles)? != *wire {
        return Err(IntegrityError::InvalidStructure);
    }

    let canonical = state.evaluate(precompiles, root).map_err(map_rehydrate_error)?;
    if !canonical.is_true_node() {
        return Err(IntegrityError::RootNotTrue);
    }

    Ok(state)
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
        precompiles: &PrecompileRegistry,
    ) -> Result<(), IntegrityError> {
        if digest == TRUE_DIGEST {
            return Ok(());
        }
        if !self.seen.insert(digest) {
            return Ok(());
        }

        let node = state.node(&digest).ok_or(IntegrityError::InvalidStructure)?;
        let node_type = decode_wire_node_type(precompiles, node)?;
        node_type
            .validate_payload(&node.payload)
            .map_err(|_| IntegrityError::InvalidStructure)?;

        let entry = match (node_type, &node.payload) {
            (NodeType::Value, Payload::Expression(felts)) => {
                WireEntry::Value { tag: node.tag, block: *felts }
            },
            (NodeType::Chunks(_), Payload::Chunk(chunks)) => WireEntry::Chunks {
                tag: node.tag,
                blocks: chunks.iter().copied().collect(),
            },
            (NodeType::Join, Payload::Expression(_)) => {
                let (lhs, rhs) = node_type
                    .children(&node.payload)
                    .map_err(|_| IntegrityError::InvalidStructure)?
                    .ok_or(IntegrityError::InvalidStructure)?;
                self.visit_state_digest(state, lhs, precompiles)?;
                self.visit_state_digest(state, rhs, precompiles)?;
                let lhs = self.index_for(lhs)?;
                let rhs = self.index_for(rhs)?;
                WireEntry::Join { tag: node.tag, lhs, rhs }
            },
            _ => return Err(IntegrityError::InvalidStructure),
        };

        self.push_entry(digest, entry)
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

fn write_tag<W: ByteWriter>(tag: Tag, target: &mut W) {
    // Wire layout is the 4-felt capacity `[id, arg0, arg1, arg2]`.
    tag.write_into(target);
}

fn read_tag<R: ByteReader>(source: &mut R) -> Result<Tag, DeserializationError> {
    Tag::read_from(source)
}

fn write_block<W: ByteWriter>(block: &Chunk, target: &mut W) {
    for felt in block {
        felt.write_into(target);
    }
}

fn read_block<R: ByteReader>(source: &mut R) -> Result<Chunk, DeserializationError> {
    let mut block = [ZERO; 8];
    for felt in &mut block {
        *felt = Felt::read_from(source)?;
    }
    Ok(block)
}

impl Serializable for WireEntry {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Value { tag, block } => {
                target.write_u8(0);
                write_tag(*tag, target);
                write_block(block, target);
            },
            Self::Chunks { tag, blocks } => {
                target.write_u8(1);
                write_tag(*tag, target);
                target.write_usize(blocks.len());
                for block in blocks {
                    write_block(block, target);
                }
            },
            Self::Join { tag, lhs, rhs } => {
                target.write_u8(2);
                write_tag(*tag, target);
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
                let tag = read_tag(source)?;
                let block = read_block(source)?;
                Ok(Self::Value { tag, block })
            },
            1 => {
                let tag = read_tag(source)?;
                let block_count = source.read_usize()?;
                let blocks = source
                    .read_many_iter::<WireBlock>(block_count)?
                    .map(|block| block.map(|block| block.0))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Chunks { tag, blocks })
            },
            2 => {
                let tag = read_tag(source)?;
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

struct WireBlock(Chunk);

impl Deserializable for WireBlock {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_block(source).map(Self)
    }

    fn min_serialized_size() -> usize {
        8 * Felt::min_serialized_size()
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
    EvaluationFailed(#[from] super::PrecompileError),
    /// The root reduced, but not to the canonical TRUE node.
    #[error("deferred root reduced to a non-TRUE canonical form")]
    RootNotTrue,
    /// Rehydrating the wire would exceed the configured deferred-state budget.
    #[error("deferred insertion requires {num_elements} elements but only {max} remain")]
    DeferredStateTooLarge { num_elements: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::{Felt, serde::ByteWriter};

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
            WireEntry::Value { tag: tag(1), block: felts(10) },
            WireEntry::Chunks {
                tag: tag(2),
                blocks: alloc::vec![felts(20), felts(30)],
            },
            WireEntry::Join { tag: tag(3), lhs: 1, rhs: TRUE_INDEX },
        ]));
        assert_wire_round_trips(DeferredStateWire::default());
    }

    #[test]
    fn wire_deserializes_many_minimal_entries() {
        let entries: Vec<WireEntry> = (0..128)
            .map(|i| WireEntry::Value { tag: tag(i), block: felts(128 + i) })
            .collect();
        assert_wire_round_trips(wire(entries));
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
    fn wire_rejects_over_budget_chunk_block_count() {
        let mut bytes = Vec::new();
        bytes.write_usize(1);
        bytes.write_u8(1);
        write_tag(tag(1), &mut bytes);
        bytes.write_usize(usize::MAX);

        assert!(DeferredStateWire::read_from_bytes(&bytes).is_err());
    }
}
