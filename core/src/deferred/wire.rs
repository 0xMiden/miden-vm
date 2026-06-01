//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a topologically ordered stream of materialized DAG entries. Wire index 0 is
//! reserved for the implicit TRUE node; entry `i` has wire index `i + 1`, and join entries may only
//! reference TRUE or earlier entries. Rehydration first decodes this untrusted representation into
//! a temporary arena, then replays the transcript through [`DeferredState`]'s ordinary
//! registration/evaluation/append API before accepting it as trusted state.

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

/// Wire representation of a deferred state.
///
/// The root is implicit: empty `entries` means [`TRUE_DIGEST`], otherwise the root is the digest of
/// the last entry. Accepted wire must be topologically ordered, root-last, duplicate-free,
/// reachable from the transcript root, and semantically valid under the installed
/// [`PrecompileRegistry`]. It does not need to be byte-for-byte identical to [`Self::from_state`]'s
/// deterministic output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeferredStateWire {
    pub entries: Vec<WireEntry>,
}

impl DeferredStateWire {
    /// Serializes the transcript-reachable DAG into deterministic wire form.
    pub(crate) fn from_state(
        state: &DeferredState,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut build = WireBuild::default();
        build.visit_state_digest(state, state.root(), precompiles)?;
        Ok(Self { entries: build.entries })
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    pub(crate) fn rehydrate(
        &self,
        precompiles: &PrecompileRegistry,
        max_elements: usize,
    ) -> Result<DeferredState, IntegrityError> {
        let decoded = DecodedWire::decode(self, precompiles)?;
        let transcript = decoded.validate_transcript_and_closure()?;
        decoded.replay_transcript(&transcript, precompiles, max_elements)
    }

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
}

// DECODED WIRE ARENA
// ================================================================================================

/// Temporary reconstruction arena for untrusted wire data.
///
/// The arena is not a trusted [`DeferredState`]. It only gives rehydration a digest-addressed view
/// of the wire so it can validate transcript reachability and replay ordinary state transitions.
struct DecodedWire {
    entries: Vec<DecodedEntry>,
    /// Parallel to the global wire index space. Index 0 is always [`TRUE_DIGEST`].
    index_to_digest: Vec<Digest>,
    /// Maps a materialized digest to its entry position in `entries`.
    by_digest: BTreeMap<Digest, usize>,
    root: Digest,
}

struct DecodedEntry {
    digest: Digest,
    node: Node,
    node_type: NodeType,
}

struct DecodedTranscript {
    /// Transcript steps in execution order.
    steps: Vec<TranscriptStep>,
    /// All materialized digests consumed by the transcript root and logged statement closures.
    reachable: BTreeSet<Digest>,
}

fn decode_wire_tag_type(
    precompiles: &PrecompileRegistry,
    tag: Tag,
) -> Result<NodeType, IntegrityError> {
    if tag == Tag::TRUE {
        Ok(NodeType::Value)
    } else if tag == Tag::AND {
        Ok(NodeType::Join)
    } else {
        precompiles.decode(tag).map_err(|_| IntegrityError::UnknownTag)
    }
}

fn decode_wire_node_type(
    precompiles: &PrecompileRegistry,
    node: &Node,
) -> Result<NodeType, IntegrityError> {
    let node_type = decode_wire_tag_type(precompiles, node.tag)?;
    if node.tag == Tag::TRUE && !node.is_true_node() {
        return Err(IntegrityError::ShapeMismatch);
    }
    Ok(node_type)
}

struct TranscriptStep {
    /// The transcript root before this statement was logged.
    prev_root: Digest,
    /// The logged statement digest.
    stmt_digest: Digest,
    /// The transcript root after this statement was logged.
    expected_root: Digest,
}

fn budget_integrity_error(err: &PrecompileError) -> Option<IntegrityError> {
    if let PrecompileError::Other(DeferredError::DeferredStateTooLarge { num_elements, max }) =
        err.root()
    {
        Some(IntegrityError::DeferredStateTooLarge { num_elements: *num_elements, max: *max })
    } else {
        None
    }
}

fn map_replay_error(err: PrecompileError) -> IntegrityError {
    budget_integrity_error(&err).unwrap_or(IntegrityError::PredicateFailed(err))
}

fn map_append_error(err: PrecompileError) -> IntegrityError {
    budget_integrity_error(&err).unwrap_or(IntegrityError::BrokenChain)
}

impl DecodedWire {
    fn decode(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let total_nodes =
            1usize.checked_add(wire.entries.len()).ok_or(IntegrityError::ShapeMismatch)?;

        let mut decoded = Self {
            entries: Vec::with_capacity(wire.entries.len()),
            index_to_digest: Vec::with_capacity(total_nodes),
            by_digest: BTreeMap::new(),
            root: TRUE_DIGEST,
        };
        decoded.index_to_digest.push(TRUE_DIGEST);

        for entry in &wire.entries {
            match entry {
                WireEntry::Value { tag, block } => {
                    let node = Node::leaf(*tag, *block);
                    let node_type = decode_wire_node_type(precompiles, &node)?;
                    decoded.push_typed_entry(node, node_type, NodeType::Value)?;
                },
                WireEntry::Chunks { tag, blocks } => {
                    let node_type = decode_wire_tag_type(precompiles, *tag)?;
                    let NodeType::Chunks(n) = node_type else {
                        return Err(IntegrityError::ShapeMismatch);
                    };
                    if blocks.len() != n.get() as usize {
                        return Err(IntegrityError::ShapeMismatch);
                    }
                    decoded.push_entry(Node::chunk(*tag, blocks.clone()), node_type)?;
                },
                WireEntry::Join { tag, lhs, rhs } => {
                    let lhs_d = decoded.resolve_index(*lhs)?;
                    let rhs_d = decoded.resolve_index(*rhs)?;
                    let node = Node::join(*tag, lhs_d, rhs_d);
                    let node_type = decode_wire_node_type(precompiles, &node)?;
                    decoded.push_typed_entry(node, node_type, NodeType::Join)?;
                },
            }
        }

        decoded.root =
            *decoded.index_to_digest.last().expect("digest table is seeded with TRUE_DIGEST");

        // A non-empty transcript must end in a framework-owned AND node. Empty wire is the only
        // accepted representation of the TRUE transcript root.
        if decoded.root != TRUE_DIGEST {
            let root = decoded.entry(&decoded.root).ok_or(IntegrityError::BrokenChain)?;
            if root.node.tag != Tag::AND {
                return Err(IntegrityError::NonAndNode);
            }
        }

        Ok(decoded)
    }

    fn push_entry(&mut self, node: Node, node_type: NodeType) -> Result<(), IntegrityError> {
        if node.is_true_node() {
            return Err(IntegrityError::MaterializedTrue);
        }

        let digest = node.digest();
        if self.contains_digest(&digest) {
            return Err(IntegrityError::DuplicateNode);
        }

        let index = self.index_to_digest.len();
        if index > u32::MAX as usize {
            return Err(IntegrityError::ShapeMismatch);
        }

        let entry_pos = self.entries.len();
        self.entries.push(DecodedEntry { digest, node, node_type });
        self.index_to_digest.push(digest);
        self.by_digest.insert(digest, entry_pos);
        Ok(())
    }

    fn push_typed_entry(
        &mut self,
        node: Node,
        node_type: NodeType,
        expected_type: NodeType,
    ) -> Result<(), IntegrityError> {
        if node.is_true_node() {
            return Err(IntegrityError::MaterializedTrue);
        }
        if node_type != expected_type {
            return Err(IntegrityError::ShapeMismatch);
        }
        self.push_entry(node, node_type)
    }

    fn entry(&self, digest: &Digest) -> Option<&DecodedEntry> {
        self.by_digest.get(digest).map(|idx| &self.entries[*idx])
    }

    fn resolve_index(&self, idx: u32) -> Result<Digest, IntegrityError> {
        self.index_to_digest.get(idx as usize).copied().ok_or(IntegrityError::BadIndex)
    }

    fn contains_digest(&self, digest: &Digest) -> bool {
        *digest == TRUE_DIGEST || self.by_digest.contains_key(digest)
    }

    fn validate_transcript_and_closure(&self) -> Result<DecodedTranscript, IntegrityError> {
        let mut steps = Vec::new();
        let mut consumed = BTreeSet::new();
        let mut chain_nodes = BTreeSet::new();
        let mut cur = self.root;

        while cur != TRUE_DIGEST {
            let entry = self.entry(&cur).ok_or(IntegrityError::BrokenChain)?;
            if entry.node.tag != Tag::AND {
                return Err(IntegrityError::NonAndNode);
            }
            if entry.node_type != NodeType::Join {
                return Err(IntegrityError::BadAndPayload);
            }
            if !chain_nodes.insert(cur) {
                return Err(IntegrityError::BrokenChain);
            }
            consumed.insert(cur);

            let (prev_root, stmt_digest) = entry
                .node_type
                .children(&entry.node.payload)
                .map_err(|_| IntegrityError::BadAndPayload)?
                .ok_or(IntegrityError::BadAndPayload)?;
            if !self.contains_digest(&stmt_digest) {
                return Err(IntegrityError::MissingStatement);
            }
            steps.push(TranscriptStep {
                prev_root,
                stmt_digest,
                expected_root: cur,
            });
            cur = prev_root;
        }

        steps.reverse();

        for step in &steps {
            self.mark_structural_closure(step.stmt_digest, &mut consumed)?;
        }

        if consumed.len() != self.entries.len() {
            return Err(IntegrityError::DanglingNode);
        }

        Ok(DecodedTranscript { steps, reachable: consumed })
    }

    fn mark_structural_closure(
        &self,
        root: Digest,
        consumed: &mut BTreeSet<Digest>,
    ) -> Result<(), IntegrityError> {
        let mut stack = Vec::new();
        let mut visited = BTreeSet::new();
        Self::push_materialized(&mut stack, root);

        while let Some(digest) = stack.pop() {
            if !visited.insert(digest) {
                continue;
            }

            let entry = self.entry(&digest).ok_or(IntegrityError::MissingChild)?;
            consumed.insert(digest);

            if let Some((lhs, rhs)) = entry
                .node_type
                .children(&entry.node.payload)
                .map_err(|_| IntegrityError::ShapeMismatch)?
            {
                Self::push_materialized(&mut stack, lhs);
                Self::push_materialized(&mut stack, rhs);
            }
        }

        Ok(())
    }

    fn replay_transcript(
        &self,
        transcript: &DecodedTranscript,
        precompiles: &PrecompileRegistry,
        max_elements: usize,
    ) -> Result<DeferredState, IntegrityError> {
        let mut state = DeferredState::new(max_elements);

        // Register all reachable entries in original wire order. Since the wire stream is
        // topological, join children are already materialized when a parent is registered.
        for entry in &self.entries {
            if !transcript.reachable.contains(&entry.digest) {
                continue;
            }

            let registered =
                state.register(precompiles, entry.node.clone()).map_err(map_replay_error)?;
            if registered != entry.digest {
                return Err(IntegrityError::DuplicateNode);
            }
        }

        for step in &transcript.steps {
            // The decoded chain already says what the previous root must be. Check before doing
            // expensive evaluation so malformed chains fail at the transcript boundary.
            if state.root() != step.prev_root {
                return Err(IntegrityError::BrokenChain);
            }

            let expected_root = Node::and(state.root(), step.stmt_digest).digest();
            if expected_root != step.expected_root {
                return Err(IntegrityError::BrokenChain);
            }

            let canonical =
                state.evaluate(precompiles, step.stmt_digest).map_err(map_replay_error)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }

            let appended = state
                .append_statement(precompiles, step.stmt_digest)
                .map_err(map_append_error)?;
            if appended != step.expected_root {
                return Err(IntegrityError::BrokenChain);
            }
        }

        if state.root() != self.root {
            return Err(IntegrityError::BrokenChain);
        }

        Ok(state)
    }

    fn push_materialized(stack: &mut Vec<Digest>, digest: Digest) {
        if digest != TRUE_DIGEST {
            stack.push(digest);
        }
    }
}

// WIRE BUILD
// ================================================================================================

/// Builder for the topological wire format used by [`super::DeferredState::to_wire`].
#[derive(Default)]
struct WireBuild {
    seen: BTreeSet<Digest>,
    by_digest: BTreeMap<Digest, u32>,
    entries: Vec<WireEntry>,
}

impl WireBuild {
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

        let node = state.node(&digest).ok_or(IntegrityError::MissingChild)?;
        let node_type = decode_wire_node_type(precompiles, node)?;
        node_type
            .validate_payload(&node.payload)
            .map_err(|_| IntegrityError::ShapeMismatch)?;

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
                    .map_err(|_| IntegrityError::ShapeMismatch)?
                    .ok_or(IntegrityError::ShapeMismatch)?;
                self.visit_state_digest(state, lhs, precompiles)?;
                self.visit_state_digest(state, rhs, precompiles)?;
                let lhs = self.index_for(lhs)?;
                let rhs = self.index_for(rhs)?;
                WireEntry::Join { tag: node.tag, lhs, rhs }
            },
            _ => return Err(IntegrityError::ShapeMismatch),
        };

        self.push_entry(digest, entry)
    }

    fn index_for(&self, digest: Digest) -> Result<u32, IntegrityError> {
        if digest == TRUE_DIGEST {
            return Ok(TRUE_INDEX);
        }
        self.by_digest.get(&digest).copied().ok_or(IntegrityError::MissingChild)
    }

    fn push_entry(&mut self, digest: Digest, entry: WireEntry) -> Result<(), IntegrityError> {
        let next_index = self.entries.len().checked_add(1).ok_or(IntegrityError::ShapeMismatch)?;
        let next_index = u32::try_from(next_index).map_err(|_| IntegrityError::ShapeMismatch)?;
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
            Self::Value { tag, block } => {
                target.write_u8(0);
                DeferredStateWire::write_tag(*tag, target);
                DeferredStateWire::write_block(block, target);
            },
            Self::Chunks { tag, blocks } => {
                target.write_u8(1);
                DeferredStateWire::write_tag(*tag, target);
                target.write_usize(blocks.len());
                for block in blocks {
                    DeferredStateWire::write_block(block, target);
                }
            },
            Self::Join { tag, lhs, rhs } => {
                target.write_u8(2);
                DeferredStateWire::write_tag(*tag, target);
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
                let tag = DeferredStateWire::read_tag(source)?;
                let block = DeferredStateWire::read_block(source)?;
                Ok(Self::Value { tag, block })
            },
            1 => {
                let tag = DeferredStateWire::read_tag(source)?;
                let block_count = source.read_usize()?;
                let blocks = source
                    .read_many_iter::<WireBlock>(block_count)?
                    .map(|block| block.map(|block| block.0))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Chunks { tag, blocks })
            },
            2 => {
                let tag = DeferredStateWire::read_tag(source)?;
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
        DeferredStateWire::read_block(source).map(Self)
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
/// Any variant rejects the proof witness under the installed `PrecompileRegistry`. The enum is not
/// `Clone`/`Eq` because predicate failures carry opaque precompile errors.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// A join child index is outside the currently reconstructed index space.
    #[error("wire join entry references an out-of-range child index")]
    BadIndex,
    /// A non-framework tag is not claimed by the installed registry.
    #[error("wire contains a node with a tag the installed registry does not recognise")]
    UnknownTag,
    /// A reconstructed payload shape or chunk count does not match the tag's declared node type.
    #[error(
        "wire reconstructs a node whose payload shape disagrees with its tag's declared NodeType"
    )]
    ShapeMismatch,
    /// A join node in the committed DAG references a child digest that is not materialized.
    #[error("deferred DAG contains a join node whose child digest is not materialized")]
    MissingChild,
    /// The wire explicitly materializes the framework TRUE node, which is implicit index 0.
    #[error("wire explicitly materializes the implicit TRUE node")]
    MaterializedTrue,
    /// Two wire indices reconstruct to the same node digest.
    #[error("wire assigns multiple indices to the same node digest")]
    DuplicateNode,
    /// The transcript chain references a previous root missing from the reconstructed closure.
    #[error("AND-chain walk encountered a prev_root digest not present in the reconstructed nodes")]
    BrokenChain,
    /// A transcript-chain step is not tagged with the framework AND tag.
    #[error("AND-chain walk encountered a node whose tag is not Tag::AND")]
    NonAndNode,
    /// A transcript-chain step does not carry `(prev_root, statement_digest)`.
    #[error("AND-chain walk encountered a node whose payload is not in join shape")]
    BadAndPayload,
    /// A logged statement digest is absent from the wire closure.
    #[error("AND-chain walk references a statement digest that is not in the node set")]
    MissingStatement,

    /// A logged statement failed while being re-evaluated by its precompile.
    #[error("AND-chain statement failed re-evaluation: {0}")]
    PredicateFailed(#[from] super::PrecompileError),
    /// A logged statement reduced, but not to the canonical TRUE node.
    #[error("AND-chain statement reduced to a non-TRUE canonical form")]
    PredicateNotTrue,
    /// The wire reconstructs data outside the transcript root's reachable closure.
    #[error("wire reconstructs a node not reachable from the transcript root")]
    DanglingNode,
    /// Replaying the wire transcript would exceed the configured deferred-state budget.
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

    /// The proof-transit format must round-trip every entry variant and the empty transcript.
    #[test]
    fn wire_serialize_round_trip_all_entries() {
        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry::Value {
                    tag: Tag::from_word(felts(1)[..4].try_into().unwrap()),
                    block: felts(10),
                },
                WireEntry::Chunks {
                    tag: Tag::from_word(felts(2)[..4].try_into().unwrap()),
                    blocks: alloc::vec![felts(20), felts(30)],
                },
                WireEntry::Join {
                    tag: Tag::from_word(felts(3)[..4].try_into().unwrap()),
                    lhs: 1,
                    rhs: TRUE_INDEX,
                },
            ],
        };
        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);

        let empty = DeferredStateWire::default();
        assert_eq!(DeferredStateWire::read_from_bytes(&empty.to_bytes()).unwrap(), empty);
    }

    #[test]
    fn wire_deserializes_many_minimal_entries() {
        let entries: Vec<WireEntry> = (0..128)
            .map(|i| WireEntry::Value {
                tag: Tag::from_word(felts(i)[..4].try_into().unwrap()),
                block: felts(128 + i),
            })
            .collect();
        let wire = DeferredStateWire { entries };

        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);
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
        DeferredStateWire::write_tag(Tag::from_word(felts(1)[..4].try_into().unwrap()), &mut bytes);
        bytes.write_usize(usize::MAX);

        assert!(DeferredStateWire::read_from_bytes(&bytes).is_err());
    }
}
