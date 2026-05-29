//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a sectioned, topologically ordered DAG witness. Opaque payload data is stored as a
//! flat block buffer, while binary nodes reference earlier reconstructed nodes by index.
//! Rehydration first decodes this untrusted representation into a temporary arena, then replays the
//! transcript through [`DeferredState`]'s ordinary registration/evaluation/logging API before
//! accepting it as trusted state.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::iter::zip;

use super::{
    Chunk, DeferredState, Digest, Node, NodeType, Payload, PrecompileRegistry, TRUE_DIGEST, Tag,
};
use crate::{
    Felt, ZERO,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

/// Reserved index for the always-known [`super::TRUE_DIGEST`] / [`super::Node::TRUE`] node.
pub const TRUE_INDEX: u32 = 0;

// WIRE NODE
// ================================================================================================

/// One binary node in the wire DAG.
///
/// The `lhs` and `rhs` fields reference the global wire-node index space, with index 0 reserved
/// for the implicit TRUE node. During rehydration, binary node `i` may reference [`TRUE_INDEX`],
/// any leaf, any chunk node, or an earlier binary node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireNode {
    pub tag: Tag,
    pub lhs: u32,
    pub rhs: u32,
}

// DEFERRED STATE WIRE
// ================================================================================================

/// Wire representation of a deferred state.
///
/// The global node index space is sectioned as follows:
///
/// ```text
/// 0                                                            => implicit TRUE node
/// 1 .. 1 + leaf_tags.len()                                     => single-block leaves
/// 1 + leaf_tags.len() .. 1 + leaf_tags.len() + chunk_tags.len() => chunk nodes
/// remaining indices                                           => binary nodes
/// ```
///
/// `blocks` stores all opaque payload blocks in one flat buffer. The first `leaf_tags.len()` blocks
/// are the single-block leaf payloads. The remaining blocks are chunk payloads, partitioned during
/// rehydration using lengths decoded from `chunk_tags` by the installed `PrecompileRegistry`.
///
/// The transcript commitment is derived from the last reconstructed node, so the wire does not
/// carry a separate root field. Empty sections represent the empty transcript.
///
/// Accepted wire is strict and canonical: every materialized entry must reconstruct to a unique
/// digest, all entries must be reachable from the transcript root under registry/framework join
/// semantics, and reserializing the rehydrated state must produce the same wire structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeferredStateWire {
    pub leaf_tags: Vec<Tag>,
    pub chunk_tags: Vec<Tag>,
    pub blocks: Vec<Chunk>,
    pub nodes: Vec<WireNode>,
}

impl DeferredStateWire {
    /// Serializes the transcript-reachable DAG into compact canonical wire form.
    pub fn from_state(
        state: &DeferredState,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut build = WireBuild::default();
        build.visit_state_digest(state, state.root(), precompiles)?;
        build.into_wire()
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    pub fn rehydrate(
        &self,
        precompiles: &PrecompileRegistry,
    ) -> Result<DeferredState, IntegrityError> {
        let decoded = DecodedWire::decode(self, precompiles)?;
        let transcript = decoded.validate_transcript_and_closure()?;
        let state = decoded.replay_transcript(&transcript, precompiles)?;

        // Canonicality/uniqueness: any accepted wire must be exactly what the canonical serializer
        // emits for the replayed state. This rejects equivalent-but-reordered index assignments.
        let canonical = Self::from_state(&state, precompiles)?;
        if &canonical != self {
            return Err(IntegrityError::NonCanonicalWire);
        }

        Ok(state)
    }

    fn write_tag<W: ByteWriter>(tag: Tag, target: &mut W) {
        // Wire layout is the 4-felt capacity `[id, arg0, arg1, arg2]`.
        for felt in &tag.as_word() {
            felt.write_into(target);
        }
    }

    fn read_tag<R: ByteReader>(source: &mut R) -> Result<Tag, DeserializationError> {
        Ok(Tag::from_word([
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ]))
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
    node: Node,
    node_type: NodeType,
}

struct DecodedTranscript {
    /// Transcript steps in execution order.
    steps: Vec<TranscriptStep>,
}

struct TranscriptStep {
    /// The transcript root before this statement was logged.
    prev_root: Digest,
    /// The logged statement digest.
    stmt_digest: Digest,
    /// The transcript root after this statement was logged.
    expected_root: Digest,
}

impl DecodedWire {
    fn decode(
        wire: &DeferredStateWire,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let total_nodes = 1usize
            .checked_add(wire.leaf_tags.len())
            .and_then(|n| n.checked_add(wire.chunk_tags.len()))
            .and_then(|n| n.checked_add(wire.nodes.len()))
            .ok_or(IntegrityError::ShapeMismatch)?;

        let mut decoded = Self {
            entries: Vec::with_capacity(total_nodes.saturating_sub(1)),
            index_to_digest: Vec::with_capacity(total_nodes),
            by_digest: BTreeMap::new(),
            root: TRUE_DIGEST,
        };
        decoded.index_to_digest.push(TRUE_DIGEST);

        if wire.blocks.len() < wire.leaf_tags.len() {
            return Err(IntegrityError::ShapeMismatch);
        }

        for (tag, block) in zip(&wire.leaf_tags, &wire.blocks) {
            let node = Node::leaf(*tag, *block);
            let node_type = precompiles.decode_wire_node_type(&node)?;
            decoded.push_typed_entry(node, node_type, NodeType::Value)?;
        }

        let mut block_offset = wire.leaf_tags.len();
        for tag in &wire.chunk_tags {
            let node_type = precompiles.decode_wire_tag_type(*tag)?;
            let NodeType::Chunks(n) = node_type else {
                return Err(IntegrityError::ShapeMismatch);
            };
            let len = n.get() as usize;
            let end = block_offset.checked_add(len).ok_or(IntegrityError::ShapeMismatch)?;
            if end > wire.blocks.len() {
                return Err(IntegrityError::ShapeMismatch);
            }
            let chunks = Arc::from(&wire.blocks[block_offset..end]);
            decoded.push_entry(Node::chunk(*tag, chunks), node_type)?;
            block_offset = end;
        }
        if block_offset != wire.blocks.len() {
            return Err(IntegrityError::ShapeMismatch);
        }

        for wire_node in &wire.nodes {
            let lhs_d = decoded.resolve_index(wire_node.lhs)?;
            let rhs_d = decoded.resolve_index(wire_node.rhs)?;
            let node = Node::join(wire_node.tag, lhs_d, rhs_d);
            let node_type = precompiles.decode_wire_node_type(&node)?;
            decoded.push_typed_entry(node, node_type, NodeType::Join)?;
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
        let digest = node.digest();
        if self.contains_digest(&digest) {
            return Err(IntegrityError::DuplicateNode);
        }

        let index = self.index_to_digest.len();
        if index > u32::MAX as usize {
            return Err(IntegrityError::ShapeMismatch);
        }

        let entry_pos = self.entries.len();
        self.entries.push(DecodedEntry { node, node_type });
        self.index_to_digest.push(digest);
        self.by_digest.insert(digest, entry_pos);
        Ok(())
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

            let (prev_root, stmt_digest) =
                entry.node.payload.join_children().map_err(|_| IntegrityError::BadAndPayload)?;
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

        Ok(DecodedTranscript { steps })
    }

    fn push_typed_entry(
        &mut self,
        node: Node,
        node_type: NodeType,
        expected_type: NodeType,
    ) -> Result<(), IntegrityError> {
        // TRUE is implicit at wire index 0. If untrusted wire tries to materialize exact TRUE in
        // any section, route through `push_entry` so it is rejected uniformly as a duplicate.
        if node.is_true_node() {
            return self.push_entry(node, node_type);
        }
        if node_type != expected_type {
            return Err(IntegrityError::ShapeMismatch);
        }
        self.push_entry(node, node_type)
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

            if entry.node_type == NodeType::Join {
                let (lhs, rhs) = entry
                    .node
                    .payload
                    .join_children()
                    .map_err(|_| IntegrityError::ShapeMismatch)?;
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
    ) -> Result<DeferredState, IntegrityError> {
        let mut state = DeferredState::new();

        for step in &transcript.steps {
            // The decoded chain already says what the previous root must be. Check before doing
            // expensive evaluation so malformed chains fail at the transcript boundary.
            if state.root() != step.prev_root {
                return Err(IntegrityError::BrokenChain);
            }

            self.register_statement_closure(&mut state, step.stmt_digest, precompiles)?;
            let canonical = state.evaluate_statement_digest(precompiles, step.stmt_digest)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }
            state
                .log(step.stmt_digest, step.expected_root)
                .map_err(|_| IntegrityError::BrokenChain)?;
        }

        if state.root() != self.root {
            return Err(IntegrityError::BrokenChain);
        }

        Ok(state)
    }

    fn register_statement_closure(
        &self,
        state: &mut DeferredState,
        root: Digest,
        precompiles: &PrecompileRegistry,
    ) -> Result<(), IntegrityError> {
        let mut stack = Vec::new();
        let mut seen = BTreeSet::new();
        Self::push_materialized(&mut stack, root);

        while let Some(digest) = stack.pop() {
            if !seen.insert(digest) {
                continue;
            }

            let entry = self.entry(&digest).ok_or(IntegrityError::MissingChild)?;

            match state.nodes().get(&digest) {
                Some(existing) if existing == &entry.node => {},
                Some(_) => return Err(IntegrityError::DuplicateNode),
                None => {
                    let registered = state
                        .register(precompiles, entry.node.clone())
                        .map_err(IntegrityError::PredicateFailed)?;
                    if registered != digest {
                        return Err(IntegrityError::DuplicateNode);
                    }
                },
            }

            if entry.node_type == NodeType::Join {
                let (lhs, rhs) = entry
                    .node
                    .payload
                    .join_children()
                    .map_err(|_| IntegrityError::ShapeMismatch)?;
                Self::push_materialized(&mut stack, lhs);
                Self::push_materialized(&mut stack, rhs);
            }
        }

        Ok(())
    }

    fn push_materialized(stack: &mut Vec<Digest>, digest: Digest) {
        if digest != TRUE_DIGEST {
            stack.push(digest);
        }
    }
}

// WIRE BUILD
// ================================================================================================

/// Builder for the sectioned wire format used by [`super::DeferredState::to_wire`].
#[derive(Default)]
struct WireBuild {
    seen: BTreeSet<Digest>,
    leaves: Vec<PendingWireLeaf>,
    chunks: Vec<PendingWireChunk>,
    pending_nodes: Vec<PendingWireNode>,
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
        let node = state.nodes().get(&digest).ok_or(IntegrityError::MissingChild)?;
        let node_type = precompiles.decode_wire_node_type(node)?;
        if !node_type.matches_payload(&node.payload) {
            return Err(IntegrityError::ShapeMismatch);
        }

        match (node_type, &node.payload) {
            (NodeType::Value, Payload::Expression(felts)) => {
                self.push_leaf(digest, node.tag, *felts)
            },
            (NodeType::Chunks(_), Payload::Chunk(chunks)) => {
                self.push_chunk(digest, node.tag, chunks)
            },
            (NodeType::Join, Payload::Expression(_)) => {
                let (lhs, rhs) =
                    node.payload.join_children().map_err(|_| IntegrityError::ShapeMismatch)?;
                self.visit_state_digest(state, lhs, precompiles)?;
                self.visit_state_digest(state, rhs, precompiles)?;
                self.push_node(digest, node.tag, lhs, rhs);
            },
            _ => return Err(IntegrityError::ShapeMismatch),
        }
        Ok(())
    }

    fn push_leaf(&mut self, digest: Digest, tag: Tag, block: Chunk) {
        self.leaves.push(PendingWireLeaf { digest, tag, block });
    }

    fn push_chunk(&mut self, digest: Digest, tag: Tag, chunks: &Arc<[Chunk]>) {
        self.chunks.push(PendingWireChunk { digest, tag, chunks: chunks.clone() });
    }

    fn push_node(&mut self, digest: Digest, tag: Tag, lhs: Digest, rhs: Digest) {
        self.pending_nodes.push(PendingWireNode { digest, tag, lhs, rhs });
    }

    fn into_wire(self) -> Result<DeferredStateWire, IntegrityError> {
        let mut by_digest = BTreeMap::<Digest, u32>::new();
        by_digest.insert(TRUE_DIGEST, TRUE_INDEX);

        let mut next_index = 1u32;
        for leaf in &self.leaves {
            by_digest.insert(leaf.digest, next_index);
            next_index = next_index.checked_add(1).ok_or(IntegrityError::ShapeMismatch)?;
        }
        for chunk in &self.chunks {
            by_digest.insert(chunk.digest, next_index);
            next_index = next_index.checked_add(1).ok_or(IntegrityError::ShapeMismatch)?;
        }
        for node in &self.pending_nodes {
            by_digest.insert(node.digest, next_index);
            next_index = next_index.checked_add(1).ok_or(IntegrityError::ShapeMismatch)?;
        }

        let mut leaf_tags = Vec::with_capacity(self.leaves.len());
        let mut chunk_tags = Vec::with_capacity(self.chunks.len());
        let mut blocks = Vec::new();

        for leaf in &self.leaves {
            leaf_tags.push(leaf.tag);
            blocks.push(leaf.block);
        }
        for chunk in &self.chunks {
            chunk_tags.push(chunk.tag);
            blocks.extend(chunk.chunks.iter().copied());
        }

        let digest_to_index =
            |digest: Digest| by_digest.get(&digest).copied().ok_or(IntegrityError::MissingChild);

        let nodes = self
            .pending_nodes
            .into_iter()
            .map(|node| {
                let lhs = digest_to_index(node.lhs)?;
                let rhs = digest_to_index(node.rhs)?;
                Ok(WireNode { tag: node.tag, lhs, rhs })
            })
            .collect::<Result<Vec<_>, IntegrityError>>()?;

        Ok(DeferredStateWire { leaf_tags, chunk_tags, blocks, nodes })
    }
}

struct PendingWireLeaf {
    digest: Digest,
    tag: Tag,
    block: Chunk,
}

struct PendingWireChunk {
    digest: Digest,
    tag: Tag,
    chunks: Arc<[Chunk]>,
}

struct PendingWireNode {
    digest: Digest,
    tag: Tag,
    lhs: Digest,
    rhs: Digest,
}

// SERIALIZATION
// ================================================================================================

impl Serializable for WireNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        DeferredStateWire::write_tag(self.tag, target);
        target.write_u32(self.lhs);
        target.write_u32(self.rhs);
    }
}

impl Deserializable for WireNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = DeferredStateWire::read_tag(source)?;
        let lhs = source.read_u32()?;
        let rhs = source.read_u32()?;
        Ok(Self { tag, lhs, rhs })
    }
}

impl Serializable for DeferredStateWire {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.leaf_tags.len());
        target.write_usize(self.chunk_tags.len());
        target.write_usize(self.blocks.len());
        target.write_usize(self.nodes.len());

        for tag in &self.leaf_tags {
            Self::write_tag(*tag, target);
        }
        for tag in &self.chunk_tags {
            Self::write_tag(*tag, target);
        }
        for block in &self.blocks {
            Self::write_block(block, target);
        }
        for node in &self.nodes {
            node.write_into(target);
        }
    }
}

impl Deserializable for DeferredStateWire {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let leaf_count = source.read_usize()?;
        let chunk_count = source.read_usize()?;
        let block_count = source.read_usize()?;
        let node_count = source.read_usize()?;

        let mut leaf_tags = Vec::with_capacity(leaf_count);
        for _ in 0..leaf_count {
            leaf_tags.push(Self::read_tag(source)?);
        }

        let mut chunk_tags = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunk_tags.push(Self::read_tag(source)?);
        }

        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(Self::read_block(source)?);
        }

        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            nodes.push(WireNode::read_from(source)?);
        }

        Ok(Self { leaf_tags, chunk_tags, blocks, nodes })
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
    /// A binary child index is outside the currently reconstructed index space.
    #[error("wire binary node references an out-of-range child index")]
    BadIndex,
    /// A non-framework tag is not claimed by the installed registry.
    #[error("wire contains a node with a tag the installed registry does not recognise")]
    UnknownTag,
    /// A reconstructed payload shape or chunk count does not match the tag's declared node type.
    #[error(
        "wire reconstructs a node whose payload shape disagrees with its tag's declared NodeType"
    )]
    ShapeMismatch,
    /// A binary node in the committed DAG references a child digest that is not materialized.
    #[error("deferred DAG contains a binary node whose child digest is not materialized")]
    MissingChild,
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
    /// The wire is semantically valid but not the canonical serialization of the replayed state.
    #[error("wire is not the canonical serialization of the replayed deferred state")]
    NonCanonicalWire,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Felt;

    fn felts(seed: u64) -> [Felt; 8] {
        core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64))
    }

    /// The proof-transit format must round-trip every section and the empty transcript.
    #[test]
    fn wire_serialize_round_trip_all_sections() {
        let wire = DeferredStateWire {
            leaf_tags: alloc::vec![Tag::from_word(felts(1)[..4].try_into().unwrap())],
            chunk_tags: alloc::vec![Tag::from_word(felts(2)[..4].try_into().unwrap())],
            blocks: alloc::vec![felts(10), felts(20), felts(30)],
            nodes: alloc::vec![WireNode {
                tag: Tag::from_word(felts(3)[..4].try_into().unwrap()),
                lhs: 1,
                rhs: TRUE_INDEX,
            }],
        };
        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);

        let empty = DeferredStateWire::default();
        assert_eq!(DeferredStateWire::read_from_bytes(&empty.to_bytes()).unwrap(), empty);
    }
}
