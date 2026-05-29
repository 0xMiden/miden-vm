//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a sectioned, topologically ordered DAG witness. Opaque payload data is stored as a
//! flat block buffer, while binary nodes reference earlier reconstructed nodes by index.
//! Rehydration recomputes digests and validates the DAG before any wire data becomes trusted state.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use super::{
    Chunk, DeferredState, Digest, Node, NodeType, Payload, PrecompileRegistry, TRUE_DIGEST, Tag,
};
use crate::{
    Felt, ZERO,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

/// Reserved index for the virtual [`super::TRUE_DIGEST`] transcript terminal.
pub const TRUE_INDEX: u32 = 0;

// WIRE NODE
// ================================================================================================

/// One binary node in the wire DAG.
///
/// The `lhs` and `rhs` fields reference the global wire-node index space, with index 0 reserved
/// for the virtual transcript terminal. During rehydration, binary node `i` may reference
/// [`TRUE_INDEX`], any leaf, any chunk node, or an earlier binary node.
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
/// 0                                                            => virtual TRUE terminal
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeferredStateWire {
    pub leaf_tags: Vec<Tag>,
    pub chunk_tags: Vec<Tag>,
    pub blocks: Vec<Chunk>,
    pub nodes: Vec<WireNode>,
}

impl DeferredStateWire {
    /// Serializes the transcript-reachable DAG into compact wire form.
    pub(super) fn from_state(
        state: &DeferredState,
        precompiles: &PrecompileRegistry,
    ) -> Result<Self, IntegrityError> {
        let mut build = WireBuild::default();
        build.visit_state_digest(state, state.root(), precompiles)?;
        build.into_wire()
    }

    /// Rebuilds and verifies a deferred state from untrusted wire data.
    pub(super) fn rehydrate(
        &self,
        precompiles: &PrecompileRegistry,
    ) -> Result<DeferredState, IntegrityError> {
        let mut state = DeferredState::new();
        // Parallel to the global wire index space: TRUE, then leaves, then chunk nodes, then
        // binary nodes.
        let total_nodes = 1 + self.leaf_tags.len() + self.chunk_tags.len() + self.nodes.len();
        let mut digests: Vec<Digest> = Vec::with_capacity(total_nodes);
        digests.push(TRUE_DIGEST);

        if self.blocks.len() < self.leaf_tags.len() {
            return Err(IntegrityError::ShapeMismatch);
        }

        for (tag, block) in self.leaf_tags.iter().copied().zip(self.blocks.iter().copied()) {
            let node_type = decode_wire_tag(precompiles, tag)?;
            if node_type != NodeType::Value {
                return Err(IntegrityError::ShapeMismatch);
            }
            let node = Node::leaf(tag, block);
            intern_wire_node(&mut state, node, &mut digests)?;
        }

        let mut block_offset = self.leaf_tags.len();
        for tag in self.chunk_tags.iter().copied() {
            let node_type = decode_wire_tag(precompiles, tag)?;
            let NodeType::Chunks(n) = node_type else {
                return Err(IntegrityError::ShapeMismatch);
            };
            let len = n.get() as usize;
            let end = block_offset.checked_add(len).ok_or(IntegrityError::ShapeMismatch)?;
            if end > self.blocks.len() {
                return Err(IntegrityError::ShapeMismatch);
            }
            let chunks = Arc::from(&self.blocks[block_offset..end]);
            let node = Node::chunk(tag, chunks);
            intern_wire_node(&mut state, node, &mut digests)?;
            block_offset = end;
        }
        if block_offset != self.blocks.len() {
            return Err(IntegrityError::ShapeMismatch);
        }

        for wire_node in &self.nodes {
            let resolve_index =
                |idx: u32| digests.get(idx as usize).copied().ok_or(IntegrityError::BadIndex);
            let lhs_d = resolve_index(wire_node.lhs)?;
            let rhs_d = resolve_index(wire_node.rhs)?;
            let node_type = decode_wire_tag(precompiles, wire_node.tag)?;
            if node_type != NodeType::Join {
                return Err(IntegrityError::ShapeMismatch);
            }
            let node = Node::join(wire_node.tag, lhs_d, rhs_d);
            intern_wire_node(&mut state, node, &mut digests)?;
        }

        // Derive the deferred commitment from phase 1's last reconstructed node. Empty sections →
        // the `TRUE_DIGEST` seeded at index 0.
        state.set_root(*digests.last().expect("digest table is seeded with TRUE_DIGEST"));

        // Reachability — every reconstructed node must lie in the registry-declared closure of
        // `root`. `to_wire` emits exactly that closure, so a faithful wire passes; any node outside
        // it is bloat or hidden data and is rejected. Done here, before phase 2's evaluate re-mints
        // canonical intermediates into `state.nodes`.
        if reachable_closure(state.nodes(), state.root(), precompiles)?.len() != state.nodes().len()
        {
            return Err(IntegrityError::DanglingNode);
        }

        // Phase 2 — chain walk + per-statement re-evaluation. AND-nodes share Tag::TRUE and a
        // `(prev_root, stmt_digest)` payload; statements must reduce to `Node::TRUE` under the
        // precompiles.
        let mut cur = state.root();
        while cur != TRUE_DIGEST {
            let and_node = state.nodes().get(&cur).ok_or(IntegrityError::BrokenChain)?;
            if and_node.tag != Tag::TRUE {
                return Err(IntegrityError::NonAndNode);
            }
            let (prev_root, stmt_digest) =
                and_node.payload.join_children().map_err(|_| IntegrityError::BadAndPayload)?;
            let stmt =
                state.nodes().get(&stmt_digest).ok_or(IntegrityError::MissingStatement)?.clone();
            let canonical = state.evaluate_node(precompiles, stmt)?;
            if !canonical.is_true_node() {
                return Err(IntegrityError::PredicateNotTrue);
            }
            cur = prev_root;
        }

        Ok(state)
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
        let first_visit = digest != TRUE_DIGEST && self.seen.insert(digest);
        if !first_visit {
            return Ok(());
        }
        let node = state.nodes().get(&digest).ok_or(IntegrityError::MissingChild)?;
        let node_type = decode_wire_tag(precompiles, node.tag)?;
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
            next_index += 1;
        }
        for chunk in &self.chunks {
            by_digest.insert(chunk.digest, next_index);
            next_index += 1;
        }
        for node in &self.pending_nodes {
            by_digest.insert(node.digest, next_index);
            next_index += 1;
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

fn intern_wire_node(
    state: &mut DeferredState,
    node: Node,
    digests: &mut Vec<Digest>,
) -> Result<(), IntegrityError> {
    let digest = node.digest();
    if state.contains(&digest) {
        return Err(IntegrityError::DuplicateNode);
    }
    state.intern(node);
    digests.push(digest);
    Ok(())
}

fn decode_wire_tag(precompiles: &PrecompileRegistry, tag: Tag) -> Result<NodeType, IntegrityError> {
    if tag == Tag::TRUE {
        return Ok(NodeType::Join);
    }
    precompiles.decode(tag).map_err(|_| IntegrityError::UnknownTag)
}

/// Returns the registry-declared closure reachable from a transcript root.
///
/// Only tags decoded as [`NodeType::Join`] contribute graph edges. Opaque value and chunk payloads
/// are never inspected for digest-looking field elements.
fn reachable_closure(
    nodes: &BTreeMap<Digest, Node>,
    root: Digest,
    precompiles: &PrecompileRegistry,
) -> Result<BTreeSet<Digest>, IntegrityError> {
    let mut seen = BTreeSet::new();
    let mut stack = Vec::new();
    let push_materialized = |stack: &mut Vec<Digest>, digest| {
        if digest != TRUE_DIGEST {
            stack.push(digest);
        }
    };
    push_materialized(&mut stack, root);

    while let Some(d) = stack.pop() {
        if !seen.insert(d) {
            continue;
        }
        let node = nodes.get(&d).ok_or(IntegrityError::MissingChild)?;
        if decode_wire_tag(precompiles, node.tag)? == NodeType::Join {
            let (lhs, rhs) =
                node.payload.join_children().map_err(|_| IntegrityError::ShapeMismatch)?;
            push_materialized(&mut stack, lhs);
            push_materialized(&mut stack, rhs);
        }
    }
    Ok(seen)
}

// SERIALIZATION
// ================================================================================================

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

impl Serializable for WireNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_tag(self.tag, target);
        target.write_u32(self.lhs);
        target.write_u32(self.rhs);
    }
}

impl Deserializable for WireNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = read_tag(source)?;
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
            write_tag(*tag, target);
        }
        for tag in &self.chunk_tags {
            write_tag(*tag, target);
        }
        for block in &self.blocks {
            write_block(block, target);
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
            leaf_tags.push(read_tag(source)?);
        }

        let mut chunk_tags = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunk_tags.push(read_tag(source)?);
        }

        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push(read_block(source)?);
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
    /// A transcript-chain step is not tagged with the framework TRUE tag.
    #[error("AND-chain walk encountered a node whose tag is not Tag::TRUE")]
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
