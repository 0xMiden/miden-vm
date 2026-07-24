//! Compact wire format for deferred-state witnesses.
//!
//! Partial proofs carry a canonical, topologically ordered stream of the explicit DAG entries
//! needed to justify a deferred root before a precompile VM STARK proof is produced. Wire index 0
//! is reserved for the implicit TRUE node; entry `i` has wire index `i + 1`, and structural child
//! references may only point to TRUE or earlier entries. Empty wire opens [`TRUE_DIGEST`];
//! otherwise the root is the digest of the final entry.
//!
//! Rehydration decodes the untrusted stream into ordinary [`DeferredState`] nodes, rejects
//! non-canonical/dangling wire by comparing with [`DeferredState::to_wire`], and finally evaluates
//! the implicit root to repopulate evaluation memos. This supports explicit partial verification:
//! public final verification rejects `DeferredProof::Wire`, while the partial verifier rehydrates
//! it and verifies the VM proof against the resulting root.

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
/// Wire index 0 is implicit TRUE. `entries[i]` has wire index `i + 1`. Structural children must
/// reference `TRUE_INDEX` or an earlier entry. Pair-list pairs store structural child references in
/// payload order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WireEntry {
    /// Raw data payload interpreted by the tag's precompile.
    ///
    /// Rehydration requires at least one chunk. A tag's precompile may assign value semantics to a
    /// one-chunk payload, but the wire shape itself does not.
    Data { tag: Tag, chunks: Vec<DataChunk> },
    /// Two child references resolved against `TRUE_INDEX` or earlier wire indices.
    Join { tag: Tag, lhs: u32, rhs: u32 },
    /// Raw structural child-reference pairs. Rehydration requires at least one pair.
    PairList { tag: Tag, pairs: Vec<(u32, u32)> },
}

// DEFERRED STATE WIRE
// ================================================================================================

/// Wire representation of a deferred root opening.
///
/// The root is implicit: empty `entries` opens [`TRUE_DIGEST`], otherwise the root is the digest of
/// the last entry. Accepted wire must be topologically ordered, root-last, duplicate-free,
/// canonical, and semantically valid under the installed [`PrecompileRegistry`]. Wire-backed
/// deferred proofs are partial material: public final verification rejects them, and explicit
/// partial verification rehydrates them before checking the VM proof.
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

        // Register entries in strict topological wire order. Structural children have already been
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
                WireEntry::PairList { tag, pairs } => self.decode_pair_list_entry(*tag, pairs)?,
            };
            self.push_entry(node)?;
        }

        let root = *self.index_to_digest.last().expect("digest table is seeded with TRUE_DIGEST");
        Ok((self.entries, root))
    }

    fn decode_data_entry(&self, tag: Tag, chunks: &[DataChunk]) -> Result<Node, IntegrityError> {
        // The decoded shape — not the wire entry variant — decides whether these payload bytes are
        // data. Semantic chunk-count checks belong to the owning precompile during registration.
        let node_type = self
            .precompiles
            .decode_node_type(tag)
            .map_err(|_| IntegrityError::InvalidStructure)?;
        let NodeType::Data = node_type else {
            return Err(IntegrityError::InvalidStructure);
        };
        let node = if tag == Tag::CHUNKS {
            Node::chunks(chunks.to_vec()).map_err(|_| IntegrityError::InvalidStructure)?
        } else {
            Node::try_data(tag, chunks.to_vec()).map_err(|_| IntegrityError::InvalidStructure)?
        };
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
            NodeType::True | NodeType::Data | NodeType::PairList => {
                Err(IntegrityError::InvalidStructure)
            },
        }
    }

    fn decode_pair_list_entry(
        &self,
        tag: Tag,
        pairs: &[(u32, u32)],
    ) -> Result<Node, IntegrityError> {
        let node_type = self
            .precompiles
            .decode_node_type(tag)
            .map_err(|_| IntegrityError::InvalidStructure)?;
        let NodeType::PairList = node_type else {
            return Err(IntegrityError::InvalidStructure);
        };

        let pairs = pairs
            .iter()
            .map(|(lhs, rhs)| Ok((self.resolve_index(*lhs)?, self.resolve_index(*rhs)?)))
            .collect::<Result<Vec<_>, IntegrityError>>()?;
        let node = Node::try_pair_list(tag, pairs).map_err(|_| IntegrityError::InvalidStructure)?;
        node_type.validate_node(&node).map_err(|_| IntegrityError::InvalidStructure)?;
        Ok(node)
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
        let mut pending = Vec::new();
        pending.push(WireEncodeStep::Visit(digest));

        while let Some(step) = pending.pop() {
            match step {
                WireEncodeStep::Visit(digest) => {
                    self.schedule_digest(state, digest, &mut pending)?
                },
                WireEncodeStep::Emit(digest) => {
                    let entry = self.entry_for_digest(state, digest)?;
                    self.push_entry(digest, entry)?;
                },
            }
        }

        Ok(())
    }

    fn schedule_digest(
        &mut self,
        state: &DeferredState,
        digest: Digest,
        pending: &mut Vec<WireEncodeStep>,
    ) -> Result<(), IntegrityError> {
        if digest == TRUE_DIGEST || !self.seen.insert(digest) {
            return Ok(());
        }

        let node = self.validated_node(state, digest)?;
        pending.push(WireEncodeStep::Emit(digest));

        match self.node_type(state, node)? {
            NodeType::Data => {},
            NodeType::Join => {
                let (lhs, rhs) =
                    node.payload().as_join().map_err(|_| IntegrityError::InvalidStructure)?;
                pending.push(WireEncodeStep::Visit(rhs));
                pending.push(WireEncodeStep::Visit(lhs));
            },
            NodeType::PairList => {
                let pairs =
                    node.payload().as_pair_list().map_err(|_| IntegrityError::InvalidStructure)?;
                for (lhs, rhs) in pairs.iter().rev() {
                    pending.push(WireEncodeStep::Visit(*rhs));
                    pending.push(WireEncodeStep::Visit(*lhs));
                }
            },
            NodeType::True => return Err(IntegrityError::InvalidStructure),
        };

        Ok(())
    }

    fn entry_for_digest(
        &self,
        state: &DeferredState,
        digest: Digest,
    ) -> Result<WireEntry, IntegrityError> {
        let node = self.validated_node(state, digest)?;

        Ok(match self.node_type(state, node)? {
            NodeType::Data => WireEntry::Data {
                tag: node.tag(),
                chunks: node
                    .payload()
                    .as_data()
                    .map_err(|_| IntegrityError::InvalidStructure)?
                    .to_vec(),
            },
            NodeType::Join => {
                let (lhs, rhs) =
                    node.payload().as_join().map_err(|_| IntegrityError::InvalidStructure)?;
                let lhs = self.index_for(lhs)?;
                let rhs = self.index_for(rhs)?;
                WireEntry::Join { tag: node.tag(), lhs, rhs }
            },
            NodeType::PairList => {
                let pairs =
                    node.payload().as_pair_list().map_err(|_| IntegrityError::InvalidStructure)?;
                let pairs = pairs
                    .iter()
                    .map(|(lhs, rhs)| Ok((self.index_for(*lhs)?, self.index_for(*rhs)?)))
                    .collect::<Result<Vec<_>, IntegrityError>>()?;
                WireEntry::PairList { tag: node.tag(), pairs }
            },
            NodeType::True => return Err(IntegrityError::InvalidStructure),
        })
    }

    fn validated_node<'a>(
        &self,
        state: &'a DeferredState,
        digest: Digest,
    ) -> Result<&'a Node, IntegrityError> {
        let node = state.get_node(&digest).ok_or(IntegrityError::InvalidStructure)?;
        self.node_type(state, node)?
            .validate_node(node)
            .map_err(|_| IntegrityError::InvalidStructure)?;
        Ok(node)
    }

    fn node_type(&self, state: &DeferredState, node: &Node) -> Result<NodeType, IntegrityError> {
        state
            .registry()
            .decode_node_type(node.tag())
            .map_err(|_| IntegrityError::InvalidStructure)
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

enum WireEncodeStep {
    Visit(Digest),
    Emit(Digest),
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
            Self::PairList { tag, pairs } => {
                target.write_u8(2);
                tag.write_into(target);
                target.write_usize(pairs.len());
                for (lhs, rhs) in pairs {
                    target.write_u32(*lhs);
                    target.write_u32(*rhs);
                }
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
            2 => {
                let tag = Tag::read_from(source)?;
                let pair_count = source.read_usize()?;
                let pairs = source
                    .read_many_iter::<WirePair>(pair_count)?
                    .map(|pair| pair.map(|pair| pair.0))
                    .collect::<Result<_, _>>()?;
                Ok(Self::PairList { tag, pairs })
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

struct WirePair((u32, u32));

impl Deserializable for WirePair {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self((source.read_u32()?, source.read_u32()?)))
    }

    fn min_serialized_size() -> usize {
        u32::min_serialized_size() * 2
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
        deferred::{DeferredContext, Payload, Precompile, precompile_id},
        serde::{ByteWriter, Serializable},
    };

    #[derive(Debug, Clone, Copy)]
    struct PairListFixture;

    impl PairListFixture {
        const NAME: &'static str = "wire-pair-list-fixture";

        fn tag() -> Tag {
            Tag::precompile(precompile_id(Self::NAME), [ZERO; 3])
                .expect("fixture id is precompile-owned")
        }
    }

    impl Precompile for PairListFixture {
        fn name(&self) -> &'static str {
            Self::NAME
        }

        fn id(&self) -> Felt {
            precompile_id(Self::NAME)
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            (args == [ZERO; 3]).then_some(NodeType::PairList)
        }

        fn evaluate(
            &self,
            _args: [Felt; 3],
            _payload: &Payload,
            _context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            Ok(Node::TRUE)
        }
    }

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

    #[test]
    fn wire_decoder_accepts_exact_framework_chunks_data() {
        let registry = PrecompileRegistry::new();
        let chunks = alloc::vec![felts(10), felts(20)];
        let wire = wire(alloc::vec![WireEntry::Data { tag: Tag::CHUNKS, chunks: chunks.clone() }]);
        let node = Node::chunks(chunks).unwrap();

        let (entries, root) = WireDecoder::new(&wire, &registry).unwrap().decode().unwrap();

        assert_eq!(entries, alloc::vec![(node.digest(), node.clone())]);
        assert_eq!(root, node.digest());
    }

    #[test]
    fn rehydration_rejects_empty_data_and_pair_list_entries() {
        let empty_data =
            wire(alloc::vec![WireEntry::Data { tag: Tag::CHUNKS, chunks: Vec::new() }]);
        assert!(matches!(
            DeferredState::from_wire(Arc::new(PrecompileRegistry::new()), &empty_data, usize::MAX,),
            Err(IntegrityError::InvalidStructure)
        ));

        let empty_pairs = wire(alloc::vec![WireEntry::PairList {
            tag: PairListFixture::tag(),
            pairs: Vec::new(),
        }]);
        assert!(matches!(
            DeferredState::from_wire(
                Arc::new(PrecompileRegistry::new().with_precompile(PairListFixture)),
                &empty_pairs,
                usize::MAX,
            ),
            Err(IntegrityError::InvalidStructure)
        ));
    }

    #[test]
    fn wire_decoder_rejects_malformed_framework_chunks_data() {
        let registry = PrecompileRegistry::new();
        let malformed = Tag::from_word([Tag::CHUNKS.id(), Felt::new_unchecked(1), ZERO, ZERO]);
        let wire = wire(alloc::vec![WireEntry::Data {
            tag: malformed,
            chunks: alloc::vec![felts(10)],
        }]);

        assert!(matches!(
            WireDecoder::new(&wire, &registry).unwrap().decode(),
            Err(IntegrityError::InvalidStructure)
        ));
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
            WireEntry::PairList {
                tag: tag(5),
                pairs: alloc::vec![(1, 2), (TRUE_INDEX, 3)],
            },
        ]));
        assert_wire_round_trips(DeferredStateWire::default());
    }

    #[test]
    fn wire_encoder_handles_deep_roots_iteratively() {
        let mut state = DeferredState::default();
        for _ in 0..4_096 {
            state.log_statement(TRUE_DIGEST).unwrap();
        }

        let root = state.root();
        let wire = state.to_wire().unwrap();

        assert_eq!(wire.entries.len(), 4_096);
        assert_eq!(
            wire.entries.last(),
            Some(&WireEntry::Join {
                tag: Tag::AND,
                lhs: 4_095,
                rhs: TRUE_INDEX,
            })
        );
        assert_eq!(
            DeferredState::from_wire(Arc::new(PrecompileRegistry::new()), &wire, usize::MAX)
                .unwrap()
                .root(),
            root
        );
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

    #[test]
    fn wire_rejects_over_budget_pair_count() {
        let mut bytes = Vec::new();
        bytes.write_usize(1);
        bytes.write_u8(2); // PairList entry discriminant
        tag(1).write_into(&mut bytes);
        bytes.write_usize(usize::MAX);

        assert!(DeferredStateWire::read_from_bytes(&bytes).is_err());
    }
}
