//! Portable singleton deferred witnesses and their versioned encoding.
//!
//! Index zero is implicit TRUE. Every explicit entry references earlier entries, and the final
//! entry opens the execution root. Decoding checks structure and commitments without evaluating
//! precompile operations; operation support and assertion truth require evaluation.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    sync::Arc,
    vec::Vec,
};

use miden_crypto::hash::eidos::{Eidos, EidosDomain, EidosFrame};

use super::{
    DEFERRED_AND_FRAME, DataChunk, DeferredState, Digest, MAX_DEFERRED_ELEMENTS, Node, NodeType,
    PrecompileError, PrecompileRegistry, TRUE_DIGEST,
};
use crate::{
    Felt, Word, ZERO,
    program::domain::DeferredChunksDomain,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader, validate_bounded_len,
    },
};

// CONSTANTS
// ================================================================================================

/// Reserved index for the always-known [`super::TRUE_DIGEST`] / [`super::Node::TRUE`] node.
const TRUE_INDEX: u32 = 0;

const MAX_WIRE_ENTRIES: usize = MAX_DEFERRED_ELEMENTS / EidosFrame::FELT_LEN;

fn reserve_wire_elements(
    remaining_elements: &mut usize,
    requested_elements: usize,
) -> Result<(), DeserializationError> {
    *remaining_elements = remaining_elements.checked_sub(requested_elements).ok_or_else(|| {
        DeserializationError::InvalidValue(format!(
            "deferred wire exceeds the {MAX_DEFERRED_ELEMENTS} element limit"
        ))
    })?;
    Ok(())
}

fn reserve_wire_payload(
    remaining_elements: &mut usize,
    payload_count: usize,
) -> Result<(), DeserializationError> {
    let payload_elements =
        payload_count.checked_mul(Node::DATA_CHUNK_FELT_LEN).ok_or_else(|| {
            DeserializationError::InvalidValue("deferred wire element count overflow".into())
        })?;
    reserve_wire_elements(remaining_elements, payload_elements)
}

// WIRE ENTRY
// ================================================================================================

/// One explicit deferred DAG entry in topological wire order.
///
/// Wire index 0 is implicit TRUE. `entries[i]` has wire index `i + 1`. Structural children must
/// reference `TRUE_INDEX` or an earlier entry. Pair-list pairs store structural child references in
/// payload order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEntry {
    /// Raw data payload interpreted by the frame's precompile.
    ///
    /// The payload requires at least one chunk. The frame's precompile may assign value semantics
    /// to a one-chunk payload, but the wire shape itself does not.
    Data {
        frame: EidosFrame,
        chunks: Vec<DataChunk>,
    },
    /// Two child references resolved against `TRUE_INDEX` or earlier wire indices.
    Join { frame: EidosFrame, lhs: u32, rhs: u32 },
    /// Raw structural child-reference pairs, with at least one pair.
    PairList {
        frame: EidosFrame,
        pairs: Vec<(u32, u32)>,
    },
}

impl WireEntry {
    // Join is the shortest valid entry; unchecked empty Data/PairList payloads are not witnesses.
    fn min_serialized_size() -> usize {
        1 + Word::min_serialized_size() + 2 * u32::min_serialized_size()
    }

    /// Returns the frame whose operation is checked by the precompile prover.
    pub fn frame(&self) -> EidosFrame {
        match self {
            Self::Data { frame, .. } | Self::Join { frame, .. } | Self::PairList { frame, .. } => {
                *frame
            },
        }
    }

    fn children(&self) -> impl DoubleEndedIterator<Item = u32> + '_ {
        let (join, pairs) = match self {
            Self::Join { lhs, rhs, .. } => (Some([*lhs, *rhs]), &[][..]),
            Self::PairList { pairs, .. } => (None, pairs.as_slice()),
            Self::Data { .. } => (None, &[][..]),
        };
        join.into_iter()
            .flatten()
            .chain(pairs.iter().flat_map(|&(lhs, rhs)| [lhs, rhs]))
    }

    /// Reconstructs this entry's commitment from preceding digests, with TRUE at index zero.
    ///
    /// This validates framework shapes and references, without interpreting precompile frames or
    /// evaluating assertions. Framework domains are accepted only in their own shapes: `CHUNKS`
    /// as data with a matching length, `AND` as a join. The caller supplies only entries
    /// preceding this one.
    pub fn digest(&self, digests: &[Digest]) -> Result<Digest, IntegrityError> {
        if digests.first() != Some(&TRUE_DIGEST) {
            return Err(IntegrityError::InvalidStructure);
        }
        if self.children().any(|index| index as usize >= digests.len()) {
            return Err(IntegrityError::InvalidStructure);
        }
        let frame = self.frame();
        let invalid = |_| IntegrityError::InvalidStructure;
        let mut cv = frame.initial_chaining_word();
        let pair = |lhs: u32, rhs: u32| {
            let [l0, l1, l2, l3] = digests[lhs as usize].into_elements();
            let [r0, r1, r2, r3] = digests[rhs as usize].into_elements();
            [l0, l1, l2, l3, r0, r1, r2, r3]
        };
        match self {
            Self::Data { chunks, .. } if !chunks.is_empty() => {
                if frame.domain() == DeferredChunksDomain::TAG {
                    if Node::chunks_frame_for_len(chunks.len()).map_err(invalid)? != frame {
                        return Err(IntegrityError::InvalidStructure);
                    }
                } else {
                    Node::require_precompile_frame(frame).map_err(invalid)?;
                }
                for &chunk in chunks {
                    cv = Eidos::compress(cv, chunk);
                }
            },
            Self::Join { lhs, rhs, .. } => {
                if frame != DEFERRED_AND_FRAME {
                    Node::require_precompile_frame(frame).map_err(invalid)?;
                }
                cv = Eidos::compress(cv, pair(*lhs, *rhs));
            },
            Self::PairList { pairs, .. } if !pairs.is_empty() => {
                Node::require_precompile_frame(frame).map_err(invalid)?;
                for &(lhs, rhs) in pairs {
                    cv = Eidos::compress(cv, pair(lhs, rhs));
                }
            },
            _ => return Err(IntegrityError::InvalidStructure),
        }
        Ok(cv)
    }
}

// PORTABLE WITNESS
// ================================================================================================

/// A portable opening of one nonempty deferred execution obligation.
///
/// Entries are canonical, child-first, duplicate-free, and reachable from the single non-TRUE
/// root. A witness contains private prover input, without runtime state or evaluation caches.
/// Structural validity does not establish operation support or assertion truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileWitness {
    entries: Vec<WireEntry>,
    root: Digest,
}

impl PrecompileWitness {
    /// Version of the standalone singleton witness encoding. Other versions are rejected.
    pub const WIRE_VERSION: u8 = 1;

    /// Checks a nonempty canonical singleton graph without evaluating any precompile.
    pub fn from_entries(entries: Vec<WireEntry>) -> Result<Self, IntegrityError> {
        let mut wire = Self { entries, root: TRUE_DIGEST };
        wire.root = wire.validate_structure()?;
        if wire.root == TRUE_DIGEST {
            return Err(IntegrityError::InvalidStructure);
        }
        Ok(wire)
    }

    /// Returns the cached commitment without checking the precompile computations.
    ///
    /// Use [`Self::compute_root`] to evaluate the witness and recompute its commitment.
    pub fn root_unchecked(&self) -> Digest {
        self.root
    }

    /// Evaluates the witness under `registry` and returns its recomputed root commitment.
    ///
    /// Entries must reference only earlier entries or implicit TRUE at index zero. Each node is
    /// registered in a temporary [`DeferredState`], which checks its shape and computation. The
    /// final node must evaluate to TRUE. The cached root is not used.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty witness, invalid references, unsupported operations, failed
    /// assertions, or evaluation that exceeds the deferred state budget.
    pub fn compute_root(
        &self,
        registry: Arc<PrecompileRegistry>,
    ) -> Result<Digest, PrecompileError> {
        if self.entries.is_empty() {
            return Err(PrecompileError::InvalidNode);
        }
        let mut state = DeferredState::new(registry)?;
        let mut digests = Vec::with_capacity(self.entries.len() + 1);
        digests.push(TRUE_DIGEST);
        for entry in &self.entries {
            let child = |index: u32| {
                digests.get(index as usize).copied().ok_or(PrecompileError::InvalidNode)
            };
            let node = match entry {
                WireEntry::Data { frame, chunks } => {
                    if frame.domain() == DeferredChunksDomain::TAG {
                        let node = Node::chunks(chunks.clone())?;
                        if node.frame() != Some(*frame) {
                            return Err(PrecompileError::InvalidNode);
                        }
                        node
                    } else {
                        Node::try_data(*frame, chunks.clone())?
                    }
                },
                WireEntry::Join { frame, lhs, rhs } => {
                    let (lhs, rhs) = (child(*lhs)?, child(*rhs)?);
                    if *frame == DEFERRED_AND_FRAME {
                        Node::and(lhs, rhs)
                    } else {
                        Node::join(*frame, lhs, rhs)?
                    }
                },
                WireEntry::PairList { frame, pairs } => {
                    let pairs = pairs
                        .iter()
                        .map(|&(lhs, rhs)| Ok((child(lhs)?, child(rhs)?)))
                        .collect::<Result<Vec<_>, PrecompileError>>()?;
                    Node::try_pair_list(*frame, pairs)?
                },
            };
            digests.push(state.register(node)?);
        }
        let root = *digests.last().expect("TRUE seeds the digest table");
        if state.evaluate_digest(root)? != TRUE_DIGEST {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(root)
    }

    /// Returns canonical child-first entries. Index zero denotes implicit TRUE.
    pub fn entries(&self) -> &[WireEntry] {
        &self.entries
    }

    fn validate_structure(&self) -> Result<Digest, IntegrityError> {
        self.validate_element_limit()?;
        let mut digests = Vec::with_capacity(self.entries.len() + 1);
        let mut seen_digests = BTreeSet::new();
        digests.push(TRUE_DIGEST);
        seen_digests.insert(TRUE_DIGEST);
        for entry in &self.entries {
            let digest = entry.digest(&digests)?;
            if !seen_digests.insert(digest) {
                return Err(IntegrityError::InvalidStructure);
            }
            digests.push(digest);
        }

        // The same left-to-right DFS used by the exporter must emit exactly the supplied stream.
        // Backward references make this iterative traversal acyclic, including for shared graphs.
        let mut seen = alloc::vec![false; digests.len()];
        let mut pending = alloc::vec![(self.entries.len(), false)];
        let mut next_index = 1;
        while let Some((index, emit)) = pending.pop() {
            if index == 0 {
                continue;
            }
            if emit {
                if index != next_index {
                    return Err(IntegrityError::InvalidStructure);
                }
                next_index += 1;
            } else if !core::mem::replace(&mut seen[index], true) {
                pending.push((index, true));
                pending.extend(
                    self.entries[index - 1].children().rev().map(|child| (child as usize, false)),
                );
            }
        }
        if next_index != digests.len() {
            return Err(IntegrityError::InvalidStructure);
        }
        Ok(*digests.last().expect("TRUE seeds the digest table"))
    }

    /// Exports the original root-reachable execution graph without serializing through bytes.
    pub(crate) fn from_state(state: &DeferredState) -> Result<Self, IntegrityError> {
        let mut build = WireEncoder::default();
        build.visit_state_digest(state, state.root())?;
        Ok(Self {
            entries: build.entries,
            root: state.root(),
        })
    }

    fn validate_element_limit(&self) -> Result<(), IntegrityError> {
        let mut remaining_elements = MAX_DEFERRED_ELEMENTS;
        for entry in &self.entries {
            let payload_count = match entry {
                WireEntry::Data { chunks, .. } => chunks.len(),
                WireEntry::Join { .. } => 1,
                WireEntry::PairList { pairs, .. } => pairs.len(),
            };
            let payload_elements = payload_count
                .checked_mul(Node::DATA_CHUNK_FELT_LEN)
                .and_then(|elements| EidosFrame::FELT_LEN.checked_add(elements))
                .ok_or(IntegrityError::InvalidStructure)?;
            remaining_elements = remaining_elements.checked_sub(payload_elements).ok_or(
                IntegrityError::DeferredStateTooLarge {
                    num_elements: payload_elements,
                    max: remaining_elements,
                },
            )?;
        }
        Ok(())
    }
}

// INTEGRITY ERROR
// ================================================================================================

/// A portable graph cannot be represented within the structural and resource constraints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// Invalid framework shape, child reference, duplicate, orphan, or canonical entry order.
    #[error("invalid or non-canonical precompile witness structure")]
    InvalidStructure,
    /// The portable entries exceed the same field-element ceiling as execution state.
    #[error("deferred insertion requires {num_elements} elements but only {max} remain")]
    DeferredStateTooLarge { num_elements: usize, max: usize },
}

// WIRE ENCODING
// ================================================================================================

/// Iterative exporter for the original, root-reachable execution graph.
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
                frame: node.frame().ok_or(IntegrityError::InvalidStructure)?,
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
                WireEntry::Join {
                    frame: node.frame().ok_or(IntegrityError::InvalidStructure)?,
                    lhs,
                    rhs,
                }
            },
            NodeType::PairList => {
                let pairs =
                    node.payload().as_pair_list().map_err(|_| IntegrityError::InvalidStructure)?;
                let pairs = pairs
                    .iter()
                    .map(|(lhs, rhs)| Ok((self.index_for(*lhs)?, self.index_for(*rhs)?)))
                    .collect::<Result<Vec<_>, IntegrityError>>()?;
                WireEntry::PairList {
                    frame: node.frame().ok_or(IntegrityError::InvalidStructure)?,
                    pairs,
                }
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
        state
            .registry()
            .validate_node(node)
            .map_err(|_| IntegrityError::InvalidStructure)?;
        Ok(node)
    }

    fn node_type(&self, state: &DeferredState, node: &Node) -> Result<NodeType, IntegrityError> {
        state
            .registry()
            .decode_node_type(node.frame().ok_or(IntegrityError::InvalidStructure)?)
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
            Self::Data { frame, chunks } => {
                target.write_u8(0);
                frame.as_word().write_into(target);
                target.write_usize(chunks.len());
                for chunk in chunks {
                    for felt in chunk {
                        felt.write_into(target);
                    }
                }
            },
            Self::Join { frame, lhs, rhs } => {
                target.write_u8(1);
                frame.as_word().write_into(target);
                target.write_u32(*lhs);
                target.write_u32(*rhs);
            },
            Self::PairList { frame, pairs } => {
                target.write_u8(2);
                frame.as_word().write_into(target);
                target.write_usize(pairs.len());
                for (lhs, rhs) in pairs {
                    target.write_u32(*lhs);
                    target.write_u32(*rhs);
                }
            },
        }
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

impl Serializable for PrecompileWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(Self::WIRE_VERSION);
        target.write_usize(self.entries.len());
        for entry in &self.entries {
            entry.write_into(target);
        }
    }
}

impl Deserializable for PrecompileWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != Self::WIRE_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported precompile witness version {version} (expected {})",
                Self::WIRE_VERSION
            )));
        }
        let entry_count =
            read_len(source, "precompile witness entry", WireEntry::min_serialized_size())?;
        if entry_count == 0 || entry_count > MAX_WIRE_ENTRIES {
            return Err(DeserializationError::InvalidValue(format!(
                "precompile witness contains {entry_count} entries, expected 1..={MAX_WIRE_ENTRIES}"
            )));
        }

        let mut remaining_elements = MAX_DEFERRED_ELEMENTS;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(read_wire_entry(source, &mut remaining_elements)?);
        }
        Self::from_entries(entries).map_err(|error| {
            DeserializationError::InvalidValue(format!("invalid precompile witness: {error}"))
        })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let wire = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "trailing bytes after deferred witness".into(),
            ));
        }
        Ok(wire)
    }

    fn min_serialized_size() -> usize {
        1 + usize::min_serialized_size() + WireEntry::min_serialized_size()
    }
}

/// Retain the existing vint64 decoder and allocation checks, requiring its shortest encoding.
fn read_len<R: ByteReader>(
    source: &mut R,
    label: &str,
    min_element_size: usize,
) -> Result<usize, DeserializationError> {
    let encoded_len = source.peek_u8()?.trailing_zeros() as usize + 1;
    let len = source.read_usize()?;
    // The usize Serializable implementation computes the exact vint64 width without allocating.
    if encoded_len != len.get_size_hint() {
        return Err(DeserializationError::InvalidValue(format!("noncanonical {label} length")));
    }
    validate_bounded_len(source, label, len, min_element_size)?;
    Ok(len)
}

fn read_wire_entry<R: ByteReader>(
    source: &mut R,
    remaining_elements: &mut usize,
) -> Result<WireEntry, DeserializationError> {
    let discriminant = source.read_u8()?;
    match discriminant {
        0 => {
            reserve_wire_elements(remaining_elements, EidosFrame::FELT_LEN)?;
            let frame = read_frame(source)?;
            let chunk_count = read_len(source, "data chunk", WireDataChunk::min_serialized_size())?;
            reserve_wire_payload(remaining_elements, chunk_count)?;
            let chunks = source
                .read_many_iter::<WireDataChunk>(chunk_count)?
                .map(|chunk| chunk.map(|chunk| chunk.0))
                .collect::<Result<_, _>>()?;
            Ok(WireEntry::Data { frame, chunks })
        },
        1 => {
            reserve_wire_elements(
                remaining_elements,
                EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN,
            )?;
            let frame = read_frame(source)?;
            let lhs = source.read_u32()?;
            let rhs = source.read_u32()?;
            Ok(WireEntry::Join { frame, lhs, rhs })
        },
        2 => {
            reserve_wire_elements(remaining_elements, EidosFrame::FELT_LEN)?;
            let frame = read_frame(source)?;
            let pair_count = read_len(source, "child pair", WirePair::min_serialized_size())?;
            reserve_wire_payload(remaining_elements, pair_count)?;
            let pairs = source
                .read_many_iter::<WirePair>(pair_count)?
                .map(|pair| pair.map(|pair| pair.0))
                .collect::<Result<_, _>>()?;
            Ok(WireEntry::PairList { frame, pairs })
        },
        other => Err(DeserializationError::InvalidValue(format!(
            "invalid deferred wire entry discriminant: {other}"
        ))),
    }
}

fn read_frame<R: ByteReader>(source: &mut R) -> Result<EidosFrame, DeserializationError> {
    EidosFrame::from_word(Word::read_from(source)?)
        .ok_or_else(|| DeserializationError::InvalidValue("invalid deferred Eidos frame".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{deferred_chunks_frame, precompile::test_precompile_domain_tag};

    fn felts(seed: u64) -> DataChunk {
        core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64))
    }

    fn frame(seed: u8) -> EidosFrame {
        EidosFrame::new(test_precompile_domain_tag(seed), [u32::from(seed), 0, 0])
    }

    fn encoded_entries(entries: &[WireEntry]) -> Vec<u8> {
        let mut bytes = alloc::vec![PrecompileWitness::WIRE_VERSION];
        bytes.write_usize(entries.len());
        for entry in entries {
            entry.write_into(&mut bytes);
        }
        bytes
    }

    #[test]
    fn portable_structure_is_independent_of_operation_support() {
        let entries = alloc::vec![
            WireEntry::Data {
                frame: frame(1),
                chunks: alloc::vec![felts(10)]
            },
            WireEntry::Data {
                frame: frame(2),
                chunks: alloc::vec![felts(20), felts(30)]
            },
            WireEntry::Join { frame: frame(3), lhs: 1, rhs: 1 },
            WireEntry::PairList {
                frame: frame(4),
                pairs: alloc::vec![(1, 2), (3, 3)]
            },
        ];
        let witness = PrecompileWitness::from_entries(entries).unwrap();
        let left = Node::value(frame(1), felts(10)).unwrap().digest();
        let right = Node::try_data(frame(2), alloc::vec![felts(20), felts(30)]).unwrap().digest();
        let claim = Node::join(frame(3), left, left).unwrap().digest();
        assert_eq!(
            witness.root_unchecked(),
            Node::try_pair_list(frame(4), alloc::vec![(left, right), (claim, claim)])
                .unwrap()
                .digest()
        );
        assert_eq!(PrecompileWitness::read_from_bytes(&witness.to_bytes()).unwrap(), witness);
    }

    #[test]
    fn portable_structure_rejects_noncanonical_and_malformed_graphs() {
        let leaf = || WireEntry::Data {
            frame: frame(1),
            chunks: alloc::vec![felts(10)],
        };
        let other = || WireEntry::Data {
            frame: frame(1),
            chunks: alloc::vec![felts(20)],
        };
        let malformed_and = EidosFrame::new(DEFERRED_AND_FRAME.domain(), [1, 0, 0]);
        let cases = [
            Vec::new(),
            alloc::vec![WireEntry::Data {
                frame: deferred_chunks_frame(1),
                chunks: Vec::new()
            }],
            alloc::vec![WireEntry::PairList { frame: frame(1), pairs: Vec::new() }],
            alloc::vec![WireEntry::Data {
                frame: DEFERRED_AND_FRAME,
                chunks: alloc::vec![felts(10)]
            }],
            alloc::vec![WireEntry::Data {
                frame: deferred_chunks_frame(2),
                chunks: alloc::vec![felts(10)]
            }],
            alloc::vec![WireEntry::Join {
                frame: deferred_chunks_frame(1),
                lhs: 0,
                rhs: 0
            }],
            alloc::vec![WireEntry::Join { frame: malformed_and, lhs: 0, rhs: 0 }],
            alloc::vec![WireEntry::Join {
                frame: DEFERRED_AND_FRAME,
                lhs: 0,
                rhs: 1
            }],
            alloc::vec![
                leaf(),
                leaf(),
                WireEntry::Join {
                    frame: DEFERRED_AND_FRAME,
                    lhs: 1,
                    rhs: 2
                }
            ],
            alloc::vec![leaf(), other()],
            alloc::vec![
                leaf(),
                other(),
                WireEntry::Join {
                    frame: DEFERRED_AND_FRAME,
                    lhs: 2,
                    rhs: 1
                }
            ],
        ];
        for entries in cases {
            let bytes = encoded_entries(&entries);
            assert!(PrecompileWitness::from_entries(entries).is_err());
            assert!(PrecompileWitness::read_from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn compute_root_ignores_cached_root_and_checks_entries() {
        let mut witness = PrecompileWitness::from_entries(alloc::vec![WireEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 0,
        }])
        .unwrap();
        let expected = witness.root_unchecked();
        witness.root = TRUE_DIGEST;
        let registry = Arc::new(PrecompileRegistry::new());
        assert_eq!(witness.compute_root(registry.clone()).unwrap(), expected);

        for entries in [
            Vec::new(),
            alloc::vec![WireEntry::Join {
                frame: DEFERRED_AND_FRAME,
                lhs: 0,
                rhs: 1
            }],
            alloc::vec![
                WireEntry::Join {
                    frame: DEFERRED_AND_FRAME,
                    lhs: 0,
                    rhs: 2
                },
                WireEntry::Join {
                    frame: DEFERRED_AND_FRAME,
                    lhs: 0,
                    rhs: 0
                },
            ],
            alloc::vec![WireEntry::PairList {
                frame: frame(1),
                pairs: alloc::vec![(0, 1)]
            }],
        ] {
            let malformed = PrecompileWitness { entries, root: expected };
            assert!(matches!(
                malformed.compute_root(registry.clone()),
                Err(PrecompileError::InvalidNode)
            ));
        }
        let value = PrecompileWitness::from_entries(alloc::vec![WireEntry::Data {
            frame: deferred_chunks_frame(1),
            chunks: alloc::vec![felts(10)],
        }])
        .unwrap();
        assert!(matches!(value.compute_root(registry), Err(PrecompileError::AssertionFailed)));
    }

    #[test]
    fn export_omits_unreachable_state_and_retains_logged_true() {
        let mut empty = DeferredState::default();
        empty.register(Node::chunks(alloc::vec![felts(10)]).unwrap()).unwrap();
        assert!(empty.into_witness().unwrap().is_none());
        let mut state = DeferredState::default();
        state.register(Node::chunks(alloc::vec![felts(10)]).unwrap()).unwrap();
        state.log_statement(TRUE_DIGEST).unwrap();
        let root = state.root();
        let witness = state.into_witness().unwrap().unwrap();
        assert_eq!(witness.root_unchecked(), root);
        assert_eq!(
            witness.entries(),
            &[WireEntry::Join {
                frame: DEFERRED_AND_FRAME,
                lhs: 0,
                rhs: 0
            }]
        );
    }

    #[test]
    fn deep_shared_graph_exports_and_decodes_without_expansion() {
        let mut state = DeferredState::default();
        let mut statement = TRUE_DIGEST;
        for _ in 0..4_096 {
            statement = state.register(Node::and(statement, statement)).unwrap();
        }
        state.log_statement(statement).unwrap();
        let root = state.root();
        let witness = state.into_witness().unwrap().unwrap();
        assert_eq!(witness.entries().len(), 4_097);
        assert_eq!(witness.compute_root(Arc::new(PrecompileRegistry::new())).unwrap(), root);
        assert_eq!(witness.root_unchecked(), root);
        assert_eq!(PrecompileWitness::from_entries(witness.entries().to_vec()).unwrap(), witness);
        assert_eq!(PrecompileWitness::read_from_bytes(&witness.to_bytes()).unwrap(), witness);
    }

    #[test]
    fn standalone_witness_rejects_unsupported_versions_and_trailing_bytes() {
        let witness = PrecompileWitness::from_entries(alloc::vec![WireEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 0
        }])
        .unwrap();
        let bytes = witness.to_bytes();
        for version in [0, PrecompileWitness::WIRE_VERSION + 1] {
            let mut unsupported = bytes.clone();
            unsupported[0] = version;
            assert!(PrecompileWitness::read_from_bytes(&unsupported).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PrecompileWitness::read_from_bytes(&trailing).is_err());
    }

    #[test]
    fn decoder_rejects_overlong_entry_and_payload_lengths() {
        let entries = [
            WireEntry::Data {
                frame: deferred_chunks_frame(1),
                chunks: alloc::vec![felts(10)],
            },
            WireEntry::PairList {
                frame: frame(1),
                pairs: alloc::vec![(0, 0)],
            },
        ];
        for entry in entries {
            let witness = PrecompileWitness::from_entries(alloc::vec![entry]).unwrap();
            let bytes = witness.to_bytes();
            // Version + entry count + variant precede the frame and payload count.
            for offset in [1, 3 + Word::min_serialized_size()] {
                assert_eq!(bytes[offset], 3, "one uses the one-byte vint64 encoding");
                let mut noncanonical = bytes[..offset].to_vec();
                noncanonical.extend_from_slice(&[6, 0]);
                noncanonical.extend_from_slice(&bytes[offset + 1..]);
                assert!(PrecompileWitness::read_from_bytes(&noncanonical).is_err());
            }
        }
    }

    #[test]
    fn singleton_vector_decodes_with_exact_byte_budget() {
        let witness = PrecompileWitness::from_entries(alloc::vec![WireEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 0
        }])
        .unwrap();
        assert_eq!(PrecompileWitness::min_serialized_size(), witness.to_bytes().len());
        let witnesses = alloc::vec![witness.clone(), witness];
        let bytes = witnesses.to_bytes();
        assert_eq!(
            Vec::<PrecompileWitness>::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap(),
            witnesses
        );
    }

    #[test]
    fn wire_element_budget_accepts_exact_limit_and_rejects_one_more() {
        let mut remaining = MAX_DEFERRED_ELEMENTS;
        reserve_wire_elements(&mut remaining, MAX_DEFERRED_ELEMENTS).unwrap();
        assert_eq!(remaining, 0);
        assert!(reserve_wire_elements(&mut remaining, 1).is_err());
        let mut overflow_budget = MAX_DEFERRED_ELEMENTS;
        assert!(reserve_wire_payload(&mut overflow_budget, usize::MAX).is_err());
    }

    #[test]
    fn in_memory_entries_enforce_the_execution_element_limit() {
        let join = WireEntry::Join {
            frame: DEFERRED_AND_FRAME,
            lhs: 0,
            rhs: 0,
        };
        let mut entries = alloc::vec![join; MAX_DEFERRED_ELEMENTS / (EidosFrame::FELT_LEN + Node::DATA_CHUNK_FELT_LEN)];
        // Budget validation runs before hashing, so a repeated-entry allocation cannot bypass it.
        entries.push(WireEntry::Data {
            frame: deferred_chunks_frame(1),
            chunks: alloc::vec![felts(10)],
        });
        assert!(matches!(
            PrecompileWitness::from_entries(entries),
            Err(IntegrityError::DeferredStateTooLarge { .. })
        ));
    }

    #[test]
    fn decoder_rejects_oversized_and_truncated_lengths_before_payload_allocation() {
        for count in [MAX_WIRE_ENTRIES, MAX_WIRE_ENTRIES + 1, usize::MAX] {
            let mut bytes = alloc::vec![PrecompileWitness::WIRE_VERSION];
            bytes.write_usize(count);
            assert!(PrecompileWitness::read_from_bytes(&bytes).is_err());
        }
        for discriminant in [0, 2] {
            let mut bytes = alloc::vec![PrecompileWitness::WIRE_VERSION];
            bytes.write_usize(1);
            bytes.write_u8(discriminant);
            frame(1).as_word().write_into(&mut bytes);
            bytes.write_usize(usize::MAX);
            assert!(PrecompileWitness::read_from_bytes(&bytes).is_err());
        }
    }
}
