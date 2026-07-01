use alloc::{format, string::ToString, vec::Vec};

use super::{
    MastNodeEntry,
    basic_blocks::{BasicBlockDataBuilder, BasicBlockDataDecoder},
    layout::{OffsetTrackingReader, TrackingReader},
};
use crate::{
    Word,
    advice::AdviceMap,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId, SparseMastForest},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

const SPARSE_MAGIC: &[u8; 4] = b"SMST";
const SPARSE_VERSION: [u8; 3] = [0, 0, 0];

fn sparse_mast_forest_min_serialized_size() -> usize {
    SPARSE_MAGIC.len()
        + SPARSE_VERSION.len()
        + usize::min_serialized_size() * 7
        + Word::min_serialized_size()
        + usize::min_serialized_size()
}

/// Serializes a [`SparseMastForest`] in trusted sparse replay form.
///
/// This format carries the digest for each full node and accepts those digests on read. It is
/// suitable for trusted remote proving inputs, not as an untrusted hashless validation path.
///
/// See <https://github.com/0xMiden/miden-vm/issues/3303> for the planned untrusted reader.
pub(super) fn write_sparse_into<W: ByteWriter>(forest: &SparseMastForest, target: &mut W) {
    let mut basic_block_data_builder = BasicBlockDataBuilder::new();
    let mut full_ids = Vec::with_capacity(forest.nodes().len());
    let mut entries = Vec::with_capacity(forest.nodes().len());
    let mut full_digests = Vec::with_capacity(forest.nodes().len());

    for (&node_id, node) in forest.nodes() {
        let ops_offset = if let MastNode::Block(basic_block) = node {
            basic_block_data_builder.encode_basic_block(basic_block)
        } else {
            0
        };

        full_ids.push(node_id);
        entries.push(MastNodeEntry::new(node, ops_offset));
        full_digests.push(node.digest());
    }

    let basic_block_data = basic_block_data_builder.finalize();
    let external_full_node_count =
        entries.iter().filter(|entry| matches!(entry, MastNodeEntry::External)).count();
    let non_external_count =
        entries.iter().filter(|entry| !matches!(entry, MastNodeEntry::External)).count();

    target.write_bytes(SPARSE_MAGIC);
    target.write_bytes(&SPARSE_VERSION);

    target.write_usize(forest.procedure_roots().len());
    target.write_usize(forest.num_nodes());
    target.write_usize(full_ids.len());
    target.write_usize(forest.digest_entries().len());
    target.write_usize(external_full_node_count);
    target.write_usize(non_external_count);
    target.write_usize(basic_block_data.len());

    for &root in forest.procedure_roots() {
        root.0.write_into(target);
    }

    forest.commitment().write_into(target);
    target.write_bytes(&basic_block_data);

    for id in full_ids {
        id.0.write_into(target);
    }

    for entry in entries {
        entry.write_into(target);
    }

    for digest in full_digests {
        digest.write_into(target);
    }

    for (&id, &digest) in forest.digest_entries() {
        id.0.write_into(target);
        digest.write_into(target);
    }

    forest.advice_map().write_into(target);
}

impl Serializable for SparseMastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_sparse_into(self, target);
    }
}

impl Deserializable for SparseMastForest {
    /// Reads a trusted sparse replay payload.
    ///
    /// Full-node digests are accepted from the payload. This is not the untrusted hash-validation
    /// path from <https://github.com/0xMiden/miden-vm/issues/3303>.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_sparse_from(source)
    }

    fn min_serialized_size() -> usize {
        sparse_mast_forest_min_serialized_size()
    }

    /// Reads trusted sparse replay bytes and rejects trailing bytes.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        SparseMastForest::read_from_bytes(bytes)
    }
}

/// Reads a trusted sparse replay payload.
///
/// The payload carries full-node digests and digest-only entries as replay data. It does not
/// rebuild those hashes from node structure.
pub(super) fn read_sparse_from<R: ByteReader>(
    source: &mut R,
) -> Result<SparseMastForest, DeserializationError> {
    let mut reader = TrackingReader::new(source);
    read_and_validate_sparse_header(&mut reader)?;

    let root_count = read_bounded_count(&mut reader, size_of::<u32>(), "procedure root count")?;
    let source_node_count = reader.read_usize()?;
    if source_node_count > MastForest::MAX_NODES {
        return Err(DeserializationError::InvalidValue(format!(
            "source node count {source_node_count} exceeds maximum allowed {}",
            MastForest::MAX_NODES
        )));
    }

    let full_node_count = read_bounded_count(
        &mut reader,
        MastNodeEntry::SERIALIZED_SIZE + Word::min_serialized_size(),
        "full node count",
    )?;
    let digest_only_count = read_bounded_count(
        &mut reader,
        size_of::<u32>() + Word::min_serialized_size(),
        "digest-only node count",
    )?;
    let external_full_node_count = read_bounded_count(
        &mut reader,
        MastNodeEntry::SERIALIZED_SIZE,
        "external full-node count",
    )?;
    let non_external_full_node_count = read_bounded_count(
        &mut reader,
        MastNodeEntry::SERIALIZED_SIZE,
        "non-external full-node count",
    )?;
    let basic_block_data_len = read_bounded_count(&mut reader, 1, "basic-block data length")?;

    let counted_full = external_full_node_count
        .checked_add(non_external_full_node_count)
        .ok_or_else(|| {
            DeserializationError::InvalidValue("full node count overflow".to_string())
        })?;
    if counted_full != full_node_count {
        return Err(DeserializationError::InvalidValue(format!(
            "sparse header full node count {full_node_count} does not match external + non-external count {counted_full}"
        )));
    }

    let roots = read_id_section(&mut reader, root_count, source_node_count, "procedure root")?;
    let commitment = Word::read_from(&mut reader)?;
    let basic_block_data = reader.read_slice(basic_block_data_len)?.to_vec();
    let full_ids = read_id_section(&mut reader, full_node_count, source_node_count, "full node")?;
    validate_strictly_increasing_ids(&full_ids, "full node")?;

    let mut entries = Vec::with_capacity(full_node_count);
    for _ in 0..full_node_count {
        entries.push(MastNodeEntry::read_from(&mut reader)?);
    }

    let counted_external =
        entries.iter().filter(|entry| matches!(entry, MastNodeEntry::External)).count();
    if counted_external != external_full_node_count {
        return Err(DeserializationError::InvalidValue(format!(
            "sparse header external full-node count {external_full_node_count} does not match {counted_external} external entries"
        )));
    }

    let mut full_digests = Vec::with_capacity(full_node_count);
    for _ in 0..full_node_count {
        full_digests.push(Word::read_from(&mut reader)?);
    }

    let mut digest_entries = Vec::with_capacity(digest_only_count);
    for _ in 0..digest_only_count {
        let id = read_node_id(&mut reader, source_node_count, "digest-only node")?;
        let digest = Word::read_from(&mut reader)?;
        digest_entries.push((id, digest));
    }
    validate_strictly_increasing_entry_ids(&digest_entries, "digest-only node")?;

    let advice_map = AdviceMap::read_from(&mut reader)?;
    let nodes = materialize_sparse_nodes(
        &full_ids,
        &entries,
        &full_digests,
        source_node_count,
        &basic_block_data,
    )?;

    SparseMastForest::from_serialized_parts(
        nodes,
        digest_entries,
        source_node_count,
        roots,
        advice_map,
        commitment,
    )
}

fn read_and_validate_sparse_header<R: ByteReader>(
    source: &mut R,
) -> Result<(), DeserializationError> {
    let magic: [u8; 4] = source.read_array()?;
    if magic != *SPARSE_MAGIC {
        return Err(DeserializationError::InvalidValue(format!(
            "Invalid sparse MAST magic bytes. Expected '{:?}', got '{:?}'",
            *SPARSE_MAGIC, magic
        )));
    }

    let version: [u8; 3] = source.read_array()?;
    if version != SPARSE_VERSION {
        return Err(DeserializationError::InvalidValue(format!(
            "Unsupported sparse MAST version. Got '{version:?}', but only '{SPARSE_VERSION:?}' is supported",
        )));
    }

    Ok(())
}

fn read_bounded_count<R: OffsetTrackingReader>(
    source: &mut R,
    element_size: usize,
    label: &str,
) -> Result<usize, DeserializationError> {
    let count = source.read_usize()?;
    let max_count = source.max_alloc(element_size);
    if count > max_count {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} {count} exceeds reader allocation bound {max_count} for {element_size}-byte elements"
        )));
    }
    Ok(count)
}

fn read_id_section<R: ByteReader>(
    source: &mut R,
    count: usize,
    node_count: usize,
    label: &str,
) -> Result<Vec<MastNodeId>, DeserializationError> {
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(read_node_id(source, node_count, label)?);
    }
    Ok(ids)
}

fn read_node_id<R: ByteReader>(
    source: &mut R,
    node_count: usize,
    label: &str,
) -> Result<MastNodeId, DeserializationError> {
    let raw = u32::read_from(source)?;
    MastNodeId::from_u32_with_node_count(raw, node_count).map_err(|err| {
        DeserializationError::InvalidValue(format!("invalid {label} id {raw}: {err}"))
    })
}

fn validate_strictly_increasing_ids(
    ids: &[MastNodeId],
    label: &str,
) -> Result<(), DeserializationError> {
    for pair in ids.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(DeserializationError::InvalidValue(format!(
                "{label} ids must be strictly increasing"
            )));
        }
    }
    Ok(())
}

fn validate_strictly_increasing_entry_ids(
    entries: &[(MastNodeId, Word)],
    label: &str,
) -> Result<(), DeserializationError> {
    for pair in entries.windows(2) {
        if pair[0].0.0 >= pair[1].0.0 {
            return Err(DeserializationError::InvalidValue(format!(
                "{label} ids must be strictly increasing"
            )));
        }
    }
    Ok(())
}

fn materialize_sparse_nodes(
    full_ids: &[MastNodeId],
    entries: &[MastNodeEntry],
    full_digests: &[Word],
    source_node_count: usize,
    basic_block_data: &[u8],
) -> Result<Vec<(MastNodeId, MastNode)>, DeserializationError> {
    let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data);
    if full_digests.len() != full_ids.len() {
        return Err(DeserializationError::InvalidValue(format!(
            "sparse full digest count {} does not match full node count {}",
            full_digests.len(),
            full_ids.len()
        )));
    }

    let mut nodes = Vec::with_capacity(entries.len());
    for ((&node_id, &entry), &digest) in full_ids.iter().zip(entries).zip(full_digests) {
        let node = entry
            .try_into_mast_node_builder(source_node_count, &basic_block_data_decoder, digest)?
            .build_linked()
            .map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "failed to build sparse MAST node {}: {err}",
                    node_id.0
                ))
            })?;
        nodes.push((node_id, node));
    }

    Ok(nodes)
}

impl SparseMastForest {
    /// Deserializes trusted sparse MAST replay bytes using default parse budgets.
    ///
    /// This reader bounds parsing, but accepts sparse MAST hashes from the payload.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from_bytes_with_options(bytes, SparseMastForestReadOptions::default())
    }

    /// Deserializes trusted sparse MAST replay bytes using explicit read options.
    ///
    /// See <https://github.com/0xMiden/miden-vm/issues/3303> for the planned untrusted reader.
    pub fn read_from_bytes_with_options(
        bytes: &[u8],
        options: SparseMastForestReadOptions,
    ) -> Result<Self, DeserializationError> {
        let wire_byte_budget = options.wire_byte_budget(bytes.len());
        if wire_byte_budget < bytes.len() {
            return Err(DeserializationError::InvalidValue(
                "SparseMastForest wire byte budget is smaller than payload length".to_string(),
            ));
        }
        let allocation_budget = wire_byte_budget.min(bytes.len().saturating_mul(4));
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), allocation_budget);
        let forest = read_sparse_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after SparseMastForest payload".to_string(),
            ));
        }
        Ok(forest)
    }
}

/// Options for reading a [`SparseMastForest`] from bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SparseMastForestReadOptions {
    wire_byte_budget: Option<usize>,
}

impl SparseMastForestReadOptions {
    /// Creates options that use the default sparse read budgets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of serialized bytes consumed while parsing wire data.
    pub fn with_wire_byte_budget(mut self, budget: usize) -> Self {
        self.wire_byte_budget = Some(budget);
        self
    }

    fn wire_byte_budget(self, bytes_len: usize) -> usize {
        self.wire_byte_budget.unwrap_or(bytes_len)
    }
}
