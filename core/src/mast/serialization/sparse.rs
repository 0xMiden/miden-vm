use alloc::{collections::BTreeMap, format, string::ToString, vec::Vec};

use super::basic_blocks::{BasicBlockDataBuilder, BasicBlockDataDecoder};
use crate::{
    Word,
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForestContributor, MastNode, MastNodeExt, MastNodeId,
        SparseMastForest, SplitNodeBuilder,
    },
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

const SPARSE_BLOCK: u8 = 0;
const SPARSE_JOIN: u8 = 1;
const SPARSE_SPLIT: u8 = 2;
const SPARSE_LOOP: u8 = 3;
const SPARSE_CALL: u8 = 4;
const SPARSE_SYSCALL: u8 = 5;
const SPARSE_DYN: u8 = 6;
const SPARSE_DYNCALL: u8 = 7;
const SPARSE_EXTERNAL: u8 = 8;

// WRITER
// ================================================================================================

/// Writes trusted sparse trace replay data.
///
/// This format preserves the sparse maps produced by execution tracing. It does not prove that
/// this sparse view is a subset of a committed [`MastForest`], and it does not share the dense
/// [`MastForest`] wire format. Callers must only read these bytes from a trusted producer, or after
/// an outer transport/authentication layer has accepted them.
fn write_sparse_into<W: ByteWriter>(forest: &SparseMastForest, target: &mut W) {
    forest.num_nodes().write_into(target);
    write_node_ids(forest.procedure_roots(), target);
    write_sparse_nodes(forest.nodes(), target);
    write_digest_entries(forest.digest_entries(), target);
    forest.advice_map().write_into(target);
}

fn write_node_ids<W: ByteWriter>(ids: &[MastNodeId], target: &mut W) {
    target.write_usize(ids.len());
    for id in ids {
        id.write_into(target);
    }
}

fn write_sparse_nodes<W: ByteWriter>(nodes: &BTreeMap<MastNodeId, MastNode>, target: &mut W) {
    target.write_usize(nodes.len());
    for (&id, node) in nodes {
        id.write_into(target);
        write_sparse_node(node, target);
    }
}

fn write_digest_entries<W: ByteWriter>(digests: &BTreeMap<MastNodeId, Word>, target: &mut W) {
    target.write_usize(digests.len());
    for (&id, &digest) in digests {
        id.write_into(target);
        digest.write_into(target);
    }
}

fn write_sparse_node<W: ByteWriter>(node: &MastNode, target: &mut W) {
    match node {
        MastNode::Block(block) => {
            target.write_u8(SPARSE_BLOCK);
            node.digest().write_into(target);

            let mut basic_block_data = BasicBlockDataBuilder::new();
            let ops_offset = basic_block_data.encode_basic_block(block);
            debug_assert_eq!(ops_offset, 0);
            let basic_block_data = basic_block_data.finalize();
            target.write_usize(basic_block_data.len());
            target.write_bytes(&basic_block_data);
        },
        MastNode::Join(join) => {
            target.write_u8(SPARSE_JOIN);
            node.digest().write_into(target);
            join.first().write_into(target);
            join.second().write_into(target);
        },
        MastNode::Split(split) => {
            target.write_u8(SPARSE_SPLIT);
            node.digest().write_into(target);
            split.on_true().write_into(target);
            split.on_false().write_into(target);
        },
        MastNode::Loop(loop_node) => {
            target.write_u8(SPARSE_LOOP);
            node.digest().write_into(target);
            loop_node.body().write_into(target);
        },
        MastNode::Call(call) => {
            target.write_u8(if call.is_syscall() { SPARSE_SYSCALL } else { SPARSE_CALL });
            node.digest().write_into(target);
            call.callee().write_into(target);
        },
        MastNode::Dyn(dyn_node) => {
            target.write_u8(if dyn_node.is_dyncall() {
                SPARSE_DYNCALL
            } else {
                SPARSE_DYN
            });
            node.digest().write_into(target);
        },
        MastNode::External(_) => {
            target.write_u8(SPARSE_EXTERNAL);
            node.digest().write_into(target);
        },
    }
}

// TRAIT IMPLS
// ================================================================================================

impl Serializable for SparseMastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_sparse_into(self, target);
    }
}

impl Deserializable for SparseMastForest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_sparse_from(source)
    }

    fn min_serialized_size() -> usize {
        usize::min_serialized_size()
    }

    /// Reads one trusted sparse replay payload and rejects trailing bytes.
    ///
    /// This is not an untrusted input format. The reader performs cheap structural checks, but a
    /// producer controls collection lengths and can drive allocation. Callers must only read these
    /// bytes from a trusted producer, or after an outer transport/authentication layer has accepted
    /// them.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = SliceReader::new(bytes);
        let forest = read_sparse_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after SparseMastForest payload".to_string(),
            ));
        }
        Ok(forest)
    }
}

// READER
// ================================================================================================

fn read_sparse_from<R: ByteReader>(
    source: &mut R,
) -> Result<SparseMastForest, DeserializationError> {
    let source_node_count = source.read_usize()?;
    let roots = read_node_ids(source, source_node_count, "procedure root")?;
    let nodes = read_sparse_nodes(source, source_node_count)?;
    let digest_entries = read_digest_entries(source, source_node_count)?;
    let advice_map = AdviceMap::read_from(source)?;

    SparseMastForest::from_serialized_parts(
        nodes,
        digest_entries,
        source_node_count,
        roots,
        advice_map,
    )
}

fn read_node_ids<R: ByteReader>(
    source: &mut R,
    source_node_count: usize,
    label: &str,
) -> Result<Vec<MastNodeId>, DeserializationError> {
    let count = read_bounded_count(source, u32::min_serialized_size(), label)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(read_node_id(source, source_node_count, label)?);
    }
    Ok(ids)
}

fn read_sparse_nodes<R: ByteReader>(
    source: &mut R,
    source_node_count: usize,
) -> Result<Vec<(MastNodeId, MastNode)>, DeserializationError> {
    let count = read_bounded_count(source, sparse_node_min_size(), "full node count")?;
    let mut nodes = Vec::with_capacity(count);
    let mut previous_id = None;

    for _ in 0..count {
        let id = read_node_id(source, source_node_count, "full node")?;
        validate_strictly_increasing_id(previous_id, id, "full node")?;
        let node = read_sparse_node(source, source_node_count, id)?;
        nodes.push((id, node));
        previous_id = Some(id);
    }

    Ok(nodes)
}

fn read_digest_entries<R: ByteReader>(
    source: &mut R,
    source_node_count: usize,
) -> Result<Vec<(MastNodeId, Word)>, DeserializationError> {
    let count =
        read_bounded_count(source, sparse_digest_entry_min_size(), "digest-only node count")?;
    let mut digests = Vec::with_capacity(count);
    let mut previous_id = None;

    for _ in 0..count {
        let id = read_node_id(source, source_node_count, "digest-only node")?;
        validate_strictly_increasing_id(previous_id, id, "digest-only node")?;
        let digest = Word::read_from(source)?;
        digests.push((id, digest));
        previous_id = Some(id);
    }

    Ok(digests)
}

fn read_sparse_node<R: ByteReader>(
    source: &mut R,
    source_node_count: usize,
    node_id: MastNodeId,
) -> Result<MastNode, DeserializationError> {
    let tag = source.read_u8()?;
    let digest = Word::read_from(source)?;

    let result = match tag {
        SPARSE_BLOCK => {
            let len = read_bounded_count(source, 1, "basic block data length")?;
            let data = source.read_vec(len)?;
            let decoder = BasicBlockDataDecoder::new(&data);
            let op_batches = decoder.decode_operations(0)?;
            BasicBlockNodeBuilder::from_op_batches(op_batches, digest)
                .build()
                .map(Into::into)
        },
        SPARSE_JOIN => {
            let first = read_node_id(source, source_node_count, "join first child")?;
            let second = read_node_id(source, source_node_count, "join second child")?;
            JoinNodeBuilder::new([first, second])
                .with_digest(digest)
                .build_linked()
                .map(Into::into)
        },
        SPARSE_SPLIT => {
            let on_true = read_node_id(source, source_node_count, "split true child")?;
            let on_false = read_node_id(source, source_node_count, "split false child")?;
            SplitNodeBuilder::new([on_true, on_false])
                .with_digest(digest)
                .build_linked()
                .map(Into::into)
        },
        SPARSE_LOOP => {
            let body = read_node_id(source, source_node_count, "loop body")?;
            LoopNodeBuilder::new(body).with_digest(digest).build_linked().map(Into::into)
        },
        SPARSE_CALL | SPARSE_SYSCALL => {
            let callee = read_node_id(source, source_node_count, "call callee")?;
            let builder = if tag == SPARSE_SYSCALL {
                CallNodeBuilder::new_syscall(callee)
            } else {
                CallNodeBuilder::new(callee)
            };
            builder.with_digest(digest).build_linked().map(Into::into)
        },
        SPARSE_DYN | SPARSE_DYNCALL => {
            let builder = if tag == SPARSE_DYNCALL {
                DynNodeBuilder::new_dyncall()
            } else {
                DynNodeBuilder::new_dyn()
            };
            Ok(builder.with_digest(digest).build().into())
        },
        SPARSE_EXTERNAL => Ok(ExternalNodeBuilder::new(digest).build().into()),
        _ => {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid sparse MAST node tag {tag}"
            )));
        },
    };

    result.map_err(|err| {
        DeserializationError::InvalidValue(format!(
            "failed to build sparse MAST node {}: {}",
            node_id.0, err
        ))
    })
}

fn read_bounded_count<R: ByteReader>(
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

fn sparse_node_min_size() -> usize {
    u32::min_serialized_size() + u8::min_serialized_size() + Word::min_serialized_size()
}

fn sparse_digest_entry_min_size() -> usize {
    u32::min_serialized_size() + Word::min_serialized_size()
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

fn validate_strictly_increasing_id(
    previous: Option<MastNodeId>,
    current: MastNodeId,
    label: &str,
) -> Result<(), DeserializationError> {
    if previous.is_some_and(|previous| previous >= current) {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} ids must be strictly increasing"
        )));
    }
    Ok(())
}
