use alloc::{string::ToString, vec::Vec};

use super::{AdviceMap, ForestLayout, MastForest, MastNodeEntry, MastNodeId, basic_block_data_len};
use crate::{
    Felt,
    chiplets::hasher,
    mast::{
        CallNode, DebugInfo, DynNode, JoinNode, LoopNode, SplitNode,
        serialization::{basic_blocks::BasicBlockDataDecoder, info::MastNodeType},
    },
    serde::{Deserializable, DeserializationError, SliceReader},
};

#[derive(Debug, Clone)]
struct ForestDigests {
    slot_by_node: Vec<u32>,
    hash_table: Option<Vec<crate::Word>>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedSerializedForest<'a> {
    bytes: &'a [u8],
    layout: ForestLayout,
    digests: ForestDigests,
}

impl ForestDigests {
    fn new(bytes: &[u8], layout: &ForestLayout) -> Result<Self, DeserializationError> {
        let slot_by_node = build_digest_slot_by_node(bytes, layout)?;
        let hash_table = if layout.node_hash_offset.is_none() {
            Some(recompute_hash_table(bytes, layout)?)
        } else {
            None
        };

        Ok(Self { slot_by_node, hash_table })
    }

    fn digest_at(
        &self,
        bytes: &[u8],
        layout: &ForestLayout,
        index: usize,
        entry: MastNodeEntry,
    ) -> Result<crate::Word, DeserializationError> {
        let digest_slot = self.slot_by_node[index] as usize;

        if matches!(entry.node_type(), MastNodeType::External) {
            return read_digest_entry(bytes, layout.external_digest_offset, digest_slot);
        }

        if let Some(hash_table) = &self.hash_table {
            return Ok(hash_table[index]);
        }

        let node_hash_offset = layout.node_hash_offset.ok_or_else(|| {
            DeserializationError::InvalidValue(
                "hash-backed digest lookup requested but node hash section is absent".to_string(),
            )
        })?;
        read_digest_entry(bytes, node_hash_offset, digest_slot)
    }
}

impl<'a> ResolvedSerializedForest<'a> {
    pub(super) fn new(bytes: &'a [u8], layout: ForestLayout) -> Result<Self, DeserializationError> {
        let layout = layout.resolve()?;
        let digests = ForestDigests::new(bytes, &layout)?;
        Ok(Self { bytes, layout, digests })
    }

    pub(super) fn materialize(
        &self,
        advice_map: AdviceMap,
        debug_info: DebugInfo,
    ) -> Result<MastForest, DeserializationError> {
        let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data(
            self.bytes,
            self.layout.basic_block_offset,
            self.layout.basic_block_len,
        )?);
        let mut mast_forest = MastForest::new();
        mast_forest.debug_info = debug_info;

        for index in 0..self.node_count() {
            let entry = self.node_entry_at(index)?;
            let digest = self.node_digest_for_entry(index, entry)?;

            let mast_node_builder = entry.try_into_mast_node_builder(
                self.node_count(),
                &basic_block_data_decoder,
                digest,
            )?;
            mast_node_builder.add_to_forest_relaxed(&mut mast_forest).map_err(|e| {
                DeserializationError::InvalidValue(format!(
                    "failed to add node to MAST forest while deserializing: {e}",
                ))
            })?;
        }

        for index in 0..self.procedure_root_count() {
            mast_forest.make_root(self.procedure_root_at(index)?);
        }

        mast_forest.advice_map = advice_map;
        Ok(mast_forest)
    }

    pub(super) fn node_count(&self) -> usize {
        self.layout.node_count
    }

    pub(super) fn procedure_root_count(&self) -> usize {
        self.layout.roots_count
    }

    pub(super) fn procedure_root_at(
        &self,
        index: usize,
    ) -> Result<MastNodeId, DeserializationError> {
        if index >= self.layout.roots_count {
            return Err(DeserializationError::InvalidValue(format!(
                "root index {} out of bounds for {} roots",
                index, self.layout.roots_count
            )));
        }

        let mut raw = [0u8; core::mem::size_of::<u32>()];
        raw.copy_from_slice(read_fixed_section_entry(
            self.bytes,
            self.layout.roots_offset,
            core::mem::size_of::<u32>(),
            index,
            "root",
        )?);
        MastNodeId::from_u32_with_node_count(u32::from_le_bytes(raw), self.layout.node_count)
    }

    pub(super) fn node_entry_at(
        &self,
        index: usize,
    ) -> Result<MastNodeEntry, DeserializationError> {
        if index >= self.layout.node_count {
            return Err(DeserializationError::InvalidValue(format!(
                "node index {} out of bounds for {} nodes",
                index, self.layout.node_count
            )));
        }

        read_node_entry(
            self.bytes,
            self.layout.node_entry_offset,
            self.layout.node_entry_size,
            index,
        )
    }

    pub(super) fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        let entry = self.node_entry_at(index)?;
        self.node_digest_for_entry(index, entry)
    }

    fn node_digest_for_entry(
        &self,
        index: usize,
        entry: MastNodeEntry,
    ) -> Result<crate::Word, DeserializationError> {
        self.digests.digest_at(self.bytes, &self.layout, index, entry)
    }

    #[cfg(test)]
    pub(super) fn advice_map_offset(&self) -> Result<usize, DeserializationError> {
        let digest_section_end = if let Some(node_hash_offset) = self.layout.node_hash_offset {
            node_hash_offset
                .checked_add(self.layout.node_hash_count * crate::Word::min_serialized_size())
                .ok_or_else(|| {
                    DeserializationError::InvalidValue("node hash section overflow".to_string())
                })?
        } else {
            self.layout
                .external_digest_offset
                .checked_add(self.layout.external_digest_count * crate::Word::min_serialized_size())
                .ok_or_else(|| {
                    DeserializationError::InvalidValue(
                        "external digest section overflow".to_string(),
                    )
                })?
        };

        if digest_section_end > self.bytes.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        Ok(digest_section_end)
    }

    #[cfg(test)]
    pub(super) fn node_entry_offset(&self) -> usize {
        self.layout.node_entry_offset
    }

    #[cfg(test)]
    pub(super) fn node_hash_offset(&self) -> Option<usize> {
        self.layout.node_hash_offset
    }

    #[cfg(test)]
    pub(super) fn digest_slot_at(&self, index: usize) -> usize {
        self.digests.slot_by_node[index] as usize
    }
}

fn read_node_entry(
    bytes: &[u8],
    node_entry_offset: usize,
    node_entry_size: usize,
    index: usize,
) -> Result<MastNodeEntry, DeserializationError> {
    let mut reader = SliceReader::new(read_fixed_section_entry(
        bytes,
        node_entry_offset,
        node_entry_size,
        index,
        "node entry",
    )?);
    MastNodeEntry::read_from(&mut reader)
}

fn read_digest_entry(
    bytes: &[u8],
    digest_section_offset: usize,
    index: usize,
) -> Result<crate::Word, DeserializationError> {
    let mut reader = SliceReader::new(read_fixed_section_entry(
        bytes,
        digest_section_offset,
        crate::Word::min_serialized_size(),
        index,
        "digest",
    )?);
    crate::Word::read_from(&mut reader)
}

fn read_fixed_section_entry<'a>(
    bytes: &'a [u8],
    section_offset: usize,
    entry_size: usize,
    index: usize,
    section_name: &str,
) -> Result<&'a [u8], DeserializationError> {
    let entry_offset = index
        .checked_mul(entry_size)
        .and_then(|delta| section_offset.checked_add(delta))
        .ok_or_else(|| {
            DeserializationError::InvalidValue(format!("{section_name} offset overflow"))
        })?;
    let entry_end = entry_offset.checked_add(entry_size).ok_or_else(|| {
        DeserializationError::InvalidValue(format!("{section_name} length overflow"))
    })?;
    if entry_end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }

    Ok(&bytes[entry_offset..entry_end])
}

fn basic_block_data(
    bytes: &[u8],
    basic_block_offset: usize,
    basic_block_len: usize,
) -> Result<&[u8], DeserializationError> {
    let end = basic_block_offset.checked_add(basic_block_len).ok_or_else(|| {
        DeserializationError::InvalidValue("basic-block data overflow".to_string())
    })?;
    if end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }
    Ok(&bytes[basic_block_offset..end])
}

fn build_digest_slot_by_node(
    bytes: &[u8],
    layout: &ForestLayout,
) -> Result<Vec<u32>, DeserializationError> {
    let mut slots = Vec::with_capacity(layout.node_count);
    let mut external_slot = 0u32;
    let mut node_hash_slot = 0u32;

    for index in 0..layout.node_count {
        let entry =
            read_node_entry(bytes, layout.node_entry_offset, layout.node_entry_size, index)?;
        if matches!(entry.node_type(), MastNodeType::External) {
            slots.push(external_slot);
            external_slot = external_slot.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("external digest slot overflow".to_string())
            })?;
        } else {
            slots.push(node_hash_slot);
            node_hash_slot = node_hash_slot.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("node hash slot overflow".to_string())
            })?;
        }
    }

    Ok(slots)
}

fn recompute_hash_table(
    bytes: &[u8],
    layout: &ForestLayout,
) -> Result<Vec<crate::Word>, DeserializationError> {
    let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data(
        bytes,
        layout.basic_block_offset,
        layout.basic_block_len,
    )?);

    let mut digests = Vec::with_capacity(layout.node_count);
    let mut external_digest_index = 0usize;

    for index in 0..layout.node_count {
        let entry =
            read_node_entry(bytes, layout.node_entry_offset, layout.node_entry_size, index)?;
        let computed = match entry.node_type() {
            MastNodeType::Block { ops_offset } => {
                let op_batches = basic_block_data_decoder.decode_operations(ops_offset)?;
                let op_groups: Vec<Felt> =
                    op_batches.iter().flat_map(|batch| *batch.groups()).collect();
                hasher::hash_elements(&op_groups)
            },
            MastNodeType::Join { left_child_id, right_child_id } => {
                let left = checked_child_index(index, left_child_id, layout.node_count)?;
                let right = checked_child_index(index, right_child_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[left], digests[right]], JoinNode::DOMAIN)
            },
            MastNodeType::Split { if_branch_id, else_branch_id } => {
                let on_true = checked_child_index(index, if_branch_id, layout.node_count)?;
                let on_false = checked_child_index(index, else_branch_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[on_true], digests[on_false]], SplitNode::DOMAIN)
            },
            MastNodeType::Loop { body_id } => {
                let body = checked_child_index(index, body_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[body], crate::Word::default()], LoopNode::DOMAIN)
            },
            MastNodeType::Call { callee_id } => {
                let callee = checked_child_index(index, callee_id, layout.node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::CALL_DOMAIN,
                )
            },
            MastNodeType::SysCall { callee_id } => {
                let callee = checked_child_index(index, callee_id, layout.node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::SYSCALL_DOMAIN,
                )
            },
            MastNodeType::Dyn => DynNode::DYN_DEFAULT_DIGEST,
            MastNodeType::Dyncall => DynNode::DYNCALL_DEFAULT_DIGEST,
            MastNodeType::External => {
                let digest =
                    read_digest_entry(bytes, layout.external_digest_offset, external_digest_index)?;
                external_digest_index = external_digest_index.checked_add(1).ok_or_else(|| {
                    DeserializationError::InvalidValue("external digest index overflow".to_string())
                })?;
                digest
            },
        };

        digests.push(computed);
    }

    Ok(digests)
}

fn checked_child_index(
    parent_index: usize,
    child_id: u32,
    node_count: usize,
) -> Result<usize, DeserializationError> {
    let child_index = child_id as usize;
    if child_index >= node_count {
        return Err(DeserializationError::InvalidValue(format!(
            "child id {} out of bounds for {} nodes",
            child_id, node_count
        )));
    }
    if child_index >= parent_index {
        return Err(DeserializationError::InvalidValue(format!(
            "forward reference from node {} to {} (child index must be less than parent)",
            parent_index, child_id
        )));
    }
    Ok(child_index)
}

pub(super) fn basic_block_offset_for_node_index(
    nodes: &[super::MastNode],
    node_index: usize,
) -> Result<u32, DeserializationError> {
    let mut offset = 0usize;
    for node in nodes.iter().take(node_index) {
        if let super::MastNode::Block(block) = node {
            offset = offset.checked_add(basic_block_data_len(block)).ok_or_else(|| {
                DeserializationError::InvalidValue("basic-block data offset overflow".to_string())
            })?;
        }
    }

    offset.try_into().map_err(|_| {
        DeserializationError::InvalidValue(
            "basic-block data offset does not fit in u32".to_string(),
        )
    })
}
