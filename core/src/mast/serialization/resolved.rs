use alloc::{format, string::ToString, vec::Vec};

use super::{
    AdviceMap, ForestLayout, MastForest, MastNodeEntry, MastNodeId, basic_block_data_len,
    reserve_allocation,
};
use crate::{
    Felt,
    chiplets::hasher,
    mast::{
        CallNode, DebugInfo, DynNode, JoinNode, LoopNode, SplitNode,
        serialization::{basic_blocks::BasicBlockDataDecoder, layout::read_fixed_section_entry},
    },
    serde::{Deserializable, DeserializationError, SliceReader},
};

/// Digest sources for a parsed serialized forest.
///
/// Non-external nodes either read from the internal-hash section or from a rebuilt in-memory hash
/// table. External nodes always read from the external-digest section.
#[derive(Debug, Clone)]
struct ForestDigests {
    /// Dense slot index for each node within its digest section.
    ///
    /// External nodes index into the external-digest section. All other nodes index into the
    /// general node-hash section or the rebuilt hash table.
    slot_by_node: Vec<u32>,
    hash_table: Option<Vec<crate::Word>>,
}

/// A serialized forest whose digest source has been resolved.
///
/// This is the elaborated layer between raw wire layout and a fully materialized [`MastForest`].
/// It combines structural access from [`ForestLayout`] with digest access from either wire sections
/// or a rebuilt in-memory hash table.
#[derive(Debug, Clone)]
pub(super) struct ResolvedSerializedForest<'a> {
    bytes: &'a [u8],
    layout: ForestLayout,
    digests: ForestDigests,
}

impl ForestDigests {
    fn new(
        bytes: &[u8],
        layout: &ForestLayout,
        mut remaining_allocation_budget: Option<&mut usize>,
    ) -> Result<Self, DeserializationError> {
        let slot_by_node =
            build_digest_slot_by_node(bytes, layout, remaining_allocation_budget.as_deref_mut())?;
        // If the internal-hash section is absent, rebuild all non-external digests once and cache
        // them for later lookups.
        let hash_table = if layout.node_hash_offset.is_none() {
            Some(recompute_hash_table(bytes, layout, remaining_allocation_budget)?)
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

        if matches!(entry, MastNodeEntry::External) {
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
    /// Resolves digest access for a parsed serialized forest.
    pub(super) fn new(bytes: &'a [u8], layout: ForestLayout) -> Result<Self, DeserializationError> {
        let digests = ForestDigests::new(bytes, &layout, None)?;
        Ok(Self { bytes, layout, digests })
    }

    /// Resolves digest access for a parsed serialized forest while charging helper allocations
    /// against an explicit untrusted validation budget.
    pub(super) fn new_with_allocation_budget(
        bytes: &'a [u8],
        layout: ForestLayout,
        mut allocation_budget: usize,
    ) -> Result<Self, DeserializationError> {
        let digests = ForestDigests::new(bytes, &layout, Some(&mut allocation_budget))?;
        Ok(Self { bytes, layout, digests })
    }

    /// Materializes a full [`MastForest`] from the serialized structure and resolved digests.
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
        self.layout.read_procedure_root_at(self.bytes, index)
    }

    pub(super) fn node_entry_at(
        &self,
        index: usize,
    ) -> Result<MastNodeEntry, DeserializationError> {
        self.layout.read_node_entry_at(self.bytes, index)
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
    pub(super) fn digest_slot_at(&self, index: usize) -> usize {
        self.digests.slot_by_node[index] as usize
    }
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
    remaining_allocation_budget: Option<&mut usize>,
) -> Result<Vec<u32>, DeserializationError> {
    // Digest sections are packed densely by node kind rather than by absolute node index.
    // This scan records, for each node index, which slot to read from in the corresponding digest
    // source.
    let mut slots = Vec::new();
    reserve_node_capacity(
        &mut slots,
        layout.node_count,
        "digest slot table",
        remaining_allocation_budget,
    )?;
    let mut external_slot = 0u32;
    let mut node_hash_slot = 0u32;

    for index in 0..layout.node_count {
        let entry = layout.read_node_entry_at(bytes, index)?;
        if matches!(entry, MastNodeEntry::External) {
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
    remaining_allocation_budget: Option<&mut usize>,
) -> Result<Vec<crate::Word>, DeserializationError> {
    let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data(
        bytes,
        layout.basic_block_offset,
        layout.basic_block_len,
    )?);

    let mut digests = Vec::new();
    reserve_node_capacity(
        &mut digests,
        layout.node_count,
        "hash table",
        remaining_allocation_budget,
    )?;
    let mut external_digest_index = 0usize;

    for index in 0..layout.node_count {
        let entry = layout.read_node_entry_at(bytes, index)?;
        let computed = match entry {
            MastNodeEntry::Block { ops_offset } => {
                let op_batches = basic_block_data_decoder.decode_operations(ops_offset)?;
                let op_groups: Vec<Felt> =
                    op_batches.iter().flat_map(|batch| *batch.groups()).collect();
                hasher::hash_elements(&op_groups)
            },
            MastNodeEntry::Join { left_child_id, right_child_id } => {
                let left = checked_child_index(index, left_child_id, layout.node_count)?;
                let right = checked_child_index(index, right_child_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[left], digests[right]], JoinNode::DOMAIN)
            },
            MastNodeEntry::Split { if_branch_id, else_branch_id } => {
                let on_true = checked_child_index(index, if_branch_id, layout.node_count)?;
                let on_false = checked_child_index(index, else_branch_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[on_true], digests[on_false]], SplitNode::DOMAIN)
            },
            MastNodeEntry::Loop { body_id } => {
                let body = checked_child_index(index, body_id, layout.node_count)?;
                hasher::merge_in_domain(&[digests[body], crate::Word::default()], LoopNode::DOMAIN)
            },
            MastNodeEntry::Call { callee_id } => {
                let callee = checked_child_index(index, callee_id, layout.node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::CALL_DOMAIN,
                )
            },
            MastNodeEntry::SysCall { callee_id } => {
                let callee = checked_child_index(index, callee_id, layout.node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::SYSCALL_DOMAIN,
                )
            },
            MastNodeEntry::Dyn => DynNode::DYN_DEFAULT_DIGEST,
            MastNodeEntry::Dyncall => DynNode::DYNCALL_DEFAULT_DIGEST,
            MastNodeEntry::External => {
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

fn reserve_node_capacity<T>(
    values: &mut Vec<T>,
    node_count: usize,
    label: &str,
    remaining_allocation_budget: Option<&mut usize>,
) -> Result<(), DeserializationError> {
    if let Some(allocation_budget) = remaining_allocation_budget {
        reserve_allocation::<T>(allocation_budget, node_count, label)?;
    }
    values.try_reserve_exact(node_count).map_err(|err| {
        DeserializationError::InvalidValue(format!(
            "failed to reserve {label} for {node_count} nodes: {err}",
        ))
    })
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
