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
/// table. External nodes always read from the external-digest prefix section.
#[derive(Debug, Clone)]
struct ForestDigests {
    /// Source of non-external digests.
    ///
    /// `None` means the serialized bytes still contain the internal node-hash section, so
    /// lookups read directly from the wire. `Some(...)` means the payload was hashless and the
    /// non-external digests have been recomputed once into this cache.
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
    /// Resolves how later digest lookups will be served for a parsed serialized forest.
    ///
    /// `bytes` and `layout` provide the already-scanned structural wire view. When
    /// `remaining_allocation_budget` is `Some`, helper allocations needed for untrusted validation
    /// such as the rebuilt hash table are charged against that budget. Trusted
    /// structural views pass `None` here, which keeps the previous unbudgeted inspection behavior.
    fn new(
        bytes: &[u8],
        layout: &ForestLayout,
        remaining_allocation_budget: Option<&mut usize>,
    ) -> Result<Self, DeserializationError> {
        // If the internal-hash section is absent, rebuild all non-external digests once and cache
        // them for later lookups.
        let hash_table = if layout.node_hash_offset.is_none() {
            Some(recompute_hash_table(bytes, layout, remaining_allocation_budget)?)
        } else {
            None
        };

        Ok(Self { hash_table })
    }

    fn digest_at(
        &self,
        bytes: &[u8],
        layout: &ForestLayout,
        index: usize,
        entry: MastNodeEntry,
    ) -> Result<crate::Word, DeserializationError> {
        if matches!(entry, MastNodeEntry::External) {
            if index >= layout.external_node_count {
                return Err(DeserializationError::InvalidValue(format!(
                    "external node index {} out of bounds for {} external digests",
                    index, layout.external_node_count
                )));
            }
            return read_digest_entry(bytes, layout.external_digest_offset, index);
        }

        if let Some(hash_table) = &self.hash_table {
            return hash_table.get(index).copied().ok_or_else(|| {
                DeserializationError::InvalidValue(format!(
                    "node index {} out of bounds for {} rebuilt digests",
                    index,
                    hash_table.len()
                ))
            });
        }

        let node_hash_offset = layout.node_hash_offset.ok_or_else(|| {
            DeserializationError::InvalidValue(
                "hash-backed digest lookup requested but node hash section is absent".to_string(),
            )
        })?;
        let digest_slot = index.checked_sub(layout.external_node_count).ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "internal node index {} must be at least {}",
                index, layout.external_node_count
            ))
        })?;
        if digest_slot >= layout.internal_node_count {
            return Err(DeserializationError::InvalidValue(format!(
                "internal digest slot {} out of bounds for {} internal digests",
                digest_slot, layout.internal_node_count
            )));
        }
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

    /// Returns the digest for the node at `index`.
    ///
    /// The caller-supplied index is checked via [`Self::node_entry_at`] before the digest lookup
    /// reaches the digest source selected for that node kind.
    pub(super) fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        let entry = self.node_entry_at(index)?;
        self.node_digest_for_entry(index, entry)
    }

    /// Returns the digest for a node whose entry was already read and bounds-checked by the caller.
    fn node_digest_for_entry(
        &self,
        index: usize,
        entry: MastNodeEntry,
    ) -> Result<crate::Word, DeserializationError> {
        self.digests.digest_at(self.bytes, &self.layout, index, entry)
    }

    #[cfg(test)]
    pub(super) fn digest_slot_at(&self, index: usize) -> usize {
        if index < self.layout.external_node_count {
            index
        } else {
            index - self.layout.external_node_count
        }
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
    // Layout scanning already established the coarse section boundaries. This helper keeps the
    // consumer-side slice extraction explicit and local to the basic-block decoder path.
    let end = basic_block_offset.checked_add(basic_block_len).ok_or_else(|| {
        DeserializationError::InvalidValue("basic-block data overflow".to_string())
    })?;
    if end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }
    Ok(&bytes[basic_block_offset..end])
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
                read_digest_entry(bytes, layout.external_digest_offset, index)?
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
            "child id {child_id} out of bounds for {node_count} nodes"
        )));
    }
    if child_index >= parent_index {
        return Err(DeserializationError::InvalidValue(format!(
            "forward reference from node {parent_index} to {child_id} (child index must be less than parent)"
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
