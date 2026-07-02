use alloc::{format, string::ToString, vec::Vec};

use super::{
    AdviceMap, ForestLayout, MastForest, MastNodeEntry, MastNodeId, basic_block_data_len,
    reserve_allocation,
};
use crate::{
    Felt,
    chiplets::hasher,
    mast::{
        CallNode, DynNode, JoinNode, LoopNode, MastForestParts, MastNode, SplitNode,
        serialization::{basic_blocks::BasicBlockDataDecoder, layout::read_fixed_section_entry},
    },
    serde::{Deserializable, DeserializationError, SliceReader},
    utils::{Idx, IndexVec},
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
        mut remaining_allocation_budget: Option<&mut usize>,
    ) -> Result<Self, DeserializationError> {
        let slot_by_node =
            build_digest_slot_by_node(bytes, layout, remaining_allocation_budget.as_deref_mut())?;
        // If the internal-hash section is absent, rebuild all non-external digests once and cache
        // them for later lookups.
        let hash_table = if layout.node_hash_offset().is_none() {
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
        let digest_slot = self.slot_by_node.get(index).copied().ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "node index {} out of bounds for {} digest slots",
                index,
                self.slot_by_node.len()
            ))
        })? as usize;

        if matches!(entry, MastNodeEntry::External) {
            return read_digest_entry(bytes, layout.external_digest_offset(), digest_slot);
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

        let node_hash_offset = layout.node_hash_offset().ok_or_else(|| {
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
    ) -> Result<MastForest, DeserializationError> {
        let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data(
            self.bytes,
            self.layout.basic_block_offset(),
            self.layout.basic_block_len(),
        )?);
        let mut nodes = IndexVec::<MastNodeId, MastNode>::with_capacity(self.node_count());

        for index in 0..self.node_count() {
            let entry = self.node_entry_at(index)?;
            let digest = self.node_digest_for_entry(index, entry)?;

            let mast_node_builder = entry.try_into_mast_node_builder(
                self.node_count(),
                &basic_block_data_decoder,
                digest,
            )?;
            let node = mast_node_builder.build_linked().map_err(|e| {
                DeserializationError::InvalidValue(format!(
                    "failed to build node while deserializing MAST forest: {e}",
                ))
            })?;
            nodes.push(node).map_err(|_| {
                DeserializationError::InvalidValue(
                    "too many nodes while deserializing MAST forest".into(),
                )
            })?;
        }

        let mut roots = Vec::with_capacity(self.procedure_root_count());
        for index in 0..self.procedure_root_count() {
            roots.push(self.procedure_root_at(index)?);
        }

        MastForest::from_trusted_deserialization_parts(MastForestParts { nodes, roots, advice_map })
            .map_err(|e| {
                DeserializationError::InvalidValue(format!(
                    "failed to construct trusted deserialized MAST forest: {e}",
                ))
            })
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
    /// reaches the internal slot table.
    pub(super) fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        let entry = self.node_entry_at(index)?;
        self.node_digest_for_entry(index, entry)
    }

    pub(super) fn validate_commitment_input_sections(&self) -> Result<(), DeserializationError> {
        self.validate_root_commitment_input_section()?;
        self.validate_dependency_commitment_input_section()
    }

    fn validate_root_commitment_input_section(&self) -> Result<(), DeserializationError> {
        let mut expected_root_digests = Vec::with_capacity(self.procedure_root_count());
        for index in 0..self.procedure_root_count() {
            let root_id = self.procedure_root_at(index)?;
            expected_root_digests.push(self.node_digest_at(root_id.to_usize())?);
        }
        expected_root_digests.sort_unstable();

        let mut previous_root_digest = None;
        for (index, expected_digest) in expected_root_digests.into_iter().enumerate() {
            let actual_digest =
                read_digest_entry(self.bytes, self.layout.root_commitment_digest_offset(), index)?;
            validate_strictly_increasing_digest(
                previous_root_digest,
                actual_digest,
                "root commitment digest",
            )?;
            if actual_digest != expected_digest {
                return Err(DeserializationError::InvalidValue(format!(
                    "root commitment digest {index} does not match the serialized forest"
                )));
            }
            previous_root_digest = Some(actual_digest);
        }

        Ok(())
    }

    fn validate_dependency_commitment_input_section(&self) -> Result<(), DeserializationError> {
        let mut previous_dependency_digest = None;
        for index in 0..self.layout.external_node_count {
            let entry = self.node_entry_at(index)?;
            debug_assert!(matches!(entry, MastNodeEntry::External));
            let expected_digest = self.node_digest_for_entry(index, entry)?;
            let actual_digest = read_digest_entry(
                self.bytes,
                self.layout.dependency_commitment_digest_offset(),
                index,
            )?;
            validate_strictly_increasing_digest(
                previous_dependency_digest,
                actual_digest,
                "dependency commitment digest",
            )?;
            if actual_digest != expected_digest {
                return Err(DeserializationError::InvalidValue(format!(
                    "dependency commitment digest {index} does not match the serialized forest"
                )));
            }
            previous_dependency_digest = Some(actual_digest);
        }

        Ok(())
    }

    #[cfg(test)]
    pub(super) fn digest_slot_at(&self, index: usize) -> usize {
        self.digests.slot_by_node[index] as usize
    }

    /// Returns the digest for a node whose entry was already read and bounds-checked by the caller.
    fn node_digest_for_entry(
        &self,
        index: usize,
        entry: MastNodeEntry,
    ) -> Result<crate::Word, DeserializationError> {
        self.digests.digest_at(self.bytes, &self.layout, index, entry)
    }
}

fn validate_strictly_increasing_digest(
    previous_digest: Option<crate::Word>,
    actual_digest: crate::Word,
    section_name: &str,
) -> Result<(), DeserializationError> {
    if let Some(previous_digest) = previous_digest
        && previous_digest >= actual_digest
    {
        return Err(DeserializationError::InvalidValue(format!(
            "{section_name} section is not strictly sorted"
        )));
    }

    Ok(())
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

fn build_digest_slot_by_node(
    bytes: &[u8],
    layout: &ForestLayout,
    remaining_allocation_budget: Option<&mut usize>,
) -> Result<Vec<u32>, DeserializationError> {
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
        let slot = if matches!(entry, MastNodeEntry::External) {
            let slot = external_slot;
            external_slot = external_slot.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("external digest slot overflow".to_string())
            })?;
            slot
        } else {
            let slot = node_hash_slot;
            node_hash_slot = node_hash_slot.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("node hash slot overflow".to_string())
            })?;
            slot
        };
        slots.push(slot);
    }

    debug_assert_eq!(node_hash_slot as usize, layout.internal_node_count);
    debug_assert_eq!(external_slot as usize, layout.external_node_count);

    Ok(slots)
}

fn recompute_hash_table(
    bytes: &[u8],
    layout: &ForestLayout,
    remaining_allocation_budget: Option<&mut usize>,
) -> Result<Vec<crate::Word>, DeserializationError> {
    let basic_block_data_decoder = BasicBlockDataDecoder::new(basic_block_data(
        bytes,
        layout.basic_block_offset(),
        layout.basic_block_len(),
    )?);

    let mut digests = Vec::new();
    reserve_node_capacity(
        &mut digests,
        layout.node_count,
        "hash table",
        remaining_allocation_budget,
    )?;
    let mut external_slot = 0usize;
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
                    read_digest_entry(bytes, layout.external_digest_offset(), external_slot)?;
                external_slot = external_slot.checked_add(1).ok_or_else(|| {
                    DeserializationError::InvalidValue("external digest slot overflow".to_string())
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
    nodes: &[MastNode],
    node_index: usize,
) -> Result<u32, DeserializationError> {
    let mut offset = 0usize;
    for node in nodes.iter().take(node_index) {
        if let MastNode::Block(block) = node {
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
