use alloc::{collections::BTreeMap, vec::Vec};

use crate::{
    crypto::hash::Blake3Digest,
    mast::{
        AsmOpId, DebugVarId, DecoratorId, MastForest, MastForestContributor, MastForestError,
        MastNode, MastNodeBuilder, MastNodeFingerprint, MastNodeId, MultiMastForestIteratorItem,
        MultiMastForestNodeIter,
    },
    serde::Serializable,
    utils::{DenseIdMap, IndexVec},
};

#[cfg(test)]
mod tests;

/// A type that allows merging [`MastForest`]s.
///
/// This functionality is exposed via [`MastForest::merge`]. See its documentation for more details.
pub(crate) struct MastForestMerger {
    mast_forest: MastForest,
    // Internal indices needed for efficient duplicate checking and MastNodeFingerprint
    // computation.
    //
    // These are always in-sync with the nodes in `mast_forest`, i.e. all nodes added to the
    // `mast_forest` are also added to the indices.
    node_id_by_hash: BTreeMap<MastNodeFingerprint, MastNodeId>,
    hash_by_node_id: IndexVec<MastNodeId, MastNodeFingerprint>,
    decorators_by_hash: BTreeMap<Blake3Digest<32>, DecoratorId>,
    /// Mappings from old decorator and node ids to their new ids.
    ///
    /// Any decorator in `mast_forest` is present as the target of some mapping in this map.
    decorator_id_mappings: Vec<DenseIdMap<DecoratorId, DecoratorId>>,
    /// Mappings from previous `MastNodeId`s to their new ids.
    ///
    /// Any `MastNodeId` in `mast_forest` is present as the target of some mapping in this map.
    node_id_mappings: Vec<DenseIdMap<MastNodeId, MastNodeId>>,
}

impl MastForestMerger {
    /// Creates a new merger with an initially empty forest and merges all provided [`MastForest`]s
    /// into it.
    ///
    /// # Normalizing Behavior
    ///
    /// This function performs normalization of the merged forest, which:
    /// - Remaps all node IDs to maintain the invariant that child node IDs < parent node IDs
    /// - Creates a clean, deduplicated forest structure
    /// - Provides consistent node ordering regardless of input
    ///
    /// This normalization is idempotent, but it means that even for single-forest merges, the
    /// resulting forest may have different node IDs and digests than the input. See assembly
    /// test `issue_1644_single_forest_merge_identity` for detailed explanation of this
    /// behavior.
    pub(crate) fn merge<'forest>(
        forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        let forests = forests.into_iter().collect::<Vec<_>>();

        let decorator_id_mappings = Vec::with_capacity(forests.len());
        let node_id_mappings =
            forests.iter().map(|f| DenseIdMap::with_len(f.nodes().len())).collect();

        let mut merger = Self {
            node_id_by_hash: BTreeMap::new(),
            hash_by_node_id: IndexVec::new(),
            decorators_by_hash: BTreeMap::new(),
            mast_forest: MastForest::new(),
            decorator_id_mappings,
            node_id_mappings,
        };

        merger.merge_inner(forests.clone())?;

        let Self { mast_forest, node_id_mappings, .. } = merger;

        let root_maps = MastForestRootMap::from_node_id_map(node_id_mappings, forests);

        Ok((mast_forest, root_maps))
    }

    /// Merges all `forests` into self.
    ///
    /// It does this in three steps:
    ///
    /// 1. Merge all advice maps, checking for key collisions.
    /// 2. Merge all decorators, which is a case of deduplication and creating a decorator id
    ///    mapping which contains how existing [`DecoratorId`]s map to [`DecoratorId`]s in the
    ///    merged forest.
    /// 3. Merge all nodes of forests.
    ///    - Similar to decorators, node indices might move during merging, so the merger keeps a
    ///      node id mapping as it merges nodes.
    ///    - This is a depth-first traversal over all forests to ensure all children are processed
    ///      before their parents. See the documentation of [`MultiMastForestNodeIter`] for details
    ///      on this traversal.
    ///    - Because all parents are processed after their children, we can use the node id mapping
    ///      to remap all [`MastNodeId`]s of the children to their potentially new id in the merged
    ///      forest.
    ///    - If any external node is encountered during this traversal with a digest `foo` for which
    ///      a `replacement` node exists in another forest with digest `foo`, then the external node
    ///      will be replaced by that node. In particular, it means we do not want to add the
    ///      external node to the merged forest, so it is never yielded from the iterator.
    ///      - Assuming the simple case, where the `replacement` was not visited yet and is just a
    ///        single node (not a tree), the iterator would first yield the `replacement` node which
    ///        means it is going to be merged into the forest.
    ///      - Next the iterator yields [`MultiMastForestIteratorItem::ExternalNodeReplacement`]
    ///        which signals that an external node was replaced by another node. In this example,
    ///        the `replacement_*` indices contained in that variant would point to the
    ///        `replacement` node. Now we can simply add a mapping from the external node to the
    ///        `replacement` node in our node id mapping which means all nodes that referenced the
    ///        external node will point to the `replacement` instead.
    /// 4. Finally, we merge all roots of all forests. Here we map the existing root indices to
    ///    their potentially new indices in the merged forest and add them to the forest,
    ///    deduplicating in the process, too.
    fn merge_inner(&mut self, forests: Vec<&MastForest>) -> Result<(), MastForestError> {
        for other_forest in forests.iter() {
            self.merge_advice_map(other_forest)?;
        }
        for other_forest in forests.iter() {
            self.merge_decorators(other_forest)?;
        }
        for other_forest in forests.iter() {
            self.merge_error_codes(other_forest)?;
        }

        let iterator = MultiMastForestNodeIter::new(forests.clone());
        for item in iterator {
            match item {
                MultiMastForestIteratorItem::Node { forest_idx, node_id } => {
                    let node = forests[forest_idx][node_id].clone();
                    self.merge_node(forest_idx, node_id, node, &forests)?;
                },
                MultiMastForestIteratorItem::ExternalNodeReplacement {
                    // forest index of the node which replaces the external node
                    replacement_forest_idx,
                    // ID of the node that replaces the external node
                    replacement_mast_node_id,
                    // forest index of the external node
                    replaced_forest_idx,
                    // ID of the external node
                    replaced_mast_node_id,
                } => {
                    // The iterator is not aware of the merged forest, so the node indices it yields
                    // are for the existing forests. That means we have to map the ID of the
                    // replacement to its new location, since it was previously merged and its IDs
                    // have very likely changed.
                    let mapped_replacement = self.node_id_mappings[replacement_forest_idx]
                        .get(replacement_mast_node_id)
                        .expect("every merged node id should be mapped");

                    // SAFETY: The iterator only yields valid forest indices, so it is safe to index
                    // directly.
                    self.node_id_mappings[replaced_forest_idx]
                        .insert(replaced_mast_node_id, mapped_replacement);
                },
            }
        }

        for (forest_idx, forest) in forests.iter().enumerate() {
            self.merge_roots(forest_idx, forest)?;
        }

        self.merge_debug_metadata(&forests)?;

        Ok(())
    }

    fn merge_decorators(&mut self, other_forest: &MastForest) -> Result<(), MastForestError> {
        let mut decorator_id_remapping =
            DenseIdMap::with_len(other_forest.debug_info.num_decorators());

        for (merging_id, merging_decorator) in
            other_forest.debug_info.decorators().iter().enumerate()
        {
            let merging_decorator_hash = merging_decorator.fingerprint();
            let new_decorator_id = if let Some(existing_decorator) =
                self.decorators_by_hash.get(&merging_decorator_hash)
            {
                *existing_decorator
            } else {
                let new_decorator_id = self.mast_forest.add_decorator(merging_decorator.clone())?;
                self.decorators_by_hash.insert(merging_decorator_hash, new_decorator_id);
                new_decorator_id
            };

            decorator_id_remapping
                .insert(DecoratorId::new_unchecked(merging_id as u32), new_decorator_id);
        }

        self.decorator_id_mappings.push(decorator_id_remapping);

        Ok(())
    }

    fn merge_advice_map(&mut self, other_forest: &MastForest) -> Result<(), MastForestError> {
        self.mast_forest
            .advice_map
            .merge(&other_forest.advice_map)
            .map_err(|((key, _prev), _new)| MastForestError::AdviceMapKeyCollisionOnMerge(key))
    }

    fn merge_error_codes(&mut self, other_forest: &MastForest) -> Result<(), MastForestError> {
        self.mast_forest.debug_info.extend_error_codes(
            other_forest.debug_info.error_codes().map(|(k, v)| (*k, v.clone())),
        );
        Ok(())
    }

    fn merge_node(
        &mut self,
        forest_idx: usize,
        merging_id: MastNodeId,
        node: MastNode,
        original_forests: &[&MastForest],
    ) -> Result<(), MastForestError> {
        // We need to remap the node prior to computing the MastNodeFingerprint.
        //
        // This is because the MastNodeFingerprint computation looks up its descendants and
        // decorators in the internal index, and if we were to pass the original node to
        // that computation, it would look up the incorrect descendants and decorators
        // (since the descendant's indices may have changed).
        //
        // Remapping at this point is guaranteed to be "complete", meaning all ids of children
        // will be present in the node id mapping since the DFS iteration guarantees
        // that all children of this `node` have been processed before this node and
        // their indices have been added to the mappings.
        let remapped_builder = self.build_with_remapped_children(
            merging_id,
            node,
            original_forests[forest_idx],
            &self.node_id_mappings[forest_idx],
            &self.decorator_id_mappings[forest_idx],
        )?;

        let base_fingerprint =
            remapped_builder.fingerprint_for_node(&self.mast_forest, &self.hash_by_node_id)?;

        // Augment with the source node's debug vars so same-ops/different-vars
        // blocks from different forests are not collapsed.
        let debug_var_data =
            serialize_debug_var_content_for_node(original_forests[forest_idx], merging_id);
        let asm_op_data =
            serialize_asm_op_content_for_node(original_forests[forest_idx], merging_id);
        let node_fingerprint = base_fingerprint
            .augment_with_data(&debug_var_data)
            .augment_with_data(&asm_op_data);

        match self.lookup_node_by_fingerprint(&node_fingerprint) {
            Some(matching_node_id) => {
                // If a node with a matching fingerprint exists, then the merging node is a
                // duplicate and we remap it to the existing node.
                self.node_id_mappings[forest_idx].insert(merging_id, matching_node_id);
            },
            None => {
                // If no node with a matching fingerprint exists, then the merging node is
                // unique and we can add it to the merged forest using builders.
                let new_node_id = remapped_builder.add_to_forest(&mut self.mast_forest)?;
                self.node_id_mappings[forest_idx].insert(merging_id, new_node_id);

                // We need to update the indices with the newly inserted nodes
                // since the MastNodeFingerprint computation requires all descendants of a node
                // to be in this index. Hence when we encounter a node in the merging forest
                // which has descendants (Call, Loop, Split, ...), then their descendants need to be
                // in the indices.
                self.node_id_by_hash.insert(node_fingerprint, new_node_id);
                let returned_id = self
                    .hash_by_node_id
                    .push(node_fingerprint)
                    .map_err(|_| MastForestError::TooManyNodes)?;
                debug_assert_eq!(
                    returned_id, new_node_id,
                    "hash_by_node_id push() should return the same node IDs as node_id_by_hash"
                );
            },
        }

        Ok(())
    }

    fn merge_roots(
        &mut self,
        forest_idx: usize,
        other_forest: &MastForest,
    ) -> Result<(), MastForestError> {
        for root_id in other_forest.roots.iter() {
            // Map the previous root to its possibly new id.
            let new_root = self.node_id_mappings[forest_idx]
                .get(*root_id)
                .expect("all node ids should have an entry");
            // This takes O(n) where n is the number of roots in the merged forest every time to
            // check if the root already exists. As the number of roots is relatively low generally,
            // this should be okay.
            self.mast_forest.make_root(new_root);
        }

        Ok(())
    }

    /// Transfers procedure names, asm ops, and debug vars from the source forests
    /// into the merged forest, remapping all IDs along the way.
    ///
    /// Procedure names are merged separately by digest. Per-node asm-op and debug-var
    /// metadata are remapped by node ID, and when two source nodes map to the same merged
    /// node (dedup), the first forest's per-node metadata wins.
    fn merge_debug_metadata(&mut self, forests: &[&MastForest]) -> Result<(), MastForestError> {
        // Procedure names are keyed by digest. First name wins so that a later
        // forest cannot silently rename an already-registered procedure.
        for forest in forests.iter() {
            for (digest, name) in forest.debug_info.procedure_names() {
                if self.mast_forest.debug_info.procedure_name(&digest).is_none() {
                    self.mast_forest.debug_info.insert_procedure_name(digest, name.clone());
                }
            }
        }

        // Collect per-node asm-op and debug-var registrations across all forests.
        // BTreeMap gives us sorted-by-node-id iteration, which the CSR requires.
        let mut asm_entries: BTreeMap<MastNodeId, Vec<(usize, AsmOpId)>> = BTreeMap::new();
        let mut dbg_entries: BTreeMap<MastNodeId, Vec<(usize, DebugVarId)>> = BTreeMap::new();

        for (forest_idx, forest) in forests.iter().enumerate() {
            // Copy AssemblyOp objects and build old→new AsmOpId remapping.
            let mut asm_id_map: BTreeMap<AsmOpId, AsmOpId> = BTreeMap::new();
            for (raw, asm_op) in forest.debug_info.asm_ops().iter().enumerate() {
                let old_id = AsmOpId::new(raw as u32);
                let new_id = self.mast_forest.debug_info.add_asm_op(asm_op.clone())?;
                asm_id_map.insert(old_id, new_id);
            }

            // Copy DebugVarInfo objects and build old→new DebugVarId remapping.
            let mut dbg_id_map: BTreeMap<DebugVarId, DebugVarId> = BTreeMap::new();
            for (raw, dvar) in forest.debug_info.debug_vars().iter().enumerate() {
                let old_id = DebugVarId::from(raw as u32);
                let new_id = self.mast_forest.debug_info.add_debug_var(dvar.clone())?;
                dbg_id_map.insert(old_id, new_id);
            }

            // For each source node, remap and store entries. First forest wins per node.
            for old_raw in 0..forest.num_nodes() {
                let old_id = MastNodeId::new_unchecked(old_raw);
                let new_id = match self.node_id_mappings[forest_idx].get(old_id) {
                    Some(id) => id,
                    None => continue,
                };

                if let alloc::collections::btree_map::Entry::Vacant(e) = asm_entries.entry(new_id) {
                    let ops = forest.debug_info.asm_ops_for_node(old_id);
                    if !ops.is_empty() {
                        let remapped =
                            ops.into_iter().map(|(idx, id)| (idx, asm_id_map[&id])).collect();
                        e.insert(remapped);
                    }
                }

                if let alloc::collections::btree_map::Entry::Vacant(e) = dbg_entries.entry(new_id) {
                    let vars = forest.debug_info.debug_vars_for_node(old_id);
                    if !vars.is_empty() {
                        let remapped =
                            vars.into_iter().map(|(idx, id)| (idx, dbg_id_map[&id])).collect();
                        e.insert(remapped);
                    }
                }
            }
        }

        // Register in node-ID order (CSR sequential constraint).
        for (node_id, entries) in asm_entries {
            let num_ops = match &self.mast_forest[node_id] {
                MastNode::Block(block) => block.num_operations() as usize,
                _ => entries.iter().map(|(idx, _)| idx + 1).max().unwrap_or(0),
            };
            self.mast_forest
                .debug_info
                .register_asm_ops(node_id, num_ops, entries)
                .map_err(|_| MastForestError::TooManyNodes)?;
        }

        for (node_id, entries) in dbg_entries {
            self.mast_forest
                .debug_info
                .register_op_indexed_debug_vars(node_id, entries)
                .map_err(|_| MastForestError::TooManyNodes)?;
        }

        Ok(())
    }

    // HELPERS
    // ================================================================================================

    /// Returns the ID of the node in the merged forest that matches the given
    /// fingerprint, if any.
    fn lookup_node_by_fingerprint(&self, fingerprint: &MastNodeFingerprint) -> Option<MastNodeId> {
        self.node_id_by_hash.get(fingerprint).copied()
    }

    /// Builds a new node with remapped children and decorators using the provided mappings.
    fn build_with_remapped_children(
        &self,
        merging_id: MastNodeId,
        src: MastNode,
        original_forest: &MastForest,
        nmap: &DenseIdMap<MastNodeId, MastNodeId>,
        dmap: &DenseIdMap<DecoratorId, DecoratorId>,
    ) -> Result<MastNodeBuilder, MastForestError> {
        super::build_node_with_remapped_ids(merging_id, src, original_forest, nmap, dmap)
    }
}

// HELPERS
// ================================================================================================

/// Serializes the actual debug var *content* (name, location, etc.) for a node,
/// producing a stable byte sequence suitable for fingerprint augmentation.
///
/// Unlike the assembler's `serialize_debug_vars` (which serializes `(op_idx, DebugVarId)` pairs),
/// this serializes the resolved DebugVarInfo so that two forests assigning different DebugVarIds
/// to identical variables still produce the same fingerprint contribution.
fn serialize_debug_var_content_for_node(forest: &MastForest, node_id: MastNodeId) -> Vec<u8> {
    let entries = forest.debug_info().debug_vars_for_node(node_id);
    if entries.is_empty() {
        return Vec::new();
    }

    let mut data = Vec::new();
    for (op_idx, var_id) in entries {
        data.extend_from_slice(&op_idx.to_le_bytes());
        if let Some(info) = forest.debug_info().debug_var(var_id) {
            info.write_into(&mut data);
        }
    }
    data
}

/// Serializes the actual asm-op content for a node, producing a stable byte
/// sequence suitable for fingerprint augmentation.
///
/// This ensures that nodes with identical structure but different source-mapping
/// metadata do not collapse during merge.
fn serialize_asm_op_content_for_node(forest: &MastForest, node_id: MastNodeId) -> Vec<u8> {
    let entries = forest.debug_info().asm_ops_for_node(node_id);
    if entries.is_empty() {
        return Vec::new();
    }

    let mut data = Vec::new();
    for (op_idx, asm_op_id) in entries {
        data.extend_from_slice(&op_idx.to_le_bytes());
        if let Some(asm_op) = forest.debug_info().asm_op(asm_op_id) {
            asm_op.context_name().write_into(&mut data);
            asm_op.op().write_into(&mut data);
            asm_op.num_cycles().write_into(&mut data);
            match asm_op.location() {
                Some(location) => {
                    data.push(1);
                    location.uri.write_into(&mut data);
                    data.extend_from_slice(&u32::from(location.start).to_le_bytes());
                    data.extend_from_slice(&u32::from(location.end).to_le_bytes());
                },
                None => data.push(0),
            }
        }
    }
    data
}

// MAST FOREST ROOT MAP
// ================================================================================================

/// A mapping for the new location of the roots of a [`MastForest`] after a merge.
///
/// It maps the roots ([`MastNodeId`]s) of a forest to their new [`MastNodeId`] in the merged
/// forest. See [`MastForest::merge`] for more details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MastForestRootMap {
    root_maps: Vec<BTreeMap<MastNodeId, MastNodeId>>,
}

impl MastForestRootMap {
    fn from_node_id_map(
        id_map: Vec<DenseIdMap<MastNodeId, MastNodeId>>,
        forests: Vec<&MastForest>,
    ) -> Self {
        let mut root_maps = vec![BTreeMap::new(); forests.len()];

        for (forest_idx, forest) in forests.into_iter().enumerate() {
            for root in forest.procedure_roots() {
                let new_id = id_map[forest_idx]
                    .get(*root)
                    .expect("every node id should be mapped to its new id");
                root_maps[forest_idx].insert(*root, new_id);
            }
        }

        Self { root_maps }
    }

    /// Maps the given root to its new location in the merged forest, if such a mapping exists.
    ///
    /// It is guaranteed that every root of the map's corresponding forest is contained in the map.
    pub fn map_root(&self, forest_index: usize, root: &MastNodeId) -> Option<MastNodeId> {
        self.root_maps.get(forest_index).and_then(|map| map.get(root)).copied()
    }
}
