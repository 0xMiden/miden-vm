use alloc::{collections::BTreeMap, vec::Vec};

use crate::{
    Word,
    mast::{
        DenseMastForestBuilder, MastForest, MastForestContributor, MastForestError, MastNode,
        MastNodeBuilder, MastNodeId, MultiMastForestIteratorItem, MultiMastForestNodeIter,
    },
    utils::{DenseIdMap, IndexVec},
};

#[cfg(test)]
mod tests;

/// A type that allows merging [`MastForest`]s.
///
/// This functionality is exposed via [`MastForest::merge`]. See its documentation for more details.
pub(crate) struct MastForestMerger {
    mast_forest: DenseMastForestBuilder,
    // Internal indices needed for efficient duplicate checking.
    //
    // These are always in-sync with the nodes in `mast_forest`, i.e. all nodes added to the
    // `mast_forest` are also added to the indices.
    node_id_by_hash: BTreeMap<Word, MastNodeId>,
    hash_by_node_id: IndexVec<MastNodeId, Word>,
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

        let node_id_mappings =
            forests.iter().map(|f| DenseIdMap::with_len(f.nodes().len())).collect();

        let mut merger = Self {
            node_id_by_hash: BTreeMap::new(),
            hash_by_node_id: IndexVec::new(),
            mast_forest: DenseMastForestBuilder::new(),
            node_id_mappings,
        };

        merger.merge_inner(forests.clone())?;

        let Self { mast_forest, node_id_mappings, .. } = merger;
        let (mast_forest, final_id_remapping) = mast_forest.build_with_id_map()?;
        let node_id_mappings =
            Self::remap_finalized_node_ids(node_id_mappings, &final_id_remapping);

        let root_maps = MastForestRootMap::from_node_id_map(node_id_mappings, forests);

        Ok((mast_forest, root_maps))
    }

    /// Merges all `forests` into self.
    ///
    /// It does this in three steps:
    ///
    /// 1. Merge all advice maps, checking for key collisions.
    /// 2. Merge all nodes of forests.
    ///    - Node indices might move during merging, so the merger keeps a node id mapping as it
    ///      merges nodes.
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
    /// 3. Finally, we merge all roots of all forests. Here we map the existing root indices to
    ///    their potentially new indices in the merged forest and add them to the forest,
    ///    deduplicating in the process, too.
    fn merge_inner(&mut self, forests: Vec<&MastForest>) -> Result<(), MastForestError> {
        for other_forest in forests.iter() {
            self.merge_advice_map(other_forest)?;
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
            self.merge_roots(forest_idx, forest);
        }

        Ok(())
    }

    fn merge_advice_map(&mut self, other_forest: &MastForest) -> Result<(), MastForestError> {
        self.mast_forest.merge_advice_map(other_forest.advice_map())
    }

    fn merge_node(
        &mut self,
        forest_idx: usize,
        merging_id: MastNodeId,
        node: MastNode,
        original_forests: &[&MastForest],
    ) -> Result<(), MastForestError> {
        // We need to remap the node prior to computing the node fingerprint since child IDs may
        // have changed in the merged forest.
        //
        // Remapping at this point is guaranteed to be "complete", meaning all IDs of children
        // will be present in the node id mapping since the DFS iteration guarantees
        // that all children of this `node` have been processed before this node and
        // their indices have been added to the mappings.
        let remapped_builder = self.build_with_remapped_children(
            merging_id,
            node,
            original_forests[forest_idx],
            &self.node_id_mappings[forest_idx],
        )?;

        let node_fingerprint =
            remapped_builder.fingerprint_for_node(&self.mast_forest, &self.hash_by_node_id)?;

        match self.lookup_node_by_fingerprint(&node_fingerprint) {
            Some(matching_node_id) => {
                // If a node with a matching fingerprint exists, then the merging node is a
                // duplicate and we remap it to the existing node.
                self.node_id_mappings[forest_idx].insert(merging_id, matching_node_id);
            },
            None => {
                // If no node with a matching fingerprint exists, then the merging node is
                // unique and we can add it to the merged forest using builders.
                let new_node_id = self.mast_forest.push_node(remapped_builder)?;
                self.node_id_mappings[forest_idx].insert(merging_id, new_node_id);

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

    fn merge_roots(&mut self, forest_idx: usize, other_forest: &MastForest) {
        for root_id in other_forest.roots.iter() {
            // Map the previous root to its possibly new id.
            let new_root = self.node_id_mappings[forest_idx]
                .get(*root_id)
                .expect("all node ids should have an entry");
            // This takes O(n) where n is the number of roots in the merged forest every time to
            // check if the root already exists. As the number of roots is relatively low generally,
            // this should be okay.
            self.mast_forest.mark_root(new_root);
        }
    }

    // HELPERS
    // ================================================================================================

    /// Returns the ID of the node in the merged forest that matches the given
    /// fingerprint, if any.
    fn lookup_node_by_fingerprint(&self, fingerprint: &Word) -> Option<MastNodeId> {
        self.node_id_by_hash.get(fingerprint).copied()
    }

    /// Builds a new node with remapped children using the provided mappings.
    fn build_with_remapped_children(
        &self,
        merging_id: MastNodeId,
        src: MastNode,
        original_forest: &MastForest,
        nmap: &DenseIdMap<MastNodeId, MastNodeId>,
    ) -> Result<MastNodeBuilder, MastForestError> {
        super::build_node_with_remapped_ids(merging_id, src, original_forest, nmap)
    }

    /// Remaps each source forest's node IDs from merger-local IDs to finalized dense IDs.
    fn remap_finalized_node_ids(
        mut node_id_mappings: Vec<DenseIdMap<MastNodeId, MastNodeId>>,
        final_id_remapping: &DenseIdMap<MastNodeId, MastNodeId>,
    ) -> Vec<DenseIdMap<MastNodeId, MastNodeId>> {
        for node_id_mapping in &mut node_id_mappings {
            for source_index in 0..node_id_mapping.len() {
                let source_id = MastNodeId::new_unchecked(
                    source_index.try_into().expect("source node index exceeds u32"),
                );
                if let Some(builder_id) = node_id_mapping.get(source_id) {
                    let finalized_id = final_id_remapping
                        .get(builder_id)
                        .expect("every builder node id should map to a finalized node id");
                    node_id_mapping.insert(source_id, finalized_id);
                }
            }
        }

        node_id_mappings
    }
}

// MAST FOREST ROOT MAP
// ================================================================================================

/// A mapping for the new location of the roots of a [`MastForest`] after a merge.
///
/// It maps the roots ([`MastNodeId`]s) of a forest to their new [`MastNodeId`] in the merged
/// forest. See [`MastForest::merge`] for more details.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MastForestRootMap {
    node_maps: Vec<BTreeMap<MastNodeId, MastNodeId>>,
    root_maps: Vec<BTreeMap<MastNodeId, MastNodeId>>,
}

impl MastForestRootMap {
    fn from_node_id_map(
        id_map: Vec<DenseIdMap<MastNodeId, MastNodeId>>,
        forests: Vec<&MastForest>,
    ) -> Self {
        let mut node_maps = vec![BTreeMap::new(); forests.len()];
        let mut root_maps = vec![BTreeMap::new(); forests.len()];

        for (forest_idx, forest) in forests.into_iter().enumerate() {
            for (node_idx, _) in forest.nodes().iter().enumerate() {
                let node_id = MastNodeId::new_unchecked(
                    node_idx.try_into().expect("MastForest node index exceeds u32"),
                );
                if let Some(new_id) = id_map[forest_idx].get(node_id) {
                    node_maps[forest_idx].insert(node_id, new_id);
                }
            }
            for root in forest.procedure_roots() {
                let new_id = id_map[forest_idx]
                    .get(*root)
                    .expect("every node id should be mapped to its new id");
                root_maps[forest_idx].insert(*root, new_id);
            }
        }

        Self { node_maps, root_maps }
    }

    /// Maps any node from the given input forest to its new location in the merged forest.
    ///
    /// This includes non-root nodes, which is required when remapping package-owned source/debug
    /// graphs after [`MastForest::merge`].
    pub fn map_node(&self, forest_index: usize, node: &MastNodeId) -> Option<MastNodeId> {
        self.node_maps.get(forest_index).and_then(|map| map.get(node)).copied()
    }

    /// Maps the given root to its new location in the merged forest, if such a mapping exists.
    ///
    /// It is guaranteed that every root of the map's corresponding forest is contained in the map.
    pub fn map_root(&self, forest_index: usize, root: &MastNodeId) -> Option<MastNodeId> {
        self.root_maps.get(forest_index).and_then(|map| map.get(root)).copied()
    }
}
