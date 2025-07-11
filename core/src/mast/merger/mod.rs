use alloc::{collections::BTreeMap, vec::Vec};

use miden_crypto::hash::blake::Blake3Digest;

use crate::mast::{
    DecoratorId, MastForest, MastForestError, MastNode, MastNodeFingerprint, MastNodeId,
    MultiMastForestIteratorItem, MultiMastForestNodeIter,
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
    hash_by_node_id: BTreeMap<MastNodeId, MastNodeFingerprint>,
    decorators_by_hash: BTreeMap<Blake3Digest<32>, DecoratorId>,
    /// Mappings from old decorator and node ids to their new ids.
    ///
    /// Any decorator in `mast_forest` is present as the target of some mapping in this map.
    decorator_id_mappings: Vec<DecoratorIdMap>,
    /// Mappings from previous `MastNodeId`s to their new ids.
    ///
    /// Any `MastNodeId` in `mast_forest` is present as the target of some mapping in this map.
    node_id_mappings: Vec<MastForestNodeIdMap>,
}

impl MastForestMerger {
    /// Creates a new merger with an initially empty forest and merges all provided [`MastForest`]s
    /// into it.
    pub(crate) fn merge<'forest>(
        forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        let forests = forests.into_iter().collect::<Vec<_>>();
        let decorator_id_mappings = Vec::with_capacity(forests.len());
        let node_id_mappings = vec![MastForestNodeIdMap::new(); forests.len()];

        let mut merger = Self {
            node_id_by_hash: BTreeMap::new(),
            hash_by_node_id: BTreeMap::new(),
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
                    let node = &forests[forest_idx][node_id];
                    self.merge_node(forest_idx, node_id, node)?;
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
                        .get(&replacement_mast_node_id)
                        .copied()
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

        Ok(())
    }

    fn merge_decorators(&mut self, other_forest: &MastForest) -> Result<(), MastForestError> {
        let mut decorator_id_remapping = DecoratorIdMap::new(other_forest.decorators.len());

        for (merging_id, merging_decorator) in other_forest.decorators.iter().enumerate() {
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
        self.mast_forest.error_codes.extend(other_forest.error_codes.clone());
        Ok(())
    }

    fn merge_node(
        &mut self,
        forest_idx: usize,
        merging_id: MastNodeId,
        node: &MastNode,
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
        let remapped_node = self.remap_node(forest_idx, node)?;

        let node_fingerprint = MastNodeFingerprint::from_mast_node(
            &self.mast_forest,
            &self.hash_by_node_id,
            &remapped_node,
        )
        .expect(
            "hash_by_node_id should contain the fingerprints of all children of `remapped_node`",
        );

        match self.lookup_node_by_fingerprint(&node_fingerprint) {
            Some(matching_node_id) => {
                // If a node with a matching fingerprint exists, then the merging node is a
                // duplicate and we remap it to the existing node.
                self.node_id_mappings[forest_idx].insert(merging_id, matching_node_id);
            },
            None => {
                // If no node with a matching fingerprint exists, then the merging node is
                // unique and we can add it to the merged forest.
                let new_node_id = self.mast_forest.add_node(remapped_node)?;
                self.node_id_mappings[forest_idx].insert(merging_id, new_node_id);

                // We need to update the indices with the newly inserted nodes
                // since the MastNodeFingerprint computation requires all descendants of a node
                // to be in this index. Hence when we encounter a node in the merging forest
                // which has descendants (Call, Loop, Split, ...), then their descendants need to be
                // in the indices.
                self.node_id_by_hash.insert(node_fingerprint, new_node_id);
                self.hash_by_node_id.insert(new_node_id, node_fingerprint);
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
                .get(root_id)
                .expect("all node ids should have an entry");
            // This takes O(n) where n is the number of roots in the merged forest every time to
            // check if the root already exists. As the number of roots is relatively low generally,
            // this should be okay.
            self.mast_forest.make_root(*new_root);
        }

        Ok(())
    }

    /// Remaps a nodes' potentially contained children and decorators to their new IDs according to
    /// the given maps.
    fn remap_node(&self, forest_idx: usize, node: &MastNode) -> Result<MastNode, MastForestError> {
        let map_decorator_id = |decorator_id: &DecoratorId| {
            self.decorator_id_mappings[forest_idx].get(decorator_id).ok_or_else(|| {
                MastForestError::DecoratorIdOverflow(
                    *decorator_id,
                    self.decorator_id_mappings[forest_idx].len(),
                )
            })
        };
        let map_decorators = |decorators: &[DecoratorId]| -> Result<Vec<_>, MastForestError> {
            decorators.iter().map(map_decorator_id).collect()
        };

        let map_node_id = |node_id: MastNodeId| {
            self.node_id_mappings[forest_idx]
                .get(&node_id)
                .copied()
                .expect("every node id should have an entry")
        };

        // Due to DFS postorder iteration all children of node's should have been inserted before
        // their parents which is why we can `expect` the constructor calls here.
        let mut mapped_node = match node {
            MastNode::Join(join_node) => {
                let first = map_node_id(join_node.first());
                let second = map_node_id(join_node.second());

                MastNode::new_join(first, second, &self.mast_forest)
                    .expect("JoinNode children should have been mapped to a lower index")
            },
            MastNode::Split(split_node) => {
                let if_branch = map_node_id(split_node.on_true());
                let else_branch = map_node_id(split_node.on_false());

                MastNode::new_split(if_branch, else_branch, &self.mast_forest)
                    .expect("SplitNode children should have been mapped to a lower index")
            },
            MastNode::Loop(loop_node) => {
                let body = map_node_id(loop_node.body());
                MastNode::new_loop(body, &self.mast_forest)
                    .expect("LoopNode children should have been mapped to a lower index")
            },
            MastNode::Call(call_node) => {
                let callee = map_node_id(call_node.callee());
                MastNode::new_call(callee, &self.mast_forest)
                    .expect("CallNode children should have been mapped to a lower index")
            },
            // Other nodes are simply copied.
            MastNode::Block(basic_block_node) => {
                MastNode::new_basic_block(
                    basic_block_node.operations().copied().collect(),
                    // Operation Indices of decorators stay the same while decorator IDs need to be
                    // mapped.
                    Some(
                        basic_block_node
                            .decorators()
                            .iter()
                            .map(|(idx, decorator_id)| match map_decorator_id(decorator_id) {
                                Ok(mapped_decorator) => Ok((*idx, mapped_decorator)),
                                Err(err) => Err(err),
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                )
                .expect("previously valid BasicBlockNode should still be valid")
            },
            MastNode::Dyn(_) => MastNode::new_dyn(),
            MastNode::External(external_node) => MastNode::new_external(external_node.digest()),
        };

        // Decorators must be handled specially for basic block nodes.
        // For other node types we can handle it centrally.
        if !mapped_node.is_basic_block() {
            mapped_node.append_before_enter(&map_decorators(node.before_enter())?);
            mapped_node.append_after_exit(&map_decorators(node.after_exit())?);
        }

        Ok(mapped_node)
    }

    // HELPERS
    // ================================================================================================

    /// Returns a slice of nodes in the merged forest which have the given `mast_root`.
    fn lookup_node_by_fingerprint(&self, fingerprint: &MastNodeFingerprint) -> Option<MastNodeId> {
        self.node_id_by_hash.get(fingerprint).copied()
    }
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
    fn from_node_id_map(id_map: Vec<MastForestNodeIdMap>, forests: Vec<&MastForest>) -> Self {
        let mut root_maps = vec![BTreeMap::new(); forests.len()];

        for (forest_idx, forest) in forests.into_iter().enumerate() {
            for root in forest.procedure_roots() {
                let new_id = id_map[forest_idx]
                    .get(root)
                    .copied()
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

// DECORATOR ID MAP
// ================================================================================================

/// A specialized map from [`DecoratorId`] -> [`DecoratorId`].
///
/// When mapping Decorator IDs during merging, we always map all IDs of the merging
/// forest to new ids. Hence it is more efficient to use a `Vec` instead of, say, a `BTreeMap`.
///
/// In other words, this type is similar to `BTreeMap<ID, ID>` but takes advantage of the fact that
/// the keys are contiguous.
///
/// This type is meant to encapsulates some guarantees:
///
/// - Indexing into the vector for any ID is safe if that ID is valid for the corresponding forest.
///   Despite that, we still cannot index unconditionally in case a node with invalid
///   [`DecoratorId`]s is passed to `merge`.
/// - The entry itself can be either None or Some. However:
///   - For `DecoratorId`s we iterate and insert all decorators into this map before retrieving any
///     entry, so all entries contain `Some`. Because of this, we can use `expect` in `get` for the
///     `Option` value.
/// - Similarly, inserting any ID from the corresponding forest is safe as the map contains a
///   pre-allocated `Vec` of the appropriate size.
struct DecoratorIdMap {
    inner: Vec<Option<DecoratorId>>,
}

impl DecoratorIdMap {
    fn new(num_ids: usize) -> Self {
        Self { inner: vec![None; num_ids] }
    }

    /// Maps the given key to the given value.
    ///
    /// It is the caller's responsibility to only pass keys that belong to the forest for which this
    /// map was originally created.
    fn insert(&mut self, key: DecoratorId, value: DecoratorId) {
        self.inner[key.as_usize()] = Some(value);
    }

    /// Retrieves the value for the given key.
    fn get(&self, key: &DecoratorId) -> Option<DecoratorId> {
        self.inner
            .get(key.as_usize())
            .map(|id| id.expect("every id should have a Some entry in the map when calling get"))
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// A type definition for increased readability in function signatures.
type MastForestNodeIdMap = BTreeMap<MastNodeId, MastNodeId>;
