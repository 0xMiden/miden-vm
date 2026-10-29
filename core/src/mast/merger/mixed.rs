use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

use crate::{
    Word,
    advice::AdviceMap,
    mast::{
        DenseMastForestBuilder, ExecutableMastForest, ExternalNodeBuilder, MastForest,
        MastForestError, MastForestRead, MastForestRootMap, MastNode, MastNodeExt, MastNodeId,
        SparseMastForest, StoredContentKey,
    },
};

/// A borrowed dense or sparse forest accepted by the shared merge operations.
#[derive(Clone, Copy, Debug)]
pub enum MastForestMergeSource<'forest> {
    Dense(&'forest MastForest),
    Sparse(&'forest SparseMastForest),
}

impl<'forest> MastForestMergeSource<'forest> {
    pub(crate) fn as_dense(self) -> Option<&'forest MastForest> {
        match self {
            Self::Dense(forest) => Some(forest),
            Self::Sparse(_) => None,
        }
    }

    fn node_span(self) -> usize {
        match self {
            Self::Dense(forest) => forest.num_nodes() as usize,
            Self::Sparse(forest) => forest.num_nodes(),
        }
    }
}

impl<'forest> From<&'forest MastForest> for MastForestMergeSource<'forest> {
    fn from(forest: &'forest MastForest) -> Self {
        Self::Dense(forest)
    }
}

impl<'forest> From<&'forest SparseMastForest> for MastForestMergeSource<'forest> {
    fn from(forest: &'forest SparseMastForest) -> Self {
        Self::Sparse(forest)
    }
}

impl ExecutableMastForest for MastForestMergeSource<'_> {
    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        match self {
            Self::Dense(forest) => forest.get_node_by_id(node_id),
            Self::Sparse(forest) => forest.get_node_by_id(node_id),
        }
    }

    fn get_digest_by_id(&self, node_id: MastNodeId) -> Option<Word> {
        match self {
            Self::Dense(forest) => forest.get_digest_by_id(node_id),
            Self::Sparse(forest) => forest.get_digest_by_id(node_id),
        }
    }

    fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        match self {
            Self::Dense(forest) => forest.find_procedure_root(digest),
            Self::Sparse(forest) => forest.find_procedure_root(digest),
        }
    }

    fn advice_map(&self) -> &AdviceMap {
        match self {
            Self::Dense(forest) => forest.advice_map(),
            Self::Sparse(forest) => forest.advice_map(),
        }
    }
}

impl MastForestRead for MastForestMergeSource<'_> {
    type NodeIter<'a>
        = Box<dyn Iterator<Item = (MastNodeId, &'a MastNode)> + 'a>
    where
        Self: 'a;
    type DigestIter<'a>
        = Box<dyn Iterator<Item = (MastNodeId, Word)> + 'a>
    where
        Self: 'a;

    fn node_entries(&self) -> Self::NodeIter<'_> {
        match self {
            Self::Dense(forest) => Box::new(MastForestRead::node_entries(*forest)),
            Self::Sparse(forest) => Box::new(MastForestRead::node_entries(*forest)),
        }
    }

    fn digest_entries(&self) -> Self::DigestIter<'_> {
        match self {
            Self::Dense(forest) => Box::new(MastForestRead::digest_entries(*forest)),
            Self::Sparse(forest) => Box::new(MastForestRead::digest_entries(*forest)),
        }
    }

    fn procedure_roots(&self) -> &[MastNodeId] {
        match self {
            Self::Dense(forest) => forest.procedure_roots(),
            Self::Sparse(forest) => forest.procedure_roots(),
        }
    }
}

pub(crate) struct MixedMastForestMerger<'forest> {
    forests: Vec<MastForestMergeSource<'forest>>,
    builder_source: MastForest,
    builder: DenseMastForestBuilder,
    advice_map: AdviceMap,
    nodes: BTreeMap<MastNodeId, MastNode>,
    digests: BTreeMap<MastNodeId, Word>,
    roots: Vec<MastNodeId>,
    node_maps: Vec<BTreeMap<MastNodeId, MastNodeId>>,
    root_maps: Vec<BTreeMap<MastNodeId, MastNodeId>>,
    opaque_by_digest: BTreeMap<Word, MastNodeId>,
    full_by_content: BTreeMap<StoredContentKey<MastNodeId>, MastNodeId>,
    non_external_by_digest: BTreeMap<Word, (usize, MastNodeId)>,
    full_ids_by_digest: BTreeMap<Word, BTreeSet<MastNodeId>>,
    resolved_digests: BTreeSet<Word>,
    visiting: BTreeSet<(usize, MastNodeId)>,
}

enum MergeTask {
    EnterFull {
        forest_idx: usize,
        node_id: MastNodeId,
    },
    FinishFull {
        forest_idx: usize,
        node_id: MastNodeId,
        node: MastNode,
    },
    EnterDigest {
        forest_idx: usize,
        node_id: MastNodeId,
        digest: Word,
    },
    FinishReplacement {
        forest_idx: usize,
        node_id: MastNodeId,
        replacement_forest: usize,
        replacement_id: MastNodeId,
    },
}

impl<'forest> MixedMastForestMerger<'forest> {
    pub(crate) fn merge_dense(
        forests: Vec<MastForestMergeSource<'forest>>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        let mut merger = Self::new(forests)?;
        merger.merge_entries()?;
        merger.merge_roots()?;

        if let Some((&node_id, _)) = merger.digests.iter().next() {
            return Err(MastForestError::MissingNodeOnDenseMerge(node_id));
        }

        let Self {
            builder,
            advice_map,
            mut node_maps,
            mut root_maps,
            ..
        } = merger;
        let (forest, final_ids) = builder.build_with_id_map()?;
        remap_maps(&mut node_maps, &final_ids);
        remap_maps(&mut root_maps, &final_ids);
        Ok((
            forest.with_advice_map(advice_map),
            MastForestRootMap::from_maps(node_maps, root_maps),
        ))
    }

    pub(crate) fn merge_sparse(
        forests: Vec<MastForestMergeSource<'forest>>,
    ) -> Result<(SparseMastForest, MastForestRootMap), MastForestError> {
        if forests.iter().any(|forest| !forest.advice_map().is_empty()) {
            return Err(MastForestError::AdviceMapNotSupportedInSparseMerge);
        }

        let mut merger = Self::new(forests)?;
        merger.merge_entries()?;
        merger.merge_roots()?;
        let Self {
            nodes,
            digests,
            roots,
            node_maps,
            root_maps,
            ..
        } = merger;
        let forest = SparseMastForest::from_merged_parts(nodes, digests, roots)?;
        Ok((forest, MastForestRootMap::from_maps(node_maps, root_maps)))
    }

    fn new(forests: Vec<MastForestMergeSource<'forest>>) -> Result<Self, MastForestError> {
        let mut advice_map = AdviceMap::default();
        let mut non_external_by_digest = BTreeMap::new();
        for (forest_idx, forest) in forests.iter().enumerate() {
            advice_map
                .merge(forest.advice_map())
                .map_err(|((key, _), _)| MastForestError::AdviceMapKeyCollisionOnMerge(key))?;
            for (node_id, node) in forest.node_entries() {
                if !node.is_external() {
                    non_external_by_digest.insert(node.digest(), (forest_idx, node_id));
                }
            }
        }
        let count = forests.len();
        Ok(Self {
            forests,
            builder_source: MastForest::new(),
            builder: DenseMastForestBuilder::new(),
            advice_map,
            nodes: BTreeMap::new(),
            digests: BTreeMap::new(),
            roots: Vec::new(),
            node_maps: vec![BTreeMap::new(); count],
            root_maps: vec![BTreeMap::new(); count],
            opaque_by_digest: BTreeMap::new(),
            full_by_content: BTreeMap::new(),
            non_external_by_digest,
            full_ids_by_digest: BTreeMap::new(),
            resolved_digests: BTreeSet::new(),
            visiting: BTreeSet::new(),
        })
    }

    fn merge_entries(&mut self) -> Result<(), MastForestError> {
        let mut digest_entries = Vec::new();
        for forest_idx in 0..self.forests.len() {
            let entries = self.forests[forest_idx].digest_entries().collect::<Vec<_>>();
            for (node_id, digest) in entries {
                digest_entries.push((forest_idx, node_id, digest));
                if self.non_external_by_digest.contains_key(&digest) {
                    continue;
                }
                let merged_id = if let Some(&merged_id) = self.opaque_by_digest.get(&digest) {
                    merged_id
                } else {
                    let merged_id = self.builder.push_node(ExternalNodeBuilder::new(digest))?;
                    self.digests.insert(merged_id, digest);
                    self.opaque_by_digest.insert(digest, merged_id);
                    merged_id
                };
                self.node_maps[forest_idx].insert(node_id, merged_id);
            }
        }

        for (forest_idx, node_id, digest) in digest_entries {
            if self.non_external_by_digest.contains_key(&digest) {
                self.merge_tasks(vec![MergeTask::EnterDigest { forest_idx, node_id, digest }])?;
            }
        }

        for forest_idx in 0..self.forests.len() {
            let node_ids = self.forests[forest_idx]
                .node_entries()
                .map(|(node_id, _)| node_id)
                .collect::<Vec<_>>();
            for node_id in node_ids {
                self.merge_full_node(forest_idx, node_id)?;
            }
        }

        for digest in &self.resolved_digests {
            if self.full_ids_by_digest.get(digest).is_some_and(|values| values.len() > 1) {
                return Err(MastForestError::ConflictingNodeDigestOnMerge(*digest));
            }
        }
        Ok(())
    }

    fn merge_full_node(
        &mut self,
        forest_idx: usize,
        node_id: MastNodeId,
    ) -> Result<MastNodeId, MastForestError> {
        self.merge_tasks(vec![MergeTask::EnterFull { forest_idx, node_id }])?;
        Ok(*self.node_maps[forest_idx]
            .get(&node_id)
            .expect("a completed merge task must map its requested node"))
    }

    fn merge_tasks(&mut self, mut tasks: Vec<MergeTask>) -> Result<(), MastForestError> {
        while let Some(task) = tasks.pop() {
            match task {
                MergeTask::EnterFull { forest_idx, node_id } => {
                    if self.node_maps[forest_idx].contains_key(&node_id) {
                        continue;
                    }
                    if !self.visiting.insert((forest_idx, node_id)) {
                        return Err(MastForestError::CyclicDependencyOnMerge(node_id));
                    }

                    let node = self.forests[forest_idx]
                        .get_node_by_id(node_id)
                        .cloned()
                        .ok_or_else(|| {
                            MastForestError::NodeIdOverflow(
                                node_id,
                                self.forests[forest_idx].node_span(),
                            )
                        })?;

                    if node.is_external()
                        && let Some(&(replacement_forest, replacement_id)) =
                            self.non_external_by_digest.get(&node.digest())
                    {
                        self.resolved_digests.insert(node.digest());
                        tasks.push(MergeTask::FinishReplacement {
                            forest_idx,
                            node_id,
                            replacement_forest,
                            replacement_id,
                        });
                        tasks.push(MergeTask::EnterFull {
                            forest_idx: replacement_forest,
                            node_id: replacement_id,
                        });
                        continue;
                    }

                    let mut children = Vec::new();
                    node.for_each_child(|child_id| children.push(child_id));
                    tasks.push(MergeTask::FinishFull { forest_idx, node_id, node });
                    for child_id in children.into_iter().rev() {
                        if self.node_maps[forest_idx].contains_key(&child_id) {
                            continue;
                        }
                        if self.forests[forest_idx].get_node_by_id(child_id).is_some() {
                            tasks.push(MergeTask::EnterFull { forest_idx, node_id: child_id });
                        } else if let Some(digest) =
                            self.forests[forest_idx].get_digest_by_id(child_id)
                        {
                            tasks.push(MergeTask::EnterDigest {
                                forest_idx,
                                node_id: child_id,
                                digest,
                            });
                        } else {
                            return Err(MastForestError::NodeIdOverflow(
                                child_id,
                                self.forests[forest_idx].node_span(),
                            ));
                        }
                    }
                },
                MergeTask::FinishFull { forest_idx, node_id, node } => {
                    self.finish_full_node(forest_idx, node_id, node)?;
                },
                MergeTask::EnterDigest { forest_idx, node_id, digest } => {
                    if self.node_maps[forest_idx].contains_key(&node_id) {
                        continue;
                    }
                    if !self.visiting.insert((forest_idx, node_id)) {
                        return Err(MastForestError::CyclicDependencyOnMerge(node_id));
                    }
                    let &(replacement_forest, replacement_id) = self
                        .non_external_by_digest
                        .get(&digest)
                        .expect("resolved digest tasks must have a full replacement");
                    self.resolved_digests.insert(digest);
                    tasks.push(MergeTask::FinishReplacement {
                        forest_idx,
                        node_id,
                        replacement_forest,
                        replacement_id,
                    });
                    tasks.push(MergeTask::EnterFull {
                        forest_idx: replacement_forest,
                        node_id: replacement_id,
                    });
                },
                MergeTask::FinishReplacement {
                    forest_idx,
                    node_id,
                    replacement_forest,
                    replacement_id,
                } => {
                    let merged_id = *self.node_maps[replacement_forest]
                        .get(&replacement_id)
                        .expect("a replacement node must be mapped before its source");
                    self.node_maps[forest_idx].insert(node_id, merged_id);
                    self.visiting.remove(&(forest_idx, node_id));
                },
            }
        }
        Ok(())
    }

    fn finish_full_node(
        &mut self,
        forest_idx: usize,
        node_id: MastNodeId,
        node: MastNode,
    ) -> Result<(), MastForestError> {
        let builder = super::super::build_node_with_remapped_ids(
            node_id,
            node.clone(),
            &self.builder_source,
            &self.node_maps[forest_idx],
        )?;
        let remapped_node = builder.build_linked()?;
        let content_key = StoredContentKey::from_node(&remapped_node, Some)
            .expect("remapped child IDs are always available");
        let merged_id = if let Some(&merged_id) = self.full_by_content.get(&content_key) {
            merged_id
        } else {
            let builder = super::super::build_node_with_remapped_ids(
                node_id,
                node.clone(),
                &self.builder_source,
                &self.node_maps[forest_idx],
            )?;
            let merged_id = self.builder.push_node(builder)?;
            self.nodes.insert(merged_id, remapped_node);
            self.full_by_content.insert(content_key, merged_id);
            merged_id
        };
        if !node.is_external() {
            self.full_ids_by_digest.entry(node.digest()).or_default().insert(merged_id);
        }
        self.node_maps[forest_idx].insert(node_id, merged_id);
        self.visiting.remove(&(forest_idx, node_id));
        Ok(())
    }

    fn merge_roots(&mut self) -> Result<(), MastForestError> {
        for forest_idx in 0..self.forests.len() {
            let roots = self.forests[forest_idx].procedure_roots().to_vec();
            for root in roots {
                let merged_root = if let Some(&merged_id) = self.node_maps[forest_idx].get(&root) {
                    merged_id
                } else {
                    return Err(MastForestError::MissingRootOnMerge(root));
                };
                self.root_maps[forest_idx].insert(root, merged_root);
                if !self.roots.contains(&merged_root) {
                    self.roots.push(merged_root);
                    self.builder.mark_root(merged_root);
                }
            }
        }
        Ok(())
    }
}

fn remap_maps(
    maps: &mut [BTreeMap<MastNodeId, MastNodeId>],
    final_ids: &impl crate::utils::LookupByIdx<MastNodeId, MastNodeId>,
) {
    for map in maps {
        for mapped_id in map.values_mut() {
            *mapped_id = *final_ids
                .get(*mapped_id)
                .expect("every mixed merger node must have a finalized dense ID");
        }
    }
}
