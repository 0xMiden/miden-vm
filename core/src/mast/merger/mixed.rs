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
        MastForestContributor, MastForestError, MastForestRead, MastForestRootMap, MastNode,
        MastNodeExt, MastNodeId, SparseMastForest,
    },
    utils::IndexVec,
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
    full_by_fingerprint: BTreeMap<Word, MastNodeId>,
    fingerprint_by_id: IndexVec<MastNodeId, Word>,
    non_external_by_digest: BTreeMap<Word, (usize, MastNodeId)>,
    fingerprints_by_digest: BTreeMap<Word, BTreeSet<Word>>,
    resolved_external_digests: BTreeSet<Word>,
    visiting: BTreeSet<(usize, MastNodeId)>,
}

impl<'forest> MixedMastForestMerger<'forest> {
    pub(crate) fn merge_dense(
        forests: Vec<MastForestMergeSource<'forest>>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        let mut merger = Self::new(forests)?;
        merger.merge_entries()?;
        merger.merge_roots(false)?;

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
        merger.merge_roots(true)?;
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
            full_by_fingerprint: BTreeMap::new(),
            fingerprint_by_id: IndexVec::new(),
            non_external_by_digest,
            fingerprints_by_digest: BTreeMap::new(),
            resolved_external_digests: BTreeSet::new(),
            visiting: BTreeSet::new(),
        })
    }

    fn merge_entries(&mut self) -> Result<(), MastForestError> {
        for forest_idx in 0..self.forests.len() {
            let entries = self.forests[forest_idx].digest_entries().collect::<Vec<_>>();
            for (node_id, digest) in entries {
                let merged_id = if let Some(&merged_id) = self.opaque_by_digest.get(&digest) {
                    merged_id
                } else {
                    let merged_id = self.builder.push_node(ExternalNodeBuilder::new(digest))?;
                    self.fingerprint_by_id
                        .push(digest)
                        .map_err(|_| MastForestError::TooManyNodes)?;
                    self.digests.insert(merged_id, digest);
                    self.opaque_by_digest.insert(digest, merged_id);
                    merged_id
                };
                self.node_maps[forest_idx].insert(node_id, merged_id);
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

        for digest in &self.resolved_external_digests {
            if self.fingerprints_by_digest.get(digest).is_some_and(|values| values.len() > 1) {
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
        if let Some(&merged_id) = self.node_maps[forest_idx].get(&node_id) {
            return Ok(merged_id);
        }
        if !self.visiting.insert((forest_idx, node_id)) {
            return Err(MastForestError::CyclicDependencyOnMerge(node_id));
        }

        let node = self.forests[forest_idx].get_node_by_id(node_id).cloned().ok_or_else(|| {
            MastForestError::NodeIdOverflow(node_id, self.forests[forest_idx].node_span())
        })?;

        if node.is_external()
            && let Some(&(replacement_forest, replacement_id)) =
                self.non_external_by_digest.get(&node.digest())
        {
            self.resolved_external_digests.insert(node.digest());
            let merged_id = self.merge_full_node(replacement_forest, replacement_id)?;
            self.node_maps[forest_idx].insert(node_id, merged_id);
            self.visiting.remove(&(forest_idx, node_id));
            return Ok(merged_id);
        }

        let mut children = Vec::new();
        node.for_each_child(|child_id| children.push(child_id));
        for child_id in children {
            if !self.node_maps[forest_idx].contains_key(&child_id) {
                if self.forests[forest_idx].get_node_by_id(child_id).is_some() {
                    self.merge_full_node(forest_idx, child_id)?;
                } else {
                    return Err(MastForestError::NodeIdOverflow(
                        child_id,
                        self.forests[forest_idx].node_span(),
                    ));
                }
            }
        }

        let builder = super::super::build_node_with_remapped_ids(
            node_id,
            node.clone(),
            &self.builder_source,
            &self.node_maps[forest_idx],
        )?;
        let fingerprint = builder.fingerprint_for_node(&self.builder, &self.fingerprint_by_id)?;
        let merged_id = if let Some(&merged_id) = self.full_by_fingerprint.get(&fingerprint) {
            merged_id
        } else {
            let merged_id = self.builder.push_node(builder)?;
            let stored_node = self
                .builder
                .get_node_by_id(merged_id)
                .expect("a node just pushed into the merge builder must exist")
                .clone();
            self.nodes.insert(merged_id, stored_node);
            self.full_by_fingerprint.insert(fingerprint, merged_id);
            self.fingerprint_by_id
                .push(fingerprint)
                .map_err(|_| MastForestError::TooManyNodes)?;
            merged_id
        };
        if !node.is_external() {
            self.fingerprints_by_digest
                .entry(node.digest())
                .or_default()
                .insert(fingerprint);
        }
        self.node_maps[forest_idx].insert(node_id, merged_id);
        self.visiting.remove(&(forest_idx, node_id));
        Ok(merged_id)
    }

    fn merge_roots(&mut self, allow_missing: bool) -> Result<(), MastForestError> {
        for forest_idx in 0..self.forests.len() {
            let roots = self.forests[forest_idx].procedure_roots().to_vec();
            for root in roots {
                let merged_root = if let Some(&merged_id) = self.node_maps[forest_idx].get(&root) {
                    merged_id
                } else if allow_missing {
                    let merged_id =
                        self.builder.push_node(ExternalNodeBuilder::new(Word::default()))?;
                    self.fingerprint_by_id
                        .push(Word::default())
                        .map_err(|_| MastForestError::TooManyNodes)?;
                    self.node_maps[forest_idx].insert(root, merged_id);
                    merged_id
                } else {
                    return Err(MastForestError::MissingNodeOnDenseMerge(root));
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
