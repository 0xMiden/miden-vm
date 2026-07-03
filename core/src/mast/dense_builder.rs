use alloc::vec::Vec;

use crate::{
    advice::AdviceMap,
    mast::{
        MastForest, MastForestError, MastForestParts, MastNode, MastNodeBuilder, MastNodeContext,
        MastNodeId,
    },
    utils::{DenseIdMap, Idx, IndexVec},
};

/// Construction surface for dense MAST forests.
///
/// The builder may append nodes while a forest is under construction. The value returned by
/// [`Self::finish`] is a finalized [`MastForest`] with canonicalized dense node order.
#[derive(Debug, Default)]
pub struct DenseMastForestBuilder {
    nodes: IndexVec<MastNodeId, MastNode>,
    roots: Vec<MastNodeId>,
    advice_map: AdviceMap,
}

impl DenseMastForestBuilder {
    pub fn new() -> Self {
        Self {
            nodes: IndexVec::new(),
            roots: Vec::new(),
            advice_map: AdviceMap::default(),
        }
    }

    pub fn push_node_builder(
        &mut self,
        builder: MastNodeBuilder,
    ) -> Result<MastNodeId, MastForestError> {
        let node = builder.build(self)?;
        self.push_linked_node(node)
    }

    pub fn push_node(
        &mut self,
        builder: impl Into<MastNodeBuilder>,
    ) -> Result<MastNodeId, MastForestError> {
        self.push_node_builder(builder.into())
    }

    fn push_linked_node(&mut self, node: MastNode) -> Result<MastNodeId, MastForestError> {
        self.nodes.push(node).map_err(|_| MastForestError::TooManyNodes)
    }

    pub fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.nodes.get(node_id)
    }

    pub fn mark_root(&mut self, root: MastNodeId) {
        assert!(root.to_usize() < self.nodes.len());

        if !self.roots.contains(&root) {
            self.roots.push(root);
        }
    }

    pub(crate) fn merge_advice_map(
        &mut self,
        advice_map: &AdviceMap,
    ) -> Result<(), MastForestError> {
        self.advice_map
            .merge(advice_map)
            .map_err(|((key, _prev), _new)| MastForestError::AdviceMapKeyCollisionOnMerge(key))
    }

    pub fn finish(self) -> Result<MastForest, MastForestError> {
        self.finish_with_id_map().map(|(forest, _remapping)| forest)
    }

    pub fn finish_with_id_map(
        self,
    ) -> Result<(MastForest, DenseIdMap<MastNodeId, MastNodeId>), MastForestError> {
        MastForest::from_parts_with_id_map(MastForestParts {
            nodes: self.nodes,
            roots: self.roots,
            advice_map: self.advice_map,
        })
    }
}

impl MastNodeContext for DenseMastForestBuilder {
    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.nodes.get(node_id)
    }
}

impl From<IndexVec<MastNodeId, MastNode>> for DenseMastForestBuilder {
    fn from(nodes: IndexVec<MastNodeId, MastNode>) -> Self {
        Self {
            nodes,
            roots: Vec::new(),
            advice_map: AdviceMap::default(),
        }
    }
}
