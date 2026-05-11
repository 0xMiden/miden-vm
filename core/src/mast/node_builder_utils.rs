use alloc::vec::Vec;

use crate::{
    mast::{
        BasicBlockNodeBuilder, DecoratorId, ExternalNodeBuilder, MastForest, MastForestContributor,
        MastForestError, MastNode, MastNodeBuilder, MastNodeId, node::MastNodeExt,
    },
    utils::LookupByIdx,
};

/// A MAST node whose decorator storage is owned by the node itself.
pub struct OwnedMastNode(MastNode);

impl TryFrom<MastNode> for OwnedMastNode {
    type Error = MastForestError;

    fn try_from(node: MastNode) -> Result<Self, Self::Error> {
        if node.has_linked_decorators() {
            return Err(MastForestError::LinkedDecoratorStorage);
        }

        Ok(Self(node))
    }
}

/// Builds a node builder with remapped children and decorators using the provided mappings.
///
/// This is a generic helper used by both `MastForestMerger` and `MastForestBuilder` to avoid
/// code duplication when copying nodes between forests.
pub fn build_node_with_remapped_ids<NMap, DMap>(
    node_id: MastNodeId,
    node: MastNode,
    source_forest: &MastForest,
    node_remapping: &NMap,
    decorator_remapping: &DMap,
) -> Result<MastNodeBuilder, MastForestError>
where
    NMap: LookupByIdx<MastNodeId, MastNodeId>,
    DMap: LookupByIdx<DecoratorId, DecoratorId>,
{
    let map_decorator_id = |decorator_id: DecoratorId| {
        decorator_remapping
            .get(decorator_id)
            .copied()
            .ok_or(MastForestError::DecoratorIdOverflow(decorator_id, 0))
    };

    let map_decorators = |decorators: &[DecoratorId]| -> Result<Vec<_>, MastForestError> {
        decorators.iter().copied().map(map_decorator_id).collect()
    };

    // Get decorators from source forest and remap them
    let before_enter_decorators = map_decorators(source_forest.before_enter_decorators(node_id))?;
    let after_exit_decorators = map_decorators(source_forest.after_exit_decorators(node_id))?;

    // Build node-specific builder with remapped children and decorators
    let builder = match node {
        MastNode::Join(join_node) => {
            let builder = join_node
                .to_builder(source_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Join(builder)
        },
        MastNode::Split(split_node) => {
            let builder = split_node
                .to_builder(source_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Split(builder)
        },
        MastNode::Loop(loop_node) => {
            let builder = loop_node
                .to_builder(source_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Loop(builder)
        },
        MastNode::Call(call_node) => {
            let builder = call_node
                .to_builder(source_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Call(builder)
        },
        MastNode::Block(basic_block_node) => {
            // Preserve the stored batches so copied blocks fingerprint the same way as raw-built
            // equivalents, even when padding NOOPs shifted stored metadata indices.
            let builder = BasicBlockNodeBuilder::from_op_batches(
                basic_block_node.op_batches().to_vec(),
                basic_block_node
                    .indexed_decorator_iter(source_forest)
                    .map(|(idx, decorator_id)| {
                        let mapped_decorator = map_decorator_id(decorator_id)?;
                        Ok((idx, mapped_decorator))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                basic_block_node.digest(),
            )
            .with_before_enter(before_enter_decorators)
            .with_after_exit(after_exit_decorators);
            MastNodeBuilder::BasicBlock(builder)
        },
        MastNode::Dyn(dyn_node) => {
            let builder = dyn_node
                .to_builder(source_forest)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Dyn(builder)
        },
        MastNode::External(external_node) => {
            let builder = ExternalNodeBuilder::new(external_node.digest())
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::External(builder)
        },
    };

    Ok(builder)
}

/// Builds an owned node builder with remapped children and decorators using the provided mappings.
///
/// This is intended for assembly-time pending nodes that have already been detached from their
/// temporary source forest. The node must own its decorator lists.
pub fn build_owned_node_with_remapped_ids<NMap, DMap>(
    node: OwnedMastNode,
    node_remapping: &NMap,
    decorator_remapping: &DMap,
) -> Result<MastNodeBuilder, MastForestError>
where
    NMap: LookupByIdx<MastNodeId, MastNodeId>,
    DMap: LookupByIdx<DecoratorId, DecoratorId>,
{
    let OwnedMastNode(node) = node;
    let map_decorator_id = |decorator_id: DecoratorId| {
        decorator_remapping
            .get(decorator_id)
            .copied()
            .ok_or(MastForestError::DecoratorIdOverflow(decorator_id, 0))
    };

    let map_decorators = |decorators: &[DecoratorId]| -> Result<Vec<_>, MastForestError> {
        decorators.iter().copied().map(map_decorator_id).collect()
    };

    let empty_forest = MastForest::new();

    let builder = match node {
        MastNode::Join(join_node) => {
            let before_enter_decorators = map_decorators(join_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(join_node.after_exit(&empty_forest))?;
            let builder = join_node
                .to_builder(&empty_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Join(builder)
        },
        MastNode::Split(split_node) => {
            let before_enter_decorators = map_decorators(split_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(split_node.after_exit(&empty_forest))?;
            let builder = split_node
                .to_builder(&empty_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Split(builder)
        },
        MastNode::Loop(loop_node) => {
            let before_enter_decorators = map_decorators(loop_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(loop_node.after_exit(&empty_forest))?;
            let builder = loop_node
                .to_builder(&empty_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Loop(builder)
        },
        MastNode::Call(call_node) => {
            let before_enter_decorators = map_decorators(call_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(call_node.after_exit(&empty_forest))?;
            let builder = call_node
                .to_builder(&empty_forest)
                .remap_children(node_remapping)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Call(builder)
        },
        MastNode::Block(basic_block_node) => {
            let before_enter_decorators =
                map_decorators(basic_block_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(basic_block_node.after_exit(&empty_forest))?;
            let builder = BasicBlockNodeBuilder::from_op_batches(
                basic_block_node.op_batches().to_vec(),
                basic_block_node
                    .indexed_decorator_iter(&empty_forest)
                    .map(|(idx, decorator_id)| {
                        let mapped_decorator = map_decorator_id(decorator_id)?;
                        Ok((idx, mapped_decorator))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                basic_block_node.digest(),
            )
            .with_before_enter(before_enter_decorators)
            .with_after_exit(after_exit_decorators);
            MastNodeBuilder::BasicBlock(builder)
        },
        MastNode::Dyn(dyn_node) => {
            let before_enter_decorators = map_decorators(dyn_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(dyn_node.after_exit(&empty_forest))?;
            let builder = dyn_node
                .to_builder(&empty_forest)
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::Dyn(builder)
        },
        MastNode::External(external_node) => {
            let before_enter_decorators =
                map_decorators(external_node.before_enter(&empty_forest))?;
            let after_exit_decorators = map_decorators(external_node.after_exit(&empty_forest))?;
            let builder = ExternalNodeBuilder::new(external_node.digest())
                .with_before_enter(before_enter_decorators)
                .with_after_exit(after_exit_decorators);
            MastNodeBuilder::External(builder)
        },
    };

    Ok(builder)
}
