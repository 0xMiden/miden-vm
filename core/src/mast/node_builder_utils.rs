use alloc::vec::Vec;

use crate::{
    LookupByIdx,
    mast::{
        BasicBlockNodeBuilder, DecoratorId, DynNodeBuilder, ExternalNodeBuilder, MastForest,
        MastForestContributor, MastForestError, MastNode, MastNodeBuilder, MastNodeId,
        node::MastNodeExt,
    },
};

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
            // For BasicBlockNode, we need to remap op-indexed decorators as well
            let builder = BasicBlockNodeBuilder::new(
                basic_block_node.operations().copied().collect(),
                basic_block_node
                    .indexed_decorator_iter(source_forest)
                    .map(|(idx, decorator_id)| {
                        let mapped_decorator = map_decorator_id(decorator_id)?;
                        Ok((idx, mapped_decorator))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .with_before_enter(before_enter_decorators)
            .with_after_exit(after_exit_decorators);
            MastNodeBuilder::BasicBlock(builder)
        },
        MastNode::Dyn(_) => {
            let builder = DynNodeBuilder::new_dyn()
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
