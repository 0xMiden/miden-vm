use crate::{
    mast::{
        BasicBlockNodeBuilder, DynNodeBuilder, ExternalNodeBuilder, MastForest,
        MastForestContributor, MastForestError, MastNode, MastNodeBuilder, MastNodeId,
        node::MastNodeExt,
    },
    utils::LookupByIdx,
};

/// Builds a node builder with remapped children using the provided mapping.
///
/// This is a generic helper used by both `MastForestMerger` and `MastForestBuilder` to avoid
/// code duplication when copying nodes between forests.
pub fn build_node_with_remapped_ids<NMap>(
    node_id: MastNodeId,
    node: MastNode,
    source_forest: &MastForest,
    node_remapping: &NMap,
) -> Result<MastNodeBuilder, MastForestError>
where
    NMap: LookupByIdx<MastNodeId, MastNodeId>,
{
    let _ = node_id;

    // Build node-specific builder with remapped children.
    let builder = match node {
        MastNode::Join(join_node) => {
            let builder = join_node.to_builder(source_forest).remap_children(node_remapping);
            MastNodeBuilder::Join(builder)
        },
        MastNode::Split(split_node) => {
            let builder = split_node.to_builder(source_forest).remap_children(node_remapping);
            MastNodeBuilder::Split(builder)
        },
        MastNode::Loop(loop_node) => {
            let builder = loop_node.to_builder(source_forest).remap_children(node_remapping);
            MastNodeBuilder::Loop(builder)
        },
        MastNode::Call(call_node) => {
            let builder = call_node.to_builder(source_forest).remap_children(node_remapping);
            MastNodeBuilder::Call(builder)
        },
        MastNode::Block(basic_block_node) => {
            // Preserve stored batches so copied blocks do not turn padding operations into raw
            // operations.
            let builder = BasicBlockNodeBuilder::from_op_batches(
                basic_block_node.op_batches().to_vec(),
                basic_block_node.digest(),
            );
            MastNodeBuilder::BasicBlock(builder)
        },
        MastNode::Dyn(dyn_node) => {
            let builder = if dyn_node.is_dyncall() {
                DynNodeBuilder::new_dyncall()
            } else {
                DynNodeBuilder::new_dyn()
            };
            MastNodeBuilder::Dyn(builder)
        },
        MastNode::External(external_node) => {
            let builder = ExternalNodeBuilder::new(external_node.digest());
            MastNodeBuilder::External(builder)
        },
    };

    Ok(builder)
}
