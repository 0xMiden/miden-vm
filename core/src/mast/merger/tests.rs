use alloc::{collections::BTreeMap, string::String, sync::Arc};

use super::*;
use crate::{
    Felt, ONE, Word,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        LoopNodeBuilder,
        node::{MastForestContributor, MastNodeExt},
    },
    operations::{AssemblyOp, DebugVarInfo, DebugVarLocation, Operation},
    utils::Idx,
};

fn block_foo() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::Mul, Operation::Add])
}

fn block_bar() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::And, Operation::Eq])
}

fn block_qux() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Push(ONE), Operation::Eq])
}

fn register_asm_ops_for_node(
    forest: &mut MastForest,
    node_id: MastNodeId,
    num_operations: usize,
    asm_ops: &[(usize, AssemblyOp)],
) -> Vec<AsmOpId> {
    let mut registered = Vec::with_capacity(asm_ops.len());
    for (op_idx, asm_op) in asm_ops {
        let asm_op_id = forest.debug_info_mut().add_asm_op(asm_op.clone()).unwrap();
        registered.push((*op_idx, asm_op_id));
    }

    forest
        .debug_info_mut()
        .register_asm_ops(node_id, num_operations, registered.clone())
        .unwrap();

    registered.into_iter().map(|(_, asm_op_id)| asm_op_id).collect()
}

/// Asserts that the given forest contains exactly one node with the given digest.
///
/// Returns a Result which can be unwrapped in the calling test function to assert. This way, if
/// this assertion fails it'll be clear which exact call failed.
fn assert_contains_node_once(forest: &MastForest, digest: Word) -> Result<(), &str> {
    if forest.nodes.iter().filter(|node| node.digest() == digest).count() != 1 {
        return Err("node digest contained more than once in the forest");
    }

    Ok(())
}

/// Asserts that every root of an original forest has an id to which it is mapped and that this
/// mapped root is in the set of roots in the merged forest.
///
/// Returns a Result which can be unwrapped in the calling test function to assert. This way, if
/// this assertion fails it'll be clear which exact call failed.
fn assert_root_mapping(
    root_map: &MastForestRootMap,
    original_roots: Vec<&[MastNodeId]>,
    merged_roots: &[MastNodeId],
) -> Result<(), &'static str> {
    for (forest_idx, original_root) in original_roots.into_iter().enumerate() {
        for root in original_root {
            let mapped_root = root_map.map_root(forest_idx, root).unwrap();
            if !merged_roots.contains(&mapped_root) {
                return Err("merged root does not contain mapped root");
            }
        }
    }

    Ok(())
}

/// Asserts that all children of nodes in the given forest have an id that is less than the parent's
/// ID.
#[track_caller]
fn assert_child_id_lt_parent_id(forest: &MastForest) {
    for (mast_node_id, node) in forest.nodes().iter().enumerate() {
        node.for_each_child(|child_id| {
            if child_id.to_usize() >= mast_node_id {
                panic!("child id {} is not < parent id {}", child_id.to_usize(), mast_node_id);
            }
        });
    }
}

#[test]
fn mast_forest_merge_preserves_dyn_callness_and_digest() {
    let mut forest = MastForest::new();

    let dynexec_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
    let dyncall_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
    forest.make_root(dynexec_id);
    forest.make_root(dyncall_id);

    let dynexec_digest = forest[dynexec_id].digest();
    let dyncall_digest = forest[dyncall_id].digest();

    let (merged, root_maps) = MastForest::merge([&forest]).unwrap();

    let merged_dynexec_id = root_maps.map_root(0, &dynexec_id).unwrap();
    let merged_dyncall_id = root_maps.map_root(0, &dyncall_id).unwrap();

    assert_ne!(
        merged_dynexec_id, merged_dyncall_id,
        "dynexec and dyncall nodes should not be deduplicated"
    );

    let merged_dynexec = merged[merged_dynexec_id].unwrap_dyn();
    let merged_dyncall = merged[merged_dyncall_id].unwrap_dyn();

    assert!(!merged_dynexec.is_dyncall(), "dynexec node should remain dynexec after merge");
    assert!(merged_dyncall.is_dyncall(), "dyncall node should remain dyncall after merge");
    assert_eq!(merged_dynexec.digest(), dynexec_digest, "dynexec digest should be preserved");
    assert_eq!(merged_dyncall.digest(), dyncall_digest, "dyncall digest should be preserved");
}

#[test]
fn mast_forest_merge_preserves_padded_basic_block_batches() {
    let mut forest = MastForest::new();

    let operations = vec![Operation::Add, Operation::Push(Felt::new_unchecked(100))];
    let block_id = BasicBlockNodeBuilder::new(operations.clone())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let original_block = forest[block_id].unwrap_basic_block();
    assert!(
        original_block.operations().count() > original_block.raw_operations().count(),
        "test input must create padded operations"
    );
    let original_batches = original_block.op_batches().to_vec();

    let (merged, root_maps) = MastForest::merge([&forest]).unwrap();

    let merged_block_id = root_maps.map_root(0, &block_id).unwrap();
    let merged_block = merged[merged_block_id].unwrap_basic_block();
    assert_eq!(
        merged_block.raw_operations().copied().collect::<Vec<_>>(),
        operations,
        "merge must not treat padded operations as raw operations"
    );
    assert_eq!(
        merged_block.op_batches(),
        original_batches,
        "merge must preserve the original batch layout"
    );
}

/// Tests that Call(bar) still correctly calls the remapped bar block.
///
/// [Block(foo), Call(foo)]
/// +
/// [Block(bar), Call(bar)]
/// =
/// [Block(foo), Call(foo), Block(bar), Call(bar)]
#[test]
fn mast_forest_merge_remap() {
    let mut forest_a = MastForest::new();
    let id_foo = block_foo().add_to_forest(&mut forest_a).unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);

    let (mut merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    assert_eq!(merged.nodes().len(), 4);

    // Check that the first node is semantically equal to the expected foo block
    // Build expected nodes in the merged forest for proper semantic comparison
    let expected_foo_id = block_foo().add_to_forest(&mut merged).unwrap();
    let expected_foo_block = merged.get_node_by_id(expected_foo_id).unwrap().unwrap_basic_block();
    assert_matches!(&merged.nodes()[0], MastNode::Block(merged_block)
        if merged_block.semantic_eq(expected_foo_block));

    assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if 0u32 == u32::from(call_node.callee()));

    // Check that the third node is semantically equal to the expected bar block
    let expected_bar_id = block_bar().add_to_forest(&mut merged).unwrap();
    let expected_bar_block = merged.get_node_by_id(expected_bar_id).unwrap().unwrap_basic_block();
    assert_matches!(&merged.nodes()[2], MastNode::Block(merged_block)
        if merged_block.semantic_eq(expected_bar_block));
    assert_matches!(&merged.nodes()[3], MastNode::Call(call_node) if 2u32 == u32::from(call_node.callee()));

    assert_eq!(u32::from(root_maps.map_root(0, &id_call_a).unwrap()), 1u32);
    assert_eq!(u32::from(root_maps.map_root(1, &id_call_b).unwrap()), 3u32);

    assert_child_id_lt_parent_id(&merged);
}

/// Tests that Forest_A + Forest_A = Forest_A (i.e. duplicates are removed).
#[test]
fn mast_forest_merge_duplicate() {
    let mut forest_a = MastForest::new();

    let bar_block_id = block_bar().add_to_forest(&mut forest_a).unwrap();
    let bar_block = forest_a.get_node_by_id(bar_block_id).unwrap().unwrap_basic_block();
    let id_external = ExternalNodeBuilder::new(bar_block.digest())
        .add_to_forest(&mut forest_a)
        .unwrap();
    let id_foo = block_foo().add_to_forest(&mut forest_a).unwrap();
    let id_call = CallNodeBuilder::new(id_foo).add_to_forest(&mut forest_a).unwrap();
    let id_loop = LoopNodeBuilder::new(id_external).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call);
    forest_a.make_root(id_loop);

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_a]).unwrap();

    for merged_root in merged.procedure_digests() {
        forest_a.procedure_digests().find(|root| root == &merged_root).unwrap();
    }

    // Both maps should map the roots to the same target id.
    for original_root in forest_a.procedure_roots() {
        assert_eq!(&root_maps.map_root(0, original_root), &root_maps.map_root(1, original_root));
    }

    for merged_node in merged.nodes().iter().map(MastNode::digest) {
        forest_a.nodes.iter().find(|node| node.digest() == merged_node).unwrap();
    }

    assert_child_id_lt_parent_id(&merged);
}

/// Tests that External(foo) is replaced by Block(foo) whether it is in forest A or B, and the
/// duplicate Call is removed.
///
/// [External(foo), Call(foo)]
/// +
/// [Block(foo), Call(foo)]
/// =
/// [Block(foo), Call(foo)]
/// +
/// [External(foo), Call(foo)]
/// =
/// [Block(foo), Call(foo)]
#[test]
fn mast_forest_merge_replace_external() {
    let mut forest_a = MastForest::new();
    let foo_block_a = block_foo().build().unwrap();
    let id_foo_a = ExternalNodeBuilder::new(foo_block_a.digest())
        .add_to_forest(&mut forest_a)
        .unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo_a).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_foo_b).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);

    let (merged_ab, root_maps_ab) = MastForest::merge([&forest_a, &forest_b]).unwrap();
    let (merged_ba, root_maps_ba) = MastForest::merge([&forest_b, &forest_a]).unwrap();

    for (mut merged, root_map) in [(merged_ab, root_maps_ab), (merged_ba, root_maps_ba)] {
        assert_eq!(merged.nodes().len(), 2);

        // Check that the first node is semantically equal to the expected foo block
        // Build expected node in the merged forest for proper semantic comparison
        let expected_foo_id = block_foo().add_to_forest(&mut merged).unwrap();
        let expected_foo_block =
            merged.get_node_by_id(expected_foo_id).unwrap().unwrap_basic_block();
        assert_matches!(&merged.nodes()[0], MastNode::Block(merged_block)
            if merged_block.semantic_eq(expected_foo_block));

        assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if 0u32 == u32::from(call_node.callee()));
        // The only root node should be the call node.
        assert_eq!(merged.roots.len(), 1);
        assert_eq!(root_map.map_root(0, &id_call_a).unwrap().to_usize(), 1);
        assert_eq!(root_map.map_root(1, &id_call_b).unwrap().to_usize(), 1);
        assert_child_id_lt_parent_id(&merged);
    }
}

/// Test that roots are preserved and deduplicated if appropriate.
///
/// Nodes: [Block(foo), Call(foo)]
/// Roots: [Call(foo)]
/// +
/// Nodes: [Block(foo), Block(bar), Call(foo)]
/// Roots: [Block(bar), Call(foo)]
/// =
/// Nodes: [Block(foo), Block(bar), Call(foo)]
/// Roots: [Block(bar), Call(foo)]
#[test]
fn mast_forest_merge_roots() {
    let mut forest_a = MastForest::new();
    let id_foo_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    let call_a = CallNodeBuilder::new(id_foo_a).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    let id_bar_b = block_bar().add_to_forest(&mut forest_b).unwrap();
    let call_b = CallNodeBuilder::new(id_foo_b).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_bar_b);
    forest_b.make_root(call_b);

    let root_digest_call_a = forest_a.get_node_by_id(call_a).unwrap().digest();
    let root_digest_bar_b = forest_b.get_node_by_id(id_bar_b).unwrap().digest();
    let root_digest_call_b = forest_b.get_node_by_id(call_b).unwrap().digest();

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    // Asserts (together with the other assertions) that the duplicate Call(foo) roots have been
    // deduplicated.
    assert_eq!(merged.procedure_roots().len(), 2);

    // Assert that all root digests from A an B are still roots in the merged forest.
    let root_digests = merged.procedure_digests().collect::<Vec<_>>();
    assert!(root_digests.contains(&root_digest_call_a));
    assert!(root_digests.contains(&root_digest_bar_b));
    assert!(root_digests.contains(&root_digest_call_b));

    assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots).unwrap();

    assert_child_id_lt_parent_id(&merged);
}

/// Test that multiple trees can be merged when the same merger is reused.
///
/// Nodes: [Block(foo), Call(foo)]
/// Roots: [Call(foo)]
/// +
/// Nodes: [Block(foo), Block(bar), Call(foo)]
/// Roots: [Block(bar), Call(foo)]
/// +
/// Nodes: [Block(foo), Block(qux), Call(foo)]
/// Roots: [Block(qux), Call(foo)]
/// =
/// Nodes: [Block(foo), Block(bar), Block(qux), Call(foo)]
/// Roots: [Block(bar), Block(qux), Call(foo)]
#[test]
fn mast_forest_merge_multiple() {
    let mut forest_a = MastForest::new();
    let id_foo_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    let call_a = CallNodeBuilder::new(id_foo_a).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    let id_bar_b = block_bar().add_to_forest(&mut forest_b).unwrap();
    let call_b = CallNodeBuilder::new(id_foo_b).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_bar_b);
    forest_b.make_root(call_b);

    let mut forest_c = MastForest::new();
    let id_foo_c = block_foo().add_to_forest(&mut forest_c).unwrap();
    let id_qux_c = block_qux().add_to_forest(&mut forest_c).unwrap();
    let call_c = CallNodeBuilder::new(id_foo_c).add_to_forest(&mut forest_c).unwrap();
    forest_c.make_root(id_qux_c);
    forest_c.make_root(call_c);

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b, &forest_c]).unwrap();

    let block_foo_digest = forest_b.get_node_by_id(id_foo_b).unwrap().digest();
    let block_bar_digest = forest_b.get_node_by_id(id_bar_b).unwrap().digest();
    let call_foo_digest = forest_b.get_node_by_id(call_b).unwrap().digest();
    let block_qux_digest = forest_c.get_node_by_id(id_qux_c).unwrap().digest();

    assert_eq!(merged.procedure_roots().len(), 3);

    let root_digests = merged.procedure_digests().collect::<Vec<_>>();
    assert!(root_digests.contains(&call_foo_digest));
    assert!(root_digests.contains(&block_bar_digest));
    assert!(root_digests.contains(&block_qux_digest));

    assert_contains_node_once(&merged, block_foo_digest).unwrap();
    assert_contains_node_once(&merged, block_bar_digest).unwrap();
    assert_contains_node_once(&merged, block_qux_digest).unwrap();
    assert_contains_node_once(&merged, call_foo_digest).unwrap();

    assert_root_mapping(
        &root_maps,
        vec![&forest_a.roots, &forest_b.roots, &forest_c.roots],
        &merged.roots,
    )
    .unwrap();

    assert_child_id_lt_parent_id(&merged);
}

/// Tests that assembly operation mappings are preserved when an external node is replaced by a
/// concrete node from another forest.
#[test]
fn mast_forest_merge_preserves_asm_op_mappings_from_external_replacement() {
    let mut forest_with_external = MastForest::new();
    let foo_digest = block_foo().build().unwrap().digest();
    let external_id = ExternalNodeBuilder::new(foo_digest)
        .add_to_forest(&mut forest_with_external)
        .unwrap();
    forest_with_external.make_root(external_id);

    let external_asm_op = AssemblyOp::new(None, "proc::caller".into(), 1, "call.foo".into());
    let external_asm_op_id = forest_with_external
        .debug_info_mut()
        .add_asm_op(external_asm_op.clone())
        .unwrap();
    forest_with_external
        .debug_info_mut()
        .register_asm_ops(external_id, 1, vec![(0, external_asm_op_id)])
        .unwrap();

    let mut forest_with_block = MastForest::new();
    let block_id = block_foo().add_to_forest(&mut forest_with_block).unwrap();
    forest_with_block.make_root(block_id);

    let (merged_ext_then_block, root_maps_ext_then_block) =
        MastForest::merge([&forest_with_external, &forest_with_block]).unwrap();
    let mapped_external_root = root_maps_ext_then_block.map_root(0, &external_id).unwrap();
    assert_eq!(
        merged_ext_then_block.get_assembly_op(mapped_external_root, None),
        Some(&external_asm_op),
    );

    let (merged_block_then_ext, root_maps_block_then_ext) =
        MastForest::merge([&forest_with_block, &forest_with_external]).unwrap();
    let mapped_external_root = root_maps_block_then_ext.map_root(1, &external_id).unwrap();
    assert_eq!(
        merged_block_then_ext.get_assembly_op(mapped_external_root, None),
        Some(&external_asm_op),
    );
}

/// Tests that dependencies between External nodes are correctly resolved.
///
/// [External(foo), Call(0) = qux]
/// +
/// [External(qux), Call(0), Block(foo)]
/// =
/// [External(qux), Call(0), Block(foo)]
/// +
/// [External(foo), Call(0) = qux]
/// =
/// [Block(foo), Call(0), Call(1)]
#[test]
fn mast_forest_merge_external_dependencies() {
    let mut forest_a = MastForest::new();
    let id_foo_a = ExternalNodeBuilder::new(block_qux().build().unwrap().digest())
        .add_to_forest(&mut forest_a)
        .unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo_a).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_ext_b = ExternalNodeBuilder::new(forest_a[id_call_a].digest())
        .add_to_forest(&mut forest_b)
        .unwrap();
    let id_call_b = CallNodeBuilder::new(id_ext_b).add_to_forest(&mut forest_b).unwrap();
    let id_qux_b = block_qux().add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    forest_b.make_root(id_qux_b);

    for (merged, _) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    {
        let digests = merged.nodes().iter().map(MastNodeExt::digest).collect::<Vec<_>>();
        assert_eq!(merged.nodes().len(), 3);
        assert!(digests.contains(&forest_b[id_ext_b].digest()));
        assert!(digests.contains(&forest_b[id_call_b].digest()));
        assert!(digests.contains(&forest_a[id_foo_a].digest()));
        assert!(digests.contains(&forest_a[id_call_a].digest()));
        assert!(digests.contains(&forest_b[id_qux_b].digest()));
        assert_eq!(merged.nodes().iter().filter(|node| node.is_external()).count(), 0);

        assert_child_id_lt_parent_id(&merged);
    }
}

/// Tests that forest advice maps are merged correctly.
#[test]
fn mast_forest_merge_advice_maps_merged() {
    let mut forest_a = MastForest::new();
    let id_foo = block_foo().add_to_forest(&mut forest_a).unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);
    let key_a = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let value_a = vec![ONE, ONE];
    forest_a = forest_a.with_advice_map(AdviceMap::from_iter([(key_a, value_a.clone())]));

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    let key_b = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(3),
        Felt::new_unchecked(2),
        Felt::new_unchecked(1),
    ]);
    let value_b = vec![Felt::new_unchecked(2), Felt::new_unchecked(2)];
    forest_b = forest_b.with_advice_map(AdviceMap::from_iter([(key_b, value_b.clone())]));

    let (merged, _root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    let merged_advice_map = merged.advice_map();
    assert_eq!(merged_advice_map.len(), 2);
    assert_eq!(merged_advice_map.get(&key_a).unwrap().as_ref(), value_a);
    assert_eq!(merged_advice_map.get(&key_b).unwrap().as_ref(), value_b);
}

/// Tests that an error is returned when advice maps have a key collision.
#[test]
fn mast_forest_merge_advice_maps_collision() {
    let mut forest_a = MastForest::new();
    let id_foo = block_foo().add_to_forest(&mut forest_a).unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);
    let key_a = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let value_a = vec![ONE, ONE];
    forest_a = forest_a.with_advice_map(AdviceMap::from_iter([(key_a, value_a)]));

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    // The key collides with key_a in the forest_a.
    let key_b = key_a;
    let value_b = vec![Felt::new_unchecked(2), Felt::new_unchecked(2)];
    forest_b = forest_b.with_advice_map(AdviceMap::from_iter([(key_b, value_b)]));

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::AdviceMapKeyCollisionOnMerge(_));
}

#[test]
fn mast_forest_merge_preserves_asm_op_mappings_for_deduplicated_nodes() {
    let mut forest_without_asm = MastForest::new();
    let without_asm_block_id = block_foo().add_to_forest(&mut forest_without_asm).unwrap();
    forest_without_asm.make_root(without_asm_block_id);

    let mut forest_with_asm = MastForest::new();
    let with_asm_block_id = block_foo().add_to_forest(&mut forest_with_asm).unwrap();
    forest_with_asm.make_root(with_asm_block_id);

    let asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "mul".into());
    register_asm_ops_for_node(&mut forest_with_asm, with_asm_block_id, 2, &[(0, asm_op.clone())]);

    // Mapping from the second forest must be preserved even when the node was already deduped
    // after merging the first forest.
    let (merged_without_then_with, root_maps_without_then_with) =
        MastForest::merge([&forest_without_asm, &forest_with_asm]).unwrap();
    let mapped_with_asm_root = root_maps_without_then_with.map_root(1, &with_asm_block_id).unwrap();

    assert_eq!(
        merged_without_then_with.get_assembly_op(mapped_with_asm_root, Some(0)),
        Some(&asm_op),
    );

    // Reverse order should behave identically.
    let (merged_with_then_without, root_maps_with_then_without) =
        MastForest::merge([&forest_with_asm, &forest_without_asm]).unwrap();
    let mapped_with_asm_root = root_maps_with_then_without.map_root(0, &with_asm_block_id).unwrap();

    assert_eq!(
        merged_with_then_without.get_assembly_op(mapped_with_asm_root, Some(0)),
        Some(&asm_op),
    );
}

#[test]
fn mast_forest_merge_returns_error_for_out_of_bounds_asm_op_mapping() {
    let mut forest = MastForest::new();
    let block_id = block_foo().add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);

    let asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "out-of-bounds".into());
    let asm_op_id = forest.debug_info_mut().add_asm_op(asm_op).unwrap();
    forest
        .debug_info_mut()
        .register_asm_ops(block_id, 3, vec![(2, asm_op_id)])
        .unwrap();

    let err = MastForest::merge([&forest]).unwrap_err();
    assert_matches!(
        err,
        MastForestError::AssemblyOpError(crate::mast::AsmOpIndexError::OpIndexOutOfBounds(2, 2))
    );
}

#[test]
fn mast_forest_merge_preserves_explicit_adjacent_asm_op_transitions() {
    let mut forest_lhs = MastForest::new();
    let lhs_block_id = block_foo().add_to_forest(&mut forest_lhs).unwrap();
    forest_lhs.make_root(lhs_block_id);

    let lhs_asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "mul".into());
    register_asm_ops_for_node(
        &mut forest_lhs,
        lhs_block_id,
        2,
        &[(0, lhs_asm_op.clone()), (1, lhs_asm_op)],
    );

    let mut forest_rhs = MastForest::new();
    let rhs_block_id = block_foo().add_to_forest(&mut forest_rhs).unwrap();
    forest_rhs.make_root(rhs_block_id);

    let rhs_asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "mul".into());
    register_asm_ops_for_node(
        &mut forest_rhs,
        rhs_block_id,
        2,
        &[(0, rhs_asm_op.clone()), (1, rhs_asm_op)],
    );

    let (merged, root_maps) = MastForest::merge([&forest_lhs, &forest_rhs]).unwrap();
    let mapped_lhs_root = root_maps.map_root(0, &lhs_block_id).unwrap();
    let mapped_rhs_root = root_maps.map_root(1, &rhs_block_id).unwrap();
    assert_eq!(mapped_lhs_root, mapped_rhs_root);

    let mapped_with_asm_root = mapped_lhs_root;
    let merged_entries = merged.debug_info().asm_ops_for_node(mapped_with_asm_root);

    assert_eq!(merged_entries.len(), 2);
    assert_eq!(merged_entries[0].0, 0);
    assert_eq!(merged_entries[1].0, 1);
    assert_eq!(merged_entries[0].1, merged_entries[1].1);
}

#[test]
fn mast_forest_merge_deduplicates_same_blocks_with_different_asm_ops() {
    let mut forest_lhs = MastForest::new();
    let lhs_block_id = block_foo().add_to_forest(&mut forest_lhs).unwrap();
    forest_lhs.make_root(lhs_block_id);

    let lhs_asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "lhs-op".into());
    register_asm_ops_for_node(&mut forest_lhs, lhs_block_id, 2, &[(0, lhs_asm_op)]);

    let mut forest_rhs = MastForest::new();
    let rhs_block_id = block_foo().add_to_forest(&mut forest_rhs).unwrap();
    forest_rhs.make_root(rhs_block_id);

    let rhs_asm_op = AssemblyOp::new(None, "proc::foo".into(), 1, "rhs-op".into());
    register_asm_ops_for_node(&mut forest_rhs, rhs_block_id, 2, &[(0, rhs_asm_op.clone())]);

    let (merged, root_maps) = MastForest::merge([&forest_lhs, &forest_rhs]).unwrap();
    let mapped_lhs_block = root_maps.map_root(0, &lhs_block_id).unwrap();
    let mapped_rhs_block = root_maps.map_root(1, &rhs_block_id).unwrap();

    assert_eq!(
        mapped_lhs_block, mapped_rhs_block,
        "identical blocks must collapse even with different asm-op metadata"
    );
    assert_eq!(merged.get_assembly_op(mapped_lhs_block, Some(0)), Some(&rhs_asm_op));
}

#[test]
fn merge_asm_op_mappings_prefers_richer_mapping() {
    let asm_mul = AsmOpId::new(0);
    let asm_add = AsmOpId::new(1);
    let coarse = vec![(0, asm_mul)];
    let rich = vec![(0, asm_mul), (1, asm_add)];
    let asm_op_value_by_id = BTreeMap::from([
        (asm_mul, (None, String::from("proc::foo"), 1, String::from("mul"))),
        (asm_add, (None, String::from("proc::foo"), 1, String::from("add"))),
    ]);

    assert_eq!(
        MastForestMerger::merge_asm_op_mappings(2, &coarse, &rich, &asm_op_value_by_id),
        rich
    );
    assert_eq!(
        MastForestMerger::merge_asm_op_mappings(2, &rich, &coarse, &asm_op_value_by_id),
        rich
    );
}

#[test]
fn mast_forest_merge_preserves_sparse_non_block_asm_op_mappings() {
    let mut forest_without_asm = MastForest::new();
    let without_asm_callee_id = block_foo().add_to_forest(&mut forest_without_asm).unwrap();
    let without_asm_call_id = CallNodeBuilder::new(without_asm_callee_id)
        .add_to_forest(&mut forest_without_asm)
        .unwrap();
    forest_without_asm.make_root(without_asm_call_id);

    let mut forest_with_asm = MastForest::new();
    let with_asm_callee_id = block_foo().add_to_forest(&mut forest_with_asm).unwrap();
    let with_asm_call_id = CallNodeBuilder::new(with_asm_callee_id)
        .add_to_forest(&mut forest_with_asm)
        .unwrap();
    forest_with_asm.make_root(with_asm_call_id);

    let asm_enter = AssemblyOp::new(None, "proc::caller".into(), 1, "call.enter".into());
    let asm_exit = AssemblyOp::new(None, "proc::caller".into(), 1, "call.exit".into());
    register_asm_ops_for_node(
        &mut forest_with_asm,
        with_asm_call_id,
        4,
        &[(1, asm_enter.clone()), (3, asm_exit.clone())],
    );

    let (merged_without_then_with, root_maps_without_then_with) =
        MastForest::merge([&forest_without_asm, &forest_with_asm]).unwrap();
    let mapped_call = root_maps_without_then_with.map_root(1, &with_asm_call_id).unwrap();
    assert_eq!(merged_without_then_with.get_assembly_op(mapped_call, Some(0)), None);
    assert_eq!(merged_without_then_with.get_assembly_op(mapped_call, Some(1)), Some(&asm_enter));
    assert_eq!(merged_without_then_with.get_assembly_op(mapped_call, Some(2)), Some(&asm_enter));
    assert_eq!(merged_without_then_with.get_assembly_op(mapped_call, Some(3)), Some(&asm_exit));

    let (merged_with_then_without, root_maps_with_then_without) =
        MastForest::merge([&forest_with_asm, &forest_without_asm]).unwrap();
    let mapped_call = root_maps_with_then_without.map_root(0, &with_asm_call_id).unwrap();
    assert_eq!(merged_with_then_without.get_assembly_op(mapped_call, Some(0)), None);
    assert_eq!(merged_with_then_without.get_assembly_op(mapped_call, Some(1)), Some(&asm_enter));
    assert_eq!(merged_with_then_without.get_assembly_op(mapped_call, Some(2)), Some(&asm_enter));
    assert_eq!(merged_with_then_without.get_assembly_op(mapped_call, Some(3)), Some(&asm_exit));
}

#[test]
fn merge_asm_op_mappings_equal_richness_conflicts_choose_whole_mapping() {
    let asm_shared = AsmOpId::new(0);
    let asm_lhs_only = AsmOpId::new(1);
    let asm_rhs_only = AsmOpId::new(2);
    let lhs = vec![(0, asm_shared), (1, asm_lhs_only)];
    let rhs = vec![(0, asm_rhs_only), (1, asm_shared)];
    let asm_op_value_by_id = BTreeMap::from([
        (asm_shared, (None, String::from("proc::foo"), 1, String::from("shared"))),
        (asm_lhs_only, (None, String::from("proc::foo"), 1, String::from("lhs-only"))),
        (asm_rhs_only, (None, String::from("proc::foo"), 1, String::from("rhs-only"))),
    ]);

    let mapping_lhs_then_rhs =
        MastForestMerger::merge_asm_op_mappings(2, &lhs, &rhs, &asm_op_value_by_id);
    let mapping_rhs_then_lhs =
        MastForestMerger::merge_asm_op_mappings(2, &rhs, &lhs, &asm_op_value_by_id);

    assert_eq!(
        mapping_lhs_then_rhs, mapping_rhs_then_lhs,
        "equal-richness conflicts should resolve deterministically independent of merge order"
    );
    assert!(
        mapping_lhs_then_rhs == lhs || mapping_lhs_then_rhs == rhs,
        "merged mapping should match one full input mapping"
    );
    assert_ne!(
        mapping_lhs_then_rhs,
        vec![(0, asm_shared), (1, asm_shared)],
        "merged mapping should not synthesize a mixed mapping"
    );
}

/// Merging two forests preserves procedure names, asm ops, and debug vars
/// with correct node-ID remapping.
#[test]
fn merge_preserves_debug_metadata() {
    // Forest A: one block with asm op + debug var + procedure name.
    let mut forest_a = MastForest::new();
    let asm_op = AssemblyOp::new(None, "test".into(), 1, "add".into());
    let asm_id_a = forest_a.debug_info_mut().add_asm_op(asm_op).unwrap();
    let dvar_a = forest_a
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();

    let block_a_id = block_foo().add_to_forest(&mut forest_a).unwrap();
    let num_ops_a = forest_a[block_a_id].get_basic_block().unwrap().num_operations() as usize;
    forest_a
        .debug_info_mut()
        .register_asm_ops(block_a_id, num_ops_a, vec![(0, asm_id_a)])
        .unwrap();
    forest_a
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_a_id, vec![(0, dvar_a)])
        .unwrap();
    forest_a.make_root(block_a_id);
    let digest_a = forest_a[block_a_id].digest();
    forest_a.insert_procedure_name(digest_a, Arc::from("proc_a"));

    // Forest B: different block with its own asm op + debug var + procedure name.
    let mut forest_b = MastForest::new();
    let asm_op_b = AssemblyOp::new(None, "test".into(), 1, "and".into());
    let asm_id_b = forest_b.debug_info_mut().add_asm_op(asm_op_b).unwrap();
    let dvar_b = forest_b
        .add_debug_var(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
        .unwrap();

    let block_b_id = block_bar().add_to_forest(&mut forest_b).unwrap();
    let num_ops_b = forest_b[block_b_id].get_basic_block().unwrap().num_operations() as usize;
    forest_b
        .debug_info_mut()
        .register_asm_ops(block_b_id, num_ops_b, vec![(0, asm_id_b)])
        .unwrap();
    forest_b
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_b_id, vec![(0, dvar_b)])
        .unwrap();
    forest_b.make_root(block_b_id);
    let digest_b = forest_b[block_b_id].digest();
    forest_b.insert_procedure_name(digest_b, Arc::from("proc_b"));

    // Merge.
    let (merged, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    // Both procedure names must be present.
    assert_eq!(merged.procedure_name(&digest_a), Some("proc_a"));
    assert_eq!(merged.procedure_name(&digest_b), Some("proc_b"));

    // Both nodes must have asm ops.
    let new_a = root_map.map_root(0, &block_a_id).unwrap();
    let new_b = root_map.map_root(1, &block_b_id).unwrap();

    assert!(
        merged.debug_info().first_asm_op_for_node(new_a).is_some(),
        "merged node A must have asm op"
    );
    assert!(
        merged.debug_info().first_asm_op_for_node(new_b).is_some(),
        "merged node B must have asm op"
    );

    // Both nodes must have debug vars.
    let vars_a = merged.debug_info().debug_vars_for_node(new_a);
    let vars_b = merged.debug_info().debug_vars_for_node(new_b);
    assert_eq!(vars_a.len(), 1, "merged node A must have debug var");
    assert_eq!(vars_b.len(), 1, "merged node B must have debug var");
}

/// compact() (which is a self-merge) must keep debug metadata intact.
#[test]
fn compact_preserves_debug_metadata() {
    let mut forest = MastForest::new();
    let asm_op = AssemblyOp::new(None, "test".into(), 1, "add".into());
    let asm_id = forest.debug_info_mut().add_asm_op(asm_op).unwrap();
    let dvar = forest
        .add_debug_var(DebugVarInfo::new("z", DebugVarLocation::Stack(2)))
        .unwrap();

    let block_id = block_foo().add_to_forest(&mut forest).unwrap();
    let num_ops = forest[block_id].get_basic_block().unwrap().num_operations() as usize;
    forest
        .debug_info_mut()
        .register_asm_ops(block_id, num_ops, vec![(0, asm_id)])
        .unwrap();
    forest
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_id, vec![(0, dvar)])
        .unwrap();
    forest.make_root(block_id);
    let digest = forest[block_id].digest();
    forest.insert_procedure_name(digest, Arc::from("my_proc"));

    let (compacted, _root_map) = forest.compact();

    // Find the node by digest in the compacted forest.
    let compacted_id = compacted.find_procedure_root(digest).expect("root should survive compact");

    assert_eq!(compacted.procedure_name(&digest), Some("my_proc"));
    assert!(
        compacted.debug_info().first_asm_op_for_node(compacted_id).is_some(),
        "compacted node must keep asm op"
    );
    let vars = compacted.debug_info().debug_vars_for_node(compacted_id);
    assert_eq!(vars.len(), 1, "compacted node must keep debug var");
}

/// Two basic blocks with the same ops but different debug vars have the same MAST shape.
#[test]
fn merge_deduplicates_blocks_with_different_debug_vars() {
    // Forest A: block [Mul, Add] with debug var "x" at stack 0.
    let mut forest_a = MastForest::new();
    let dvar_a = forest_a
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    forest_a
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_a, vec![(0, dvar_a)])
        .unwrap();
    forest_a.make_root(block_a);

    // Forest B: identical block [Mul, Add] but with debug var "y" at stack 1.
    let mut forest_b = MastForest::new();
    let dvar_b = forest_b
        .add_debug_var(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
        .unwrap();
    let block_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    forest_b
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_b, vec![(0, dvar_b)])
        .unwrap();
    forest_b.make_root(block_b);

    let (merged, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(1, &block_b).unwrap();

    assert_eq!(new_a, new_b, "debug vars must not affect MAST shape");

    let vars_a = merged.debug_info().debug_vars_for_node(new_a);
    assert_eq!(vars_a.len(), 1);

    let info_a = merged.debug_info().debug_var(vars_a[0].1).unwrap();
    assert_eq!(info_a.name(), "x");
}

/// Two blocks with identical structure and debug vars but different asm-op metadata have the same
/// MAST shape.
#[test]
fn merge_deduplicates_blocks_with_different_asm_ops() {
    let mut forest_a = MastForest::new();
    let asm_id_a = forest_a
        .debug_info_mut()
        .add_asm_op(AssemblyOp::new(None, "ctx_a".into(), 1, "mul add".into()))
        .unwrap();
    let dvar_a = forest_a
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    let num_ops_a = forest_a[block_a].get_basic_block().unwrap().num_operations() as usize;
    forest_a
        .debug_info_mut()
        .register_asm_ops(block_a, num_ops_a, vec![(0, asm_id_a)])
        .unwrap();
    forest_a
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_a, vec![(0, dvar_a)])
        .unwrap();
    forest_a.make_root(block_a);

    let mut forest_b = MastForest::new();
    let asm_id_b = forest_b
        .debug_info_mut()
        .add_asm_op(AssemblyOp::new(None, "ctx_b".into(), 1, "mul add".into()))
        .unwrap();
    let dvar_b = forest_b
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    let num_ops_b = forest_b[block_b].get_basic_block().unwrap().num_operations() as usize;
    forest_b
        .debug_info_mut()
        .register_asm_ops(block_b, num_ops_b, vec![(0, asm_id_b)])
        .unwrap();
    forest_b
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_b, vec![(0, dvar_b)])
        .unwrap();
    forest_b.make_root(block_b);

    let (merged, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(1, &block_b).unwrap();

    assert_eq!(new_a, new_b, "AssemblyOp metadata must not affect MAST shape");
    assert_eq!(
        merged.debug_info().first_asm_op_for_node(new_a).unwrap().context_name(),
        "ctx_b"
    );
}

/// Debug vars are only representable on basic block nodes. The builder API
/// (`ensure_block`) is the sole entry point for attaching debug vars, and
/// control-flow nodes (Join, Split, Loop, Call, Dyn) have no `debug_vars`
/// parameter. This test verifies that after assembly, non-block nodes carry
/// no debug vars.
#[test]
fn non_basic_block_nodes_have_no_debug_vars() {
    use crate::mast::{JoinNodeBuilder, SplitNodeBuilder};

    let mut forest = MastForest::new();

    // Two leaf blocks (no debug vars).
    let block_a = block_foo().add_to_forest(&mut forest).unwrap();
    let block_b = block_bar().add_to_forest(&mut forest).unwrap();

    // Join node wrapping the two.
    let join = JoinNodeBuilder::new([block_a, block_b]);
    let join_id = join.add_to_forest(&mut forest).unwrap();

    // Split node wrapping the two.
    let split = SplitNodeBuilder::new([block_a, block_b]);
    let split_id = split.add_to_forest(&mut forest).unwrap();

    // Loop node.
    let loop_node = LoopNodeBuilder::new(block_a);
    let loop_id = loop_node.add_to_forest(&mut forest).unwrap();

    forest.make_root(join_id);
    forest.make_root(split_id);
    forest.make_root(loop_id);

    // None of these control-flow nodes should have debug vars.
    assert!(
        forest.debug_info().debug_vars_for_node(join_id).is_empty(),
        "join node must not carry debug vars"
    );
    assert!(
        forest.debug_info().debug_vars_for_node(split_id).is_empty(),
        "split node must not carry debug vars"
    );
    assert!(
        forest.debug_info().debug_vars_for_node(loop_id).is_empty(),
        "loop node must not carry debug vars"
    );
}

/// Identical debug var content from two forests collapses to one node.
#[test]
fn merge_deduplicates_blocks_with_same_debug_vars() {
    let mut forest_a = MastForest::new();
    let dvar_a = forest_a
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    forest_a
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_a, vec![(0, dvar_a)])
        .unwrap();
    forest_a.make_root(block_a);

    let mut forest_b = MastForest::new();
    let dvar_b = forest_b
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    forest_b
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_b, vec![(0, dvar_b)])
        .unwrap();
    forest_b.make_root(block_b);

    let (merged, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();
    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(1, &block_b).unwrap();

    assert_eq!(new_a, new_b, "identical content must dedup to one node");
    assert_eq!(merged.debug_info().debug_vars_for_node(new_a).len(), 1);
}

/// Different debug vars do not prevent compact from collapsing same-ops blocks.
#[test]
fn compact_deduplicates_blocks_with_different_debug_vars() {
    let mut forest = MastForest::new();
    let var_x = forest
        .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
        .unwrap();
    let var_y = forest
        .add_debug_var(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
        .unwrap();

    let block_a = block_foo().add_to_forest(&mut forest).unwrap();
    forest
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_a, vec![(0, var_x)])
        .unwrap();
    forest.make_root(block_a);

    let block_b = block_foo().add_to_forest(&mut forest).unwrap();
    forest
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_b, vec![(0, var_y)])
        .unwrap();
    forest.make_root(block_b);

    let (compacted, root_map) = forest.compact();
    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(0, &block_b).unwrap();

    assert_eq!(new_a, new_b, "different debug vars must not affect compacted MAST shape");

    let info_a = compacted
        .debug_info()
        .debug_var(compacted.debug_info().debug_vars_for_node(new_a)[0].1)
        .unwrap();
    assert_eq!(info_a.name(), "x");
}

/// Procedure names survive compact.
#[test]
fn compact_preserves_procedure_names() {
    let mut forest = MastForest::new();
    let block_id = block_foo().add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);
    let digest = forest[block_id].digest();
    forest.insert_procedure_name(digest, Arc::from("my_fn"));

    let (compacted, _) = forest.compact();

    assert_eq!(compacted.procedure_name(&digest), Some("my_fn"));
}

/// Three-way merge keeps debug vars and asm ops on every root.
#[test]
fn merge_three_forests_preserves_all_metadata() {
    let blocks = [block_foo, block_bar, block_qux];
    let var_names = ["a", "b", "c"];
    let ctx_names = ["ctx_1", "ctx_2", "ctx_3"];
    let mut forests = Vec::new();

    for i in 0..3 {
        let mut f = MastForest::new();
        let dvar = f
            .add_debug_var(DebugVarInfo::new(var_names[i], DebugVarLocation::Stack(i as u8)))
            .unwrap();
        let asm = AssemblyOp::new(None, ctx_names[i].into(), 1, "op".into());
        let asm_id = f.debug_info_mut().add_asm_op(asm).unwrap();

        let block = blocks[i]().add_to_forest(&mut f).unwrap();
        let num_ops = f[block].get_basic_block().unwrap().num_operations() as usize;
        f.debug_info_mut().register_asm_ops(block, num_ops, vec![(0, asm_id)]).unwrap();
        f.debug_info_mut()
            .register_op_indexed_debug_vars(block, vec![(0, dvar)])
            .unwrap();
        f.make_root(block);
        forests.push(f);
    }

    let refs: Vec<&MastForest> = forests.iter().collect();
    let (merged, _) = MastForest::merge(refs).unwrap();

    assert_eq!(merged.procedure_roots().len(), 3);
    for root_id in merged.procedure_roots() {
        assert_eq!(merged.debug_info().debug_vars_for_node(*root_id).len(), 1);
        assert!(merged.debug_info().first_asm_op_for_node(*root_id).is_some());
    }
}

/// External placeholder doesn't clobber the concrete node's asm ops / debug vars.
#[test]
fn merge_concrete_metadata_survives_external_placeholder() {
    let mut forest_concrete = MastForest::new();
    let asm = AssemblyOp::new(None, "real_ctx".into(), 1, "mul".into());
    let asm_id = forest_concrete.debug_info_mut().add_asm_op(asm).unwrap();
    let dvar = forest_concrete
        .add_debug_var(DebugVarInfo::new("v", DebugVarLocation::Stack(0)))
        .unwrap();
    let block_id = block_foo().add_to_forest(&mut forest_concrete).unwrap();
    let num_ops = forest_concrete[block_id].get_basic_block().unwrap().num_operations() as usize;
    forest_concrete
        .debug_info_mut()
        .register_asm_ops(block_id, num_ops, vec![(0, asm_id)])
        .unwrap();
    forest_concrete
        .debug_info_mut()
        .register_op_indexed_debug_vars(block_id, vec![(0, dvar)])
        .unwrap();
    forest_concrete.make_root(block_id);
    let digest = forest_concrete[block_id].digest();

    let mut forest_external = MastForest::new();
    let ext_id = ExternalNodeBuilder::new(digest).add_to_forest(&mut forest_external).unwrap();
    forest_external.make_root(ext_id);

    // external first, concrete second
    let (merged, root_map) = MastForest::merge([&forest_external, &forest_concrete]).unwrap();
    let merged_id = root_map.map_root(1, &block_id).unwrap();

    assert!(
        merged.debug_info().first_asm_op_for_node(merged_id).is_some(),
        "concrete asm-op must survive merge with external placeholder"
    );
    assert_eq!(
        merged.debug_info().debug_vars_for_node(merged_id).len(),
        1,
        "concrete debug var must survive merge with external placeholder"
    );
}

/// First name wins when two forests name the same digest.
#[test]
fn merge_procedure_names_first_name_wins() {
    let mut forest_a = MastForest::new();
    let block_a = block_foo().add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(block_a);
    let digest = forest_a[block_a].digest();
    forest_a.insert_procedure_name(digest, Arc::from("alias_a"));

    let mut forest_b = MastForest::new();
    let block_b = block_foo().add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(block_b);
    assert_eq!(forest_b[block_b].digest(), digest);
    forest_b.insert_procedure_name(digest, Arc::from("alias_b"));

    let (merged, root_map) = MastForest::merge([&forest_a, &forest_b]).unwrap();
    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(1, &block_b).unwrap();

    assert_eq!(new_a, new_b);
    assert_eq!(
        merged.procedure_name(&digest),
        Some("alias_a"),
        "first forest's name must stick"
    );
}
