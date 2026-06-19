use super::*;
use crate::{
    Felt, ONE, Word,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder,
        ExternalNodeBuilder, LoopNodeBuilder, OpBatch,
        node::{MastForestContributor, MastNodeExt},
    },
    operations::Operation,
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

fn first_error_code(block: &BasicBlockNode) -> Felt {
    let op = block
        .op_batches()
        .iter()
        .flat_map(OpBatch::raw_ops)
        .next()
        .expect("expected a basic block operation");

    match op {
        Operation::Assert(code) | Operation::U32assert2(code) | Operation::MpVerify(code) => *code,
        other => panic!("expected error-code-bearing operation, got {other:?}"),
    }
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
    forest_a.advice_map_mut().insert(key_a, value_a.clone());

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
    forest_b.advice_map_mut().insert(key_b, value_b.clone());

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
    forest_a.advice_map_mut().insert(key_a, value_a);

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    // The key collides with key_a in the forest_a.
    let key_b = key_a;
    let value_b = vec![Felt::new_unchecked(2), Felt::new_unchecked(2)];
    forest_b.advice_map_mut().insert(key_b, value_b);

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::AdviceMapKeyCollisionOnMerge(_));
}

#[test]
fn compact_keeps_error_code_bearing_basic_blocks_distinct() {
    let mut forest = MastForest::new();
    let block_a = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(1))])
        .add_to_forest(&mut forest)
        .unwrap();
    let block_b = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(2))])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_a);
    forest.make_root(block_b);

    assert_eq!(forest[block_a].digest(), forest[block_b].digest());

    let (compacted, root_map) = forest.compact();
    let new_a = root_map.map_root(0, &block_a).unwrap();
    let new_b = root_map.map_root(0, &block_b).unwrap();

    assert_ne!(
        new_a, new_b,
        "same-digest blocks with different runtime error codes must not compact together",
    );
    assert_eq!(first_error_code(compacted[new_a].unwrap_basic_block()), Felt::from_u32(1),);
    assert_eq!(first_error_code(compacted[new_b].unwrap_basic_block()), Felt::from_u32(2),);
}

#[test]
fn compact_propagates_error_code_fingerprints_through_control_nodes() {
    let mut forest = MastForest::new();
    let block_a = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(1))])
        .add_to_forest(&mut forest)
        .unwrap();
    let call_a = CallNodeBuilder::new(block_a).add_to_forest(&mut forest).unwrap();

    let block_b = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(2))])
        .add_to_forest(&mut forest)
        .unwrap();
    let call_b = CallNodeBuilder::new(block_b).add_to_forest(&mut forest).unwrap();

    forest.make_root(call_a);
    forest.make_root(call_b);

    assert_eq!(forest[call_a].digest(), forest[call_b].digest());

    let (compacted, root_map) = forest.compact();
    let new_call_a = root_map.map_root(0, &call_a).unwrap();
    let new_call_b = root_map.map_root(0, &call_b).unwrap();

    assert_ne!(
        new_call_a, new_call_b,
        "same-digest control nodes must stay distinct when their children differ by runtime error code",
    );

    let new_block_a = compacted[new_call_a].unwrap_call().callee();
    let new_block_b = compacted[new_call_b].unwrap_call().callee();
    assert_eq!(first_error_code(compacted[new_block_a].unwrap_basic_block()), Felt::from_u32(1),);
    assert_eq!(first_error_code(compacted[new_block_b].unwrap_basic_block()), Felt::from_u32(2),);
}
