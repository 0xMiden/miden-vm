use miden_crypto::{Felt, ONE, Word};
use miden_utils_indexing::Idx;

use super::*;
use crate::{
    Decorator, Operation,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DecoratorId, ExternalNodeBuilder, LoopNodeBuilder,
        node::MastForestContributor,
    },
};

fn block_foo() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::Mul, Operation::Add], Vec::new())
}

fn block_foo_with_decorators(
    before_enter: &[DecoratorId],
    after_exit: &[DecoratorId],
) -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::Mul, Operation::Add], Vec::new())
        .with_before_enter(before_enter.to_vec())
        .with_after_exit(after_exit.to_vec())
}

fn block_bar() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(vec![Operation::And, Operation::Eq], Vec::new())
}

fn block_qux() -> BasicBlockNodeBuilder {
    BasicBlockNodeBuilder::new(
        vec![Operation::Swap, Operation::Push(ONE), Operation::Eq],
        Vec::new(),
    )
}

fn loop_with_decorators(
    body_id: MastNodeId,
    before_enter: &[DecoratorId],
    after_exit: &[DecoratorId],
) -> LoopNodeBuilder {
    LoopNodeBuilder::new(body_id)
        .with_before_enter(before_enter.to_vec())
        .with_after_exit(after_exit.to_vec())
}

fn external_with_decorators(
    procedure_hash: Word,
    before_enter: &[DecoratorId],
    after_exit: &[DecoratorId],
) -> ExternalNodeBuilder {
    ExternalNodeBuilder::new(procedure_hash)
        .with_before_enter(before_enter.to_vec())
        .with_after_exit(after_exit.to_vec())
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
///
/// Returns a Result which can be unwrapped in the calling test function to assert. This way, if
/// this assertion fails it'll be clear which exact call failed.
fn assert_child_id_lt_parent_id(forest: &MastForest) -> Result<(), &str> {
    for (mast_node_id, node) in forest.nodes().iter().enumerate() {
        node.for_each_child(|child_id| {
            if child_id.to_usize() >= mast_node_id {
                panic!("child id {} is not < parent id {}", child_id.to_usize(), mast_node_id);
            }
        });
    }

    Ok(())
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
        if merged_block.semantic_eq(expected_foo_block, &merged));

    assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if 0u32 == u32::from(call_node.callee()));

    // Check that the third node is semantically equal to the expected bar block
    let expected_bar_id = block_bar().add_to_forest(&mut merged).unwrap();
    let expected_bar_block = merged.get_node_by_id(expected_bar_id).unwrap().unwrap_basic_block();
    assert_matches!(&merged.nodes()[2], MastNode::Block(merged_block)
        if merged_block.semantic_eq(expected_bar_block, &merged));
    assert_matches!(&merged.nodes()[3], MastNode::Call(call_node) if 2u32 == u32::from(call_node.callee()));

    assert_eq!(u32::from(root_maps.map_root(0, &id_call_a).unwrap()), 1u32);
    assert_eq!(u32::from(root_maps.map_root(1, &id_call_b).unwrap()), 3u32);

    assert_child_id_lt_parent_id(&merged).unwrap();
}

/// Tests that Forest_A + Forest_A = Forest_A (i.e. duplicates are removed).
#[test]
fn mast_forest_merge_duplicate() {
    let mut forest_a = MastForest::new();
    forest_a.add_decorator(Decorator::Debug(crate::DebugOptions::MemAll)).unwrap();
    forest_a.add_decorator(Decorator::Trace(25)).unwrap();

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

    for merged_decorator in merged.decorators().iter() {
        assert!(forest_a.decorators().contains(merged_decorator));
    }

    assert_child_id_lt_parent_id(&merged).unwrap();
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
            if merged_block.semantic_eq(expected_foo_block, &merged));

        assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if 0u32 == u32::from(call_node.callee()));
        // The only root node should be the call node.
        assert_eq!(merged.roots.len(), 1);
        assert_eq!(root_map.map_root(0, &id_call_a).unwrap().to_usize(), 1);
        assert_eq!(root_map.map_root(1, &id_call_b).unwrap().to_usize(), 1);
        assert_child_id_lt_parent_id(&merged).unwrap();
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

    assert_child_id_lt_parent_id(&merged).unwrap();
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

    assert_child_id_lt_parent_id(&merged).unwrap();
}

/// Tests that decorators are merged and that nodes who are identical except for their
/// decorators are not deduplicated.
///
/// Note in particular that the `Loop` nodes only differ in their decorator which ensures that
/// the merging takes decorators into account.
///
/// Nodes: [Block(foo, [Trace(1), Trace(2)]), Loop(foo, [Trace(0), Trace(2)])]
/// Decorators: [Trace(0), Trace(1), Trace(2)]
/// +
/// Nodes: [Block(foo, [Trace(1), Trace(2)]), Loop(foo, [Trace(1), Trace(3)])]
/// Decorators: [Trace(1), Trace(2), Trace(3)]
/// =
/// Nodes: [
///   Block(foo, [Trace(1), Trace(2)]),
///   Loop(foo, [Trace(0), Trace(2)]),
///   Loop(foo, [Trace(1), Trace(3)]),
/// ]
/// Decorators: [Trace(0), Trace(1), Trace(2), Trace(3)]
#[test]
fn mast_forest_merge_decorators() {
    let mut forest_a = MastForest::new();
    let trace0 = Decorator::Trace(0);
    let trace1 = Decorator::Trace(1);
    let trace2 = Decorator::Trace(2);
    let trace3 = Decorator::Trace(3);

    // Build Forest A
    let deco0_a = forest_a.add_decorator(trace0.clone()).unwrap();
    let deco1_a = forest_a.add_decorator(trace1.clone()).unwrap();
    let deco2_a = forest_a.add_decorator(trace2.clone()).unwrap();

    let foo_node_a = block_foo_with_decorators(&[deco1_a, deco2_a], &[]);
    let id_foo_a = foo_node_a.add_to_forest(&mut forest_a).unwrap();

    let loop_node_a = loop_with_decorators(id_foo_a, &[], &[deco0_a, deco2_a]);
    let id_loop_a = loop_node_a.add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_loop_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco1_b = forest_b.add_decorator(trace1.clone()).unwrap();
    let deco2_b = forest_b.add_decorator(trace2.clone()).unwrap();
    let deco3_b = forest_b.add_decorator(trace3.clone()).unwrap();

    // This foo node is identical to the one in A, including its decorators.
    let foo_node_b = block_foo_with_decorators(&[deco1_b, deco2_b], &[]);
    let id_foo_b = foo_node_b.add_to_forest(&mut forest_b).unwrap();

    // This loop node's decorators are different from the loop node in a.
    let loop_node_b = loop_with_decorators(id_foo_b, &[], &[deco1_b, deco3_b]);
    let id_loop_b = loop_node_b.add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_loop_b);

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    // There are 4 unique decorators across both forests.
    assert_eq!(merged.decorators().len(), 4);
    assert!(merged.decorators().contains(&trace0));
    assert!(merged.decorators().contains(&trace1));
    assert!(merged.decorators().contains(&trace2));
    assert!(merged.decorators().contains(&trace3));

    let find_decorator_id = |deco: &Decorator| {
        let idx = merged
            .decorators()
            .iter()
            .enumerate()
            .find_map(
                |(deco_id, forest_deco)| if forest_deco == deco { Some(deco_id) } else { None },
            )
            .unwrap();
        DecoratorId::from_u32_safe(idx as u32, &merged).unwrap()
    };

    let merged_deco0 = find_decorator_id(&trace0);
    let merged_deco1 = find_decorator_id(&trace1);
    let merged_deco2 = find_decorator_id(&trace2);
    let merged_deco3 = find_decorator_id(&trace3);

    assert_eq!(merged.nodes.len(), 3);

    let merged_foo_block = merged.nodes.iter().find(|node| node.is_basic_block()).unwrap();
    let MastNode::Block(merged_foo_block) = merged_foo_block else {
        panic!("expected basic block node");
    };

    // Test basic block decorators using new MastForest API
    // The basic block should have Trace(1) and Trace(2) as before-enter decorators at index 0
    let merged_foo_block_id = merged_foo_block.linked_id().unwrap();

    // For basic blocks, we need to combine before_enter, operation-indexed, and after_exit
    // decorators using the helper method
    let all_decorators = merged.all_decorators(merged_foo_block_id);
    assert_eq!(all_decorators, vec![(0, merged_deco1), (0, merged_deco2)]);

    // Asserts that there exists exactly one Loop Node with the given decorators.
    assert_eq!(
        merged
            .nodes
            .iter()
            .filter(|node| {
                if let MastNode::Loop(loop_node) = node {
                    loop_node.after_exit(&merged) == [merged_deco0, merged_deco2]
                } else {
                    false
                }
            })
            .count(),
        1
    );

    // Asserts that there exists exactly one Loop Node with the given decorators.
    assert_eq!(
        merged
            .nodes
            .iter()
            .filter(|node| {
                if let MastNode::Loop(loop_node) = node {
                    loop_node.after_exit(&merged) == [merged_deco1, merged_deco3]
                } else {
                    false
                }
            })
            .count(),
        1
    );

    assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots).unwrap();

    assert_child_id_lt_parent_id(&merged).unwrap();
}

/// Tests that an external node without decorators is replaced by its referenced node which has
/// decorators.
///
/// [External(foo)]
/// +
/// [Block(foo, Trace(1))]
/// =
/// [Block(foo, Trace(1))]
/// +
/// [External(foo)]
/// =
/// [Block(foo, Trace(1))]
#[test]
fn mast_forest_merge_external_node_reference_with_decorator() {
    let mut forest_a = MastForest::new();
    let trace = Decorator::Trace(1);

    // Build Forest A
    let deco = forest_a.add_decorator(trace.clone()).unwrap();

    let foo_node_a = block_foo_with_decorators(&[deco], &[]);
    let foo_node_digest = block_foo_with_decorators(&[deco], &[]).build().unwrap().digest();
    let id_foo_a = foo_node_a.add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_foo_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let id_external_b =
        ExternalNodeBuilder::new(foo_node_digest).add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_external_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let id_foo_a_digest = forest_a[id_foo_a].digest();
        let digests: Vec<_> = merged.nodes().iter().map(|node| node.digest()).collect();

        assert_eq!(merged.nodes.len(), 1);
        assert!(digests.contains(&id_foo_a_digest));

        if idx == 0 {
            assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots)
                .unwrap();
        } else {
            assert_root_mapping(&root_maps, vec![&forest_b.roots, &forest_a.roots], &merged.roots)
                .unwrap();
        }

        assert_child_id_lt_parent_id(&merged).unwrap();
    }
}

/// Tests that an external node with decorators is replaced by its referenced node which does not
/// have decorators.
///
/// [External(foo, Trace(1), Trace(2))]
/// +
/// [Block(foo)]
/// =
/// [Block(foo)]
/// +
/// [External(foo, Trace(1), Trace(2))]
/// =
/// [Block(foo)]
#[test]
fn mast_forest_merge_external_node_with_decorator() {
    let mut forest_a = MastForest::new();
    let trace1 = Decorator::Trace(1);
    let trace2 = Decorator::Trace(2);

    // Build Forest A
    let deco1 = forest_a.add_decorator(trace1.clone()).unwrap();
    let deco2 = forest_a.add_decorator(trace2.clone()).unwrap();

    let external_node_a =
        external_with_decorators(block_foo().build().unwrap().digest(), &[deco1], &[deco2]);
    let id_external_a = external_node_a.add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_external_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let id_foo_b = block_foo().add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_digest = forest_b[id_foo_b].digest();
        let digests: Vec<_> = merged.nodes().iter().map(|node| node.digest()).collect();

        // Block foo should be unmodified.
        assert!(digests.contains(&id_foo_b_digest));

        if idx == 0 {
            assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots)
                .unwrap();
        } else {
            assert_root_mapping(&root_maps, vec![&forest_b.roots, &forest_a.roots], &merged.roots)
                .unwrap();
        }

        assert_child_id_lt_parent_id(&merged).unwrap();
    }
}

/// Tests that an external node with decorators is replaced by its referenced node which also has
/// decorators.
///
/// [External(foo, Trace(1))]
/// +
/// [Block(foo, Trace(2))]
/// =
/// [Block(foo, Trace(2))]
/// +
/// [External(foo, Trace(1))]
/// =
/// [Block(foo, Trace(2))]
#[test]
fn mast_forest_merge_external_node_and_referenced_node_have_decorators() {
    let mut forest_a = MastForest::new();
    let trace1 = Decorator::Trace(1);
    let trace2 = Decorator::Trace(2);

    // Build Forest A
    let deco1_a = forest_a.add_decorator(trace1.clone()).unwrap();

    let external_node_a =
        external_with_decorators(block_foo().build().unwrap().digest(), &[deco1_a], &[]);
    let id_external_a = external_node_a.add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_external_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco2_b = forest_b.add_decorator(trace2.clone()).unwrap();

    let foo_node_b = block_foo_with_decorators(&[deco2_b], &[]);
    let id_foo_b = foo_node_b.add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_digest = forest_b[id_foo_b].digest();
        let digests: Vec<_> = merged.nodes().iter().map(|node| node.digest()).collect();

        // Block foo should be unmodified.
        assert!(digests.contains(&id_foo_b_digest));

        if idx == 0 {
            assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots)
                .unwrap();
        } else {
            assert_root_mapping(&root_maps, vec![&forest_b.roots, &forest_a.roots], &merged.roots)
                .unwrap();
        }

        assert_child_id_lt_parent_id(&merged).unwrap();
    }
}

/// Tests that two external nodes with the same MAST root are deduplicated during merging and then
/// replaced by a block with the matching digest.
///
/// [External(foo, Trace(1), Trace(2)),
///  External(foo, Trace(1))]
/// +
/// [Block(foo, Trace(1))]
/// =
/// [Block(foo, Trace(1))]
/// +
/// [External(foo, Trace(1), Trace(2)),
///  External(foo, Trace(1))]
/// =
/// [Block(foo, Trace(1))]
#[test]
fn mast_forest_merge_multiple_external_nodes_with_decorator() {
    let mut forest_a = MastForest::new();
    let trace1 = Decorator::Trace(1);
    let trace2 = Decorator::Trace(2);

    // Build Forest A
    let deco1_a = forest_a.add_decorator(trace1.clone()).unwrap();
    let deco2_a = forest_a.add_decorator(trace2.clone()).unwrap();

    let external_node_a =
        external_with_decorators(block_foo().build().unwrap().digest(), &[deco1_a], &[deco2_a]);
    let id_external_a = external_node_a.add_to_forest(&mut forest_a).unwrap();

    let external_node_b =
        external_with_decorators(block_foo().build().unwrap().digest(), &[deco1_a], &[]);
    let id_external_b = external_node_b.add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_external_a);
    forest_a.make_root(id_external_b);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco1_b = forest_b.add_decorator(trace1).unwrap();
    let block_foo_b = block_foo_with_decorators(&[deco1_b], &[]);
    let id_foo_b = block_foo_b.add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_digest = forest_b[id_foo_b].digest();
        let digests: Vec<_> = merged.nodes().iter().map(|node| node.digest()).collect();

        // Block foo should be unmodified.
        assert!(digests.contains(&id_foo_b_digest));

        if idx == 0 {
            assert_root_mapping(&root_maps, vec![&forest_a.roots, &forest_b.roots], &merged.roots)
                .unwrap();
        } else {
            assert_root_mapping(&root_maps, vec![&forest_b.roots, &forest_a.roots], &merged.roots)
                .unwrap();
        }

        assert_child_id_lt_parent_id(&merged).unwrap();
    }
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
        let digests = merged.nodes().iter().map(|node| node.digest()).collect::<Vec<_>>();
        assert_eq!(merged.nodes().len(), 3);
        assert!(digests.contains(&forest_b[id_ext_b].digest()));
        assert!(digests.contains(&forest_b[id_call_b].digest()));
        assert!(digests.contains(&forest_a[id_foo_a].digest()));
        assert!(digests.contains(&forest_a[id_call_a].digest()));
        assert!(digests.contains(&forest_b[id_qux_b].digest()));
        assert_eq!(merged.nodes().iter().filter(|node| node.is_external()).count(), 0);

        assert_child_id_lt_parent_id(&merged).unwrap();
    }
}

/// Tests that a forest with nodes who reference non-existent decorators return an error during
/// merging and does not panic.
#[test]
fn mast_forest_merge_invalid_decorator_index() {
    let trace1 = Decorator::Trace(1);
    let trace2 = Decorator::Trace(2);

    // Build Forest A
    let mut forest_a = MastForest::new();
    let deco1_a = forest_a.add_decorator(trace1.clone()).unwrap();
    let deco2_a = forest_a.add_decorator(trace2.clone()).unwrap();
    let id_bar_a = block_bar().add_to_forest(&mut forest_a).unwrap();

    forest_a.make_root(id_bar_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let block_b = block_foo_with_decorators(&[deco1_a, deco2_a], &[]);
    // We're using a DecoratorId from forest A which is invalid.
    let id_foo_b = block_b.add_to_forest(&mut forest_b).unwrap();

    forest_b.make_root(id_foo_b);

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::DecoratorIdOverflow(_, _));
}

/// Tests that forest's advice maps are merged correctly.
#[test]
fn mast_forest_merge_advice_maps_merged() {
    let mut forest_a = MastForest::new();
    let id_foo = block_foo().add_to_forest(&mut forest_a).unwrap();
    let id_call_a = CallNodeBuilder::new(id_foo).add_to_forest(&mut forest_a).unwrap();
    forest_a.make_root(id_call_a);
    let key_a = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let value_a = vec![ONE, ONE];
    forest_a.advice_map_mut().insert(key_a, value_a.clone());

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    let key_b = Word::new([Felt::new(1), Felt::new(3), Felt::new(2), Felt::new(1)]);
    let value_b = vec![Felt::new(2), Felt::new(2)];
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
    let key_a = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let value_a = vec![ONE, ONE];
    forest_a.advice_map_mut().insert(key_a, value_a.clone());

    let mut forest_b = MastForest::new();
    let id_bar = block_bar().add_to_forest(&mut forest_b).unwrap();
    let id_call_b = CallNodeBuilder::new(id_bar).add_to_forest(&mut forest_b).unwrap();
    forest_b.make_root(id_call_b);
    // The key collides with key_a in the forest_a.
    let key_b = key_a;
    let value_b = vec![Felt::new(2), Felt::new(2)];
    forest_b.advice_map_mut().insert(key_b, value_b.clone());

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::AdviceMapKeyCollisionOnMerge(_));
}

// Forest A:
//   - Block with op-indexed decorators at operations [0, 1]
//   - Before-enter and after-exit decorators
// Forest B:
//   - Block with op-indexed decorators at operations [0, 2]
//   - Before-enter and after-exit decorators
//   - One decorator duplicated from Forest A
//   - Some decorators unique to B
#[test]
fn mast_forest_merge_op_indexed_decorators_preservation() {
    // Build Forest A with diverse decorators
    let mut forest_a = MastForest::new();

    // Create decorators for Forest A
    let before_enter_a = forest_a.add_decorator(Decorator::Trace(0)).unwrap();
    let op0_a = forest_a.add_decorator(Decorator::Trace(1)).unwrap();
    let op1_a = forest_a.add_decorator(Decorator::Trace(2)).unwrap();
    let after_exit_a = forest_a.add_decorator(Decorator::Trace(3)).unwrap();
    let shared_deco_a = forest_a.add_decorator(Decorator::Trace(99)).unwrap(); // Will be deduped

    // Create a block with multiple operations and op-indexed decorators
    let ops_a = vec![Operation::Add, Operation::Mul, Operation::Or];
    let block_id_a = BasicBlockNodeBuilder::new(
        ops_a.clone(),
        vec![(0, op0_a), (1, op1_a)], // Op-indexed decorators
    )
    .with_before_enter(vec![before_enter_a, shared_deco_a]) // Use shared decorator
    .with_after_exit(vec![after_exit_a])
    .add_to_forest(&mut forest_a)
    .unwrap();

    forest_a.make_root(block_id_a);

    // Build Forest B with some overlapping and some new decorators
    let mut forest_b = MastForest::new();

    // Create decorators for Forest B (note: Trace(99) matches shared_deco from A)
    let before_enter_b = forest_b.add_decorator(Decorator::Trace(10)).unwrap();
    let op0_b = forest_b.add_decorator(Decorator::Trace(11)).unwrap();
    let op2_b = forest_b.add_decorator(Decorator::Trace(12)).unwrap();
    let after_exit_b = forest_b.add_decorator(Decorator::Trace(13)).unwrap();
    let shared_deco_b = forest_b.add_decorator(Decorator::Trace(99)).unwrap(); // Same value as Forest A
    let unique_b = forest_b.add_decorator(Decorator::Trace(20)).unwrap();

    let ops_b = vec![Operation::Add, Operation::Mul, Operation::Or];
    let block_id_b = BasicBlockNodeBuilder::new(
        ops_b.clone(),
        vec![(0, op0_b), (2, op2_b)], // Op-indexed decorators at different positions
    )
    .with_before_enter(vec![before_enter_b, shared_deco_b]) // Use shared decorator
    .with_after_exit(vec![after_exit_b, unique_b]) // Use unique decorator
    .add_to_forest(&mut forest_b)
    .unwrap();

    forest_b.make_root(block_id_b);

    // Perform the merge
    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    // Helper to find a decorator's ID in the merged forest
    let find_decorator = |trace_value: u32| {
        let idx = merged
            .decorators()
            .iter()
            .enumerate()
            .find_map(|(id, deco)| {
                if let Decorator::Trace(v) = deco {
                    if *v == trace_value { Some(id) } else { None }
                } else {
                    None
                }
            })
            .expect("decorator not found");
        DecoratorId::from_u32_safe(idx as u32, &merged).unwrap()
    };

    // Find all decorator IDs in merged forest
    let merged_before_enter_a = find_decorator(0);
    let merged_op0_a = find_decorator(1);
    let merged_op1_a = find_decorator(2);
    let merged_after_exit_a = find_decorator(3);
    let merged_shared = find_decorator(99);
    let merged_before_enter_b = find_decorator(10);
    let merged_op0_b = find_decorator(11);
    let merged_op2_b = find_decorator(12);
    let merged_after_exit_b = find_decorator(13);
    let merged_unique_b = find_decorator(20);

    // Verify that shared decorator appears only once in merged forest
    assert!(
        merged
            .decorators()
            .iter()
            .enumerate()
            .find_map(|(i, deco)| {
                if let Decorator::Trace(v) = deco
                    && i > merged_shared.0 as usize
                {
                    if *v == 99 { Some(i) } else { None }
                } else {
                    None
                }
            })
            .is_none(),
        "Shared decorator should map to single ID"
    );

    // Count how many times each decorator appears in the merged forest
    let mut decorator_ref_counts = alloc::collections::BTreeMap::new();

    // Check all nodes for decorator references
    for node in &merged.nodes {
        // Count before_enter decorators
        for &deco_id in node.before_enter(&merged) {
            *decorator_ref_counts.entry(deco_id).or_insert(0) += 1;
        }
        // Count after_exit decorators
        for &deco_id in node.after_exit(&merged) {
            *decorator_ref_counts.entry(deco_id).or_insert(0) += 1;
        }
        // Count op-indexed decorators if it's a basic block
        if let MastNode::Block(block) = node {
            for (_, deco_id) in block.indexed_decorator_iter(&merged) {
                *decorator_ref_counts.entry(deco_id).or_insert(0) += 1;
            }
        }
    }

    // Verify all decorators are referenced at least once (no orphans)
    for (i, decorator) in merged.decorators().iter().enumerate() {
        let deco_id = DecoratorId::from_u32_safe(i as u32, &merged).unwrap();
        let ref_count = decorator_ref_counts.get(&deco_id).unwrap_or(&0);
        if ref_count == &0 {
            panic!(
                "Decorator at index {} (value: {:?}) is not referenced anywhere in the merged forest (orphan)",
                i, decorator
            );
        }
    }

    // Verify op-indexed decorators are correctly preserved for Forest A's block
    let mapped_root_a = root_maps.map_root(0, &block_id_a).unwrap();
    if let MastNode::Block(block_a) = &merged[mapped_root_a] {
        // Check before_enter decorators (note: includes both before_enter_a and shared_deco_a)
        assert_eq!(
            block_a.before_enter(&merged),
            &[merged_before_enter_a, merged_shared],
            "Forest A's before_enter decorators should be preserved (including shared decorator)"
        );

        // Check op-indexed decorators at correct positions
        let indexed_decs: alloc::collections::BTreeMap<usize, DecoratorId> =
            block_a.indexed_decorator_iter(&merged).collect();

        assert_eq!(
            indexed_decs.get(&0),
            Some(&merged_op0_a),
            "Forest A's op[0] decorator should be preserved at position 0"
        );
        assert_eq!(
            indexed_decs.get(&1),
            Some(&merged_op1_a),
            "Forest A's op[1] decorator should be preserved at position 1"
        );
        assert_eq!(indexed_decs.get(&2), None, "Forest A's block doesn't have op[2] decorator");

        // Check after_exit decorators
        assert_eq!(
            block_a.after_exit(&merged),
            &[merged_after_exit_a],
            "Forest A's after_exit decorator should be preserved"
        );
    } else {
        panic!("Expected a basic block node");
    }

    // Verify op-indexed decorators are correctly preserved for Forest B's block
    let mapped_root_b = root_maps.map_root(1, &block_id_b).unwrap();
    if let MastNode::Block(block_b) = &merged[mapped_root_b] {
        // Check before_enter decorators (note: includes both before_enter_b and shared_deco_b)
        assert_eq!(
            block_b.before_enter(&merged),
            &[merged_before_enter_b, merged_shared],
            "Forest B's before_enter decorators should be preserved (including shared decorator)"
        );

        // Check op-indexed decorators at correct positions
        let indexed_decs: alloc::collections::BTreeMap<usize, DecoratorId> =
            block_b.indexed_decorator_iter(&merged).collect();

        assert_eq!(
            indexed_decs.get(&0),
            Some(&merged_op0_b),
            "Forest B's op[0] decorator should be preserved at position 0"
        );
        assert_eq!(indexed_decs.get(&1), None, "Forest B's block doesn't have op[1] decorator");
        assert_eq!(
            indexed_decs.get(&2),
            Some(&merged_op2_b),
            "Forest B's op[2] decorator should be preserved at position 2"
        );

        // Check after_exit decorators (note: includes both after_exit_b and unique_b)
        assert_eq!(
            block_b.after_exit(&merged),
            &[merged_after_exit_b, merged_unique_b],
            "Forest B's after_exit decorators should be preserved (including unique decorator)"
        );
    } else {
        panic!("Expected a basic block node");
    }

    // Verify the shared decorator (Trace(99)) is deduped and referenced correctly
    let shared_ref_count = decorator_ref_counts.get(&merged_shared).unwrap_or(&0);
    assert!(shared_ref_count > &0, "Shared decorator should be referenced at least once");

    // Verify no decorator was lost or orphaned
    assert_eq!(
        decorator_ref_counts.len(),
        merged.decorators().len(),
        "Every decorator in merged forest should be referenced at least once (no orphans)"
    );
}
