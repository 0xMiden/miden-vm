use miden_crypto::{Felt, ONE, Word};

use super::*;
use crate::{
    Decorator, Operation,
    mast::{BasicBlockNode, MastNode},
};

fn block_foo() -> MastNode {
    BasicBlockNode::new(vec![Operation::Mul, Operation::Add], None).unwrap().into()
}

fn block_bar() -> MastNode {
    BasicBlockNode::new(vec![Operation::And, Operation::Eq], None).unwrap().into()
}

fn block_qux() -> MastNode {
    BasicBlockNode::new(vec![Operation::Swap, Operation::Push(ONE), Operation::Eq], None)
        .unwrap()
        .into()
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
        match node {
            MastNode::Join(join_node) => {
                if join_node.first().as_usize() >= mast_node_id {
                    return Err("join node first child id is not < parent id");
                };
                if join_node.second().as_usize() >= mast_node_id {
                    return Err("join node second child id is not < parent id");
                }
            },
            MastNode::Split(split_node) => {
                if split_node.on_true().as_usize() >= mast_node_id {
                    return Err("split node on true id is not < parent id");
                }
                if split_node.on_false().as_usize() >= mast_node_id {
                    return Err("split node on false id is not < parent id");
                }
            },
            MastNode::Loop(loop_node) => {
                if loop_node.body().as_usize() >= mast_node_id {
                    return Err("loop node body id is not < parent id");
                }
            },
            MastNode::Call(call_node) => {
                if call_node.callee().as_usize() >= mast_node_id {
                    return Err("call node callee id is not < parent id");
                }
            },
            MastNode::Block(_) => (),
            MastNode::Dyn(_) => (),
            MastNode::External(_) => (),
        }
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
    let id_foo = forest_a.add_node(block_foo()).unwrap();
    let id_call_a = forest_a.add_call(id_foo).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_bar = forest_b.add_node(block_bar()).unwrap();
    let id_call_b = forest_b.add_call(id_bar).unwrap();
    forest_b.make_root(id_call_b);

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    assert_eq!(merged.nodes().len(), 4);
    assert_eq!(merged.nodes()[0], block_foo());
    assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if call_node.callee().as_u32() == 0);
    assert_eq!(merged.nodes()[2], block_bar());
    assert_matches!(&merged.nodes()[3], MastNode::Call(call_node) if call_node.callee().as_u32() == 2);

    assert_eq!(root_maps.map_root(0, &id_call_a).unwrap().as_u32(), 1);
    assert_eq!(root_maps.map_root(1, &id_call_b).unwrap().as_u32(), 3);

    assert_child_id_lt_parent_id(&merged).unwrap();
}

/// Tests that Forest_A + Forest_A = Forest_A (i.e. duplicates are removed).
#[test]
fn mast_forest_merge_duplicate() {
    let mut forest_a = MastForest::new();
    forest_a.add_decorator(Decorator::Debug(crate::DebugOptions::MemAll)).unwrap();
    forest_a.add_decorator(Decorator::Trace(25)).unwrap();

    let id_external = forest_a.add_external(block_bar().digest()).unwrap();
    let id_foo = forest_a.add_node(block_foo()).unwrap();
    let id_call = forest_a.add_call(id_foo).unwrap();
    let id_loop = forest_a.add_loop(id_external).unwrap();
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

    for merged_decorator in merged.decorators.iter() {
        assert!(forest_a.decorators.contains(merged_decorator));
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
    let id_foo_a = forest_a.add_external(block_foo().digest()).unwrap();
    let id_call_a = forest_a.add_call(id_foo_a).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = forest_b.add_node(block_foo()).unwrap();
    let id_call_b = forest_b.add_call(id_foo_b).unwrap();
    forest_b.make_root(id_call_b);

    let (merged_ab, root_maps_ab) = MastForest::merge([&forest_a, &forest_b]).unwrap();
    let (merged_ba, root_maps_ba) = MastForest::merge([&forest_b, &forest_a]).unwrap();

    for (merged, root_map) in [(merged_ab, root_maps_ab), (merged_ba, root_maps_ba)] {
        assert_eq!(merged.nodes().len(), 2);
        assert_eq!(merged.nodes()[0], block_foo());
        assert_matches!(&merged.nodes()[1], MastNode::Call(call_node) if call_node.callee().as_u32() == 0);
        // The only root node should be the call node.
        assert_eq!(merged.roots.len(), 1);
        assert_eq!(root_map.map_root(0, &id_call_a).unwrap().as_usize(), 1);
        assert_eq!(root_map.map_root(1, &id_call_b).unwrap().as_usize(), 1);
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
    let id_foo_a = forest_a.add_node(block_foo()).unwrap();
    let call_a = forest_a.add_call(id_foo_a).unwrap();
    forest_a.make_root(call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = forest_b.add_node(block_foo()).unwrap();
    let id_bar_b = forest_b.add_node(block_bar()).unwrap();
    let call_b = forest_b.add_call(id_foo_b).unwrap();
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
    let id_foo_a = forest_a.add_node(block_foo()).unwrap();
    let call_a = forest_a.add_call(id_foo_a).unwrap();
    forest_a.make_root(call_a);

    let mut forest_b = MastForest::new();
    let id_foo_b = forest_b.add_node(block_foo()).unwrap();
    let id_bar_b = forest_b.add_node(block_bar()).unwrap();
    let call_b = forest_b.add_call(id_foo_b).unwrap();
    forest_b.make_root(id_bar_b);
    forest_b.make_root(call_b);

    let mut forest_c = MastForest::new();
    let id_foo_c = forest_c.add_node(block_foo()).unwrap();
    let id_qux_c = forest_c.add_node(block_qux()).unwrap();
    let call_c = forest_c.add_call(id_foo_c).unwrap();
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

    let mut foo_node_a = block_foo();
    foo_node_a.append_before_enter(&[deco1_a, deco2_a]);
    let id_foo_a = forest_a.add_node(foo_node_a).unwrap();

    let mut loop_node_a = LoopNode::new(id_foo_a, &forest_a).unwrap();
    loop_node_a.append_after_exit(&[deco0_a, deco2_a]);
    let id_loop_a = forest_a.add_node(loop_node_a).unwrap();

    forest_a.make_root(id_loop_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco1_b = forest_b.add_decorator(trace1.clone()).unwrap();
    let deco2_b = forest_b.add_decorator(trace2.clone()).unwrap();
    let deco3_b = forest_b.add_decorator(trace3.clone()).unwrap();

    // This foo node is identical to the one in A, including its decorators.
    let mut foo_node_b = block_foo();
    foo_node_b.append_before_enter(&[deco1_b, deco2_b]);
    let id_foo_b = forest_b.add_node(foo_node_b).unwrap();

    // This loop node's decorators are different from the loop node in a.
    let mut loop_node_b = LoopNode::new(id_foo_b, &forest_b).unwrap();
    loop_node_b.append_after_exit(&[deco1_b, deco3_b]);
    let id_loop_b = forest_b.add_node(loop_node_b).unwrap();

    forest_b.make_root(id_loop_b);

    let (merged, root_maps) = MastForest::merge([&forest_a, &forest_b]).unwrap();

    // There are 4 unique decorators across both forests.
    assert_eq!(merged.decorators.len(), 4);
    assert!(merged.decorators.contains(&trace0));
    assert!(merged.decorators.contains(&trace1));
    assert!(merged.decorators.contains(&trace2));
    assert!(merged.decorators.contains(&trace3));

    let find_decorator_id = |deco: &Decorator| {
        let idx = merged
            .decorators
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

    assert_eq!(
        &merged_foo_block.decorators().collect::<Vec<_>>()[..],
        &[(0, merged_deco1), (0, merged_deco2)]
    );

    // Asserts that there exists exactly one Loop Node with the given decorators.
    assert_eq!(
        merged
            .nodes
            .iter()
            .filter(|node| {
                if let MastNode::Loop(loop_node) = node {
                    loop_node.after_exit() == [merged_deco0, merged_deco2]
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
                    loop_node.after_exit() == [merged_deco1, merged_deco3]
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

    let mut foo_node_a = block_foo();
    foo_node_a.append_before_enter(&[deco]);
    let foo_node_digest = foo_node_a.digest();
    let id_foo_a = forest_a.add_node(foo_node_a).unwrap();

    forest_a.make_root(id_foo_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let id_external_b = forest_b.add_external(foo_node_digest).unwrap();

    forest_b.make_root(id_external_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let id_foo_a_fingerprint =
            MastNodeFingerprint::from_mast_node(&forest_a, &BTreeMap::new(), &forest_a[id_foo_a]);

        let fingerprints: Vec<_> = merged
            .nodes()
            .iter()
            .map(|node| MastNodeFingerprint::from_mast_node(&merged, &BTreeMap::new(), node))
            .collect();

        assert_eq!(merged.nodes.len(), 1);
        assert!(fingerprints.contains(&id_foo_a_fingerprint));

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

    let mut external_node_a = ExternalNode::new(block_foo().digest());
    external_node_a.append_before_enter(&[deco1]);
    external_node_a.append_after_exit(&[deco2]);
    let id_external_a = forest_a.add_node(external_node_a).unwrap();

    forest_a.make_root(id_external_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let id_foo_b = forest_b.add_node(block_foo()).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_fingerprint =
            MastNodeFingerprint::from_mast_node(&forest_a, &BTreeMap::new(), &forest_b[id_foo_b]);

        let fingerprints: Vec<_> = merged
            .nodes()
            .iter()
            .map(|node| MastNodeFingerprint::from_mast_node(&merged, &BTreeMap::new(), node))
            .collect();

        // Block foo should be unmodified.
        assert!(fingerprints.contains(&id_foo_b_fingerprint));

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

    let mut external_node_a = ExternalNode::new(block_foo().digest());
    external_node_a.append_before_enter(&[deco1_a]);
    let id_external_a = forest_a.add_node(external_node_a).unwrap();

    forest_a.make_root(id_external_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco2_b = forest_b.add_decorator(trace2.clone()).unwrap();

    let mut foo_node_b = block_foo();
    foo_node_b.append_before_enter(&[deco2_b]);
    let id_foo_b = forest_b.add_node(foo_node_b).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_fingerprint =
            MastNodeFingerprint::from_mast_node(&forest_b, &BTreeMap::new(), &forest_b[id_foo_b]);

        let fingerprints: Vec<_> = merged
            .nodes()
            .iter()
            .map(|node| MastNodeFingerprint::from_mast_node(&merged, &BTreeMap::new(), node))
            .collect();

        // Block foo should be unmodified.
        assert!(fingerprints.contains(&id_foo_b_fingerprint));

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

    let mut external_node_a = ExternalNode::new(block_foo().digest());
    external_node_a.append_before_enter(&[deco1_a]);
    external_node_a.append_after_exit(&[deco2_a]);
    let id_external_a = forest_a.add_node(external_node_a).unwrap();

    let mut external_node_b = ExternalNode::new(block_foo().digest());
    external_node_b.append_before_enter(&[deco1_a]);
    let id_external_b = forest_a.add_node(external_node_b).unwrap();

    forest_a.make_root(id_external_a);
    forest_a.make_root(id_external_b);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let deco1_b = forest_b.add_decorator(trace1).unwrap();
    let mut block_foo_b = block_foo();
    block_foo_b.append_before_enter(&[deco1_b]);
    let id_foo_b = forest_b.add_node(block_foo_b).unwrap();

    forest_b.make_root(id_foo_b);

    for (idx, (merged, root_maps)) in [
        MastForest::merge([&forest_a, &forest_b]).unwrap(),
        MastForest::merge([&forest_b, &forest_a]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(merged.nodes.len(), 1);

        let id_foo_b_fingerprint =
            MastNodeFingerprint::from_mast_node(&forest_a, &BTreeMap::new(), &forest_b[id_foo_b]);

        let fingerprints: Vec<_> = merged
            .nodes()
            .iter()
            .map(|node| MastNodeFingerprint::from_mast_node(&merged, &BTreeMap::new(), node))
            .collect();

        // Block foo should be unmodified.
        assert!(fingerprints.contains(&id_foo_b_fingerprint));

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
    let id_foo_a = forest_a.add_external(block_qux().digest()).unwrap();
    let id_call_a = forest_a.add_call(id_foo_a).unwrap();
    forest_a.make_root(id_call_a);

    let mut forest_b = MastForest::new();
    let id_ext_b = forest_b.add_external(forest_a[id_call_a].digest()).unwrap();
    let id_call_b = forest_b.add_call(id_ext_b).unwrap();
    let id_qux_b = forest_b.add_node(block_qux()).unwrap();
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
    let id_bar_a = forest_a.add_node(block_bar()).unwrap();

    forest_a.make_root(id_bar_a);

    // Build Forest B
    let mut forest_b = MastForest::new();
    let mut block_b = block_foo();
    // We're using a DecoratorId from forest A which is invalid.
    block_b.append_before_enter(&[deco1_a, deco2_a]);
    let id_foo_b = forest_b.add_node(block_b).unwrap();

    forest_b.make_root(id_foo_b);

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::DecoratorIdOverflow(_, _));
}

/// Tests that forest's advice maps are merged correctly.
#[test]
fn mast_forest_merge_advice_maps_merged() {
    let mut forest_a = MastForest::new();
    let id_foo = forest_a.add_node(block_foo()).unwrap();
    let id_call_a = forest_a.add_call(id_foo).unwrap();
    forest_a.make_root(id_call_a);
    let key_a = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let value_a = vec![ONE, ONE];
    forest_a.advice_map_mut().insert(key_a, value_a.clone());

    let mut forest_b = MastForest::new();
    let id_bar = forest_b.add_node(block_bar()).unwrap();
    let id_call_b = forest_b.add_call(id_bar).unwrap();
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
    let id_foo = forest_a.add_node(block_foo()).unwrap();
    let id_call_a = forest_a.add_call(id_foo).unwrap();
    forest_a.make_root(id_call_a);
    let key_a = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let value_a = vec![ONE, ONE];
    forest_a.advice_map_mut().insert(key_a, value_a.clone());

    let mut forest_b = MastForest::new();
    let id_bar = forest_b.add_node(block_bar()).unwrap();
    let id_call_b = forest_b.add_call(id_bar).unwrap();
    forest_b.make_root(id_call_b);
    // The key collides with key_a in the forest_a.
    let key_b = key_a;
    let value_b = vec![Felt::new(2), Felt::new(2)];
    forest_b.advice_map_mut().insert(key_b, value_b.clone());

    let err = MastForest::merge([&forest_a, &forest_b]).unwrap_err();
    assert_matches!(err, MastForestError::AdviceMapKeyCollisionOnMerge(_));
}
