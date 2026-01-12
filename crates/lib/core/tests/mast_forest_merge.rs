use miden_processor::{
    MastForest, MastNode, MastNodeExt,
    utils::{Deserializable, Serializable},
};

/// Tests that the core library merged with itself produces a forest that has the same procedure
/// roots.
///
/// This test is added here since we do not have the StdLib in miden-core where merging is
/// implemented and the StdLib serves as a convenient example of a large MastForest.
#[test]
fn mast_forest_merge_core_lib() {
    let std_lib = miden_core_lib::CoreLibrary::default();
    let std_forest = std_lib.mast_forest().as_ref();

    let (merged, _) = MastForest::merge([std_forest, std_forest]).unwrap();

    let merged_digests = merged.procedure_digests().collect::<Vec<_>>();
    for digest in std_forest.procedure_digests() {
        assert!(merged_digests.contains(&digest));
    }
}

/// Tests that the core library with its multi-batch basic blocks round-trips through serialization.
///
/// The standard library contains many procedures with >72 operations, ensuring multi-batch
/// serialization is tested comprehensively.
#[test]
fn test_core_lib_serialization_roundtrip() {
    let std_lib = miden_core_lib::CoreLibrary::default();
    let original_forest = std_lib.mast_forest().as_ref();

    // Count multi-batch blocks in the stdlib
    let multi_batch_count = original_forest
        .nodes()
        .iter()
        .filter_map(|node| {
            if let MastNode::Block(block) = node {
                if block.op_batches().len() > 1 { Some(()) } else { None }
            } else {
                None
            }
        })
        .count();

    assert!(
        multi_batch_count > 0,
        "Standard library should contain basic blocks with multiple batches"
    );

    // Round-trip through serialization
    let serialized = original_forest.to_bytes();
    let deserialized_forest =
        MastForest::read_from_bytes(&serialized).expect("Failed to deserialize standard library");

    // Verify forest structure is preserved
    assert_eq!(
        original_forest.num_nodes(),
        deserialized_forest.num_nodes(),
        "Node count mismatch after serialization"
    );

    assert_eq!(
        original_forest.num_procedures(),
        deserialized_forest.num_procedures(),
        "Procedure count mismatch after serialization"
    );

    // Verify all procedure roots match
    let original_roots: Vec<_> = original_forest.procedure_roots().iter().collect();
    let deserialized_roots: Vec<_> = deserialized_forest.procedure_roots().iter().collect();
    assert_eq!(original_roots, deserialized_roots, "Procedure roots mismatch");

    // Verify all nodes have matching digests
    for (idx, (orig_node, deser_node)) in
        original_forest.nodes().iter().zip(deserialized_forest.nodes()).enumerate()
    {
        assert_eq!(orig_node.digest(), deser_node.digest(), "Node {} digest mismatch", idx);

        // For basic blocks, verify OpBatch structure is preserved
        if let (MastNode::Block(orig_block), MastNode::Block(deser_block)) = (orig_node, deser_node)
        {
            assert_eq!(
                orig_block.op_batches(),
                deser_block.op_batches(),
                "Node {} OpBatch structure mismatch",
                idx
            );
        }
    }
}
