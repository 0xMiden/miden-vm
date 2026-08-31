// MAST FOREST MERGING
// ================================================================================================

use super::*;

/// Reproduces issue #3035: a MAST with padded basic blocks must not grow during self-merge.
#[test]
fn issue_3035_self_merge_does_not_grow_mast() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(source_file!(
        &context,
        "
            namespace issue_3035::repro

            pub proc repro
                add
                push.100
            end
            "
    ))?;

    let library = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        module,
        None::<Box<Module>>,
    )?;
    let forest = library.mast_forest().as_ref().clone();
    assert!(
        forest
            .nodes()
            .iter()
            .filter_map(|node| node.get_basic_block())
            .any(|block| { block.operations().count() > block.raw_operations().count() }),
        "test input must create at least one padded basic block"
    );

    let original_size = forest.to_bytes().len();
    let explicit_size = {
        let mut bytes = Vec::new();
        forest.write_into(&mut bytes);
        bytes.len()
    };
    let original_nodes = forest.nodes().len();
    let (merged, _) = MastForest::merge([&forest]).into_diagnostic()?;
    let merged_size = merged.to_bytes().len();
    let merged_explicit_size = {
        let mut bytes = Vec::new();
        merged.write_into(&mut bytes);
        bytes.len()
    };
    let merged_nodes = merged.nodes().len();

    assert!(
        merged_size <= original_size,
        "MastForest self-merge increased serialized execution size: \
         original={original_size}, merged={merged_size}, \
         explicit={explicit_size}, merged_explicit={merged_explicit_size}, \
         original_nodes={original_nodes}, merged_nodes={merged_nodes}"
    );

    Ok(())
}

/// Test for issue #1644: verify that single-forest merge doesn't preserves node digests
#[test]
fn issue_1644_single_forest_merge_identity() -> TestResult {
    // Test to more precisely demonstrate MastForest::merge non-identity behavior
    // This test focuses on the case where merge operation does not preserve identity for single
    // forests

    let context = TestContext::new();

    // Create a simple program that will result in specific basic block structures

    let program_source = r#"
    proc test
        push.1
        push.2
        push.3
    end

    proc main
        push.10
        if.true
            exec.test
            push.20
        else
            push.30
        end
        push.40
    end

    begin
        exec.main
    end"#;

    let program = context.assemble(program_source)?;
    let original_forest = program.mast_forest().clone();

    // Core test: Merge the forest with itself
    // This should act as identity (return the same forest) but doesn't
    let (merged_forest, _) = MastForest::merge([&*original_forest]).into_diagnostic()?;

    // Assert that the merged forest still contains the same join structure even if finalization
    // order changes where that join appears.
    let original_join = original_forest
        .nodes()
        .iter()
        .find_map(|node| match node {
            MastNode::Join(join) => Some(join),
            _ => None,
        })
        .expect("original forest must contain a join node");
    let merged_join = merged_forest
        .nodes()
        .iter()
        .find_map(|node| match node {
            MastNode::Join(join) => Some(join),
            _ => None,
        })
        .expect("merged forest must contain a join node");

    // Check that they have the same structure. Finalization may remap node IDs, so compare the
    // children by content commitment rather than by positional ID.
    assert_eq!(
        original_forest[original_join.first()].digest(),
        merged_forest[merged_join.first()].digest(),
    );
    assert_eq!(
        original_forest[original_join.second()].digest(),
        merged_forest[merged_join.second()].digest(),
    );
    assert_eq!(original_join.digest(), merged_join.digest());

    //Assert that merging is idempotent
    let (new_merged_forest, _) = MastForest::merge([&merged_forest]).into_diagnostic()?;
    let mut should_panic = false;

    // The merge operation does not act as identity for single-element arrays
    // Check 1: Forest structure should be identical (same number of nodes)
    if new_merged_forest.nodes().len() != merged_forest.nodes().len() {
        eprintln!(
            "Forest node count differs: original={}, merged={}",
            new_merged_forest.nodes().len(),
            merged_forest.nodes().len()
        );
        eprintln!("This violates the identity requirement for merge operation");

        should_panic = true;
    }

    // Check 2: Each node should have identical digest (strict identity)
    for (i, (orig_node, merged_node)) in
        new_merged_forest.nodes().iter().zip(merged_forest.nodes().iter()).enumerate()
    {
        if orig_node.digest() != merged_node.digest() {
            eprintln!("Node {i} digest violation:");
            eprintln!("   Original: {orig_node:?}");
            eprintln!("   Merged:   {merged_node:?}");
            eprintln!("   Original digest: {:?}", orig_node.digest());
            eprintln!("   Merged digest:   {:?}", merged_node.digest());

            should_panic = true;
        }
    }

    // Check 3: Roots should be identical
    for (i, (orig_root, merged_root)) in new_merged_forest
        .procedure_roots()
        .iter()
        .zip(merged_forest.procedure_roots())
        .enumerate()
    {
        if new_merged_forest[*orig_root].digest() != merged_forest[*merged_root].digest() {
            eprintln!("Root {i} digest violation:");
            eprintln!("   Original: {:?}", original_forest[*orig_root].digest());
            eprintln!("   Merged:   {:?}", merged_forest[*merged_root].digest());
            should_panic = true;
        }
    }

    if should_panic {
        panic!("Merge idempotence violation");
    }

    eprintln!("Merge identity test passed - no violations detected");
    Ok(())
}
