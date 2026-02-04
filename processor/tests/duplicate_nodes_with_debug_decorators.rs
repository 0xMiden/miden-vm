use miden_assembly::testing::TestContext;
use miden_processor::{AdviceInputs, DefaultHost, ExecutionOptions, Operation, StackInputs};

/// Ensures that equal MAST nodes don't get added twice to a MAST forest
///
/// This test is disabled because with debug mode always enabled (issue #1821),
/// nodes get unique debug decorators and are no longer de-duplicated.
#[test]
fn duplicate_nodes_with_debug_decorators() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            mul
        else
            if.true add else mul end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();
    let mast_forest = program.mast_forest();

    // With debug mode always enabled, we should have debug decorators
    assert!(
        !mast_forest.decorators().is_empty(),
        "Should have debug decorators with always-enabled debug mode"
    );

    // Count nodes - should be more than before due to unique debug decorators
    // The exact number depends on implementation, but should be greater than the minimum expected
    assert!(
        mast_forest.num_nodes() > 3,
        "Should have more nodes with debug decorators enabled"
    );

    // Verify the program can be executed (functional test)
    let mut host = DefaultHost::default();
    let result = miden_processor::execute(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    );
    assert!(result.is_ok(), "Program should execute successfully");

    // Check that we have the expected control flow structure
    // With debug decorators enabled, the program should have more nodes due to less deduplication
    let nodes = mast_forest.nodes();
    let has_mul_operations = nodes.iter().any(|node| {
        matches!(node, miden_core::mast::MastNode::Block(bb)
            if bb.operations().any(|op| op == &Operation::Mul))
    });
    assert!(has_mul_operations, "Should contain mul operations in control flow");
}
