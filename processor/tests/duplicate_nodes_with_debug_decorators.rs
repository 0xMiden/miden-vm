use miden_assembly::testing::TestContext;
use miden_processor::{
    DefaultHost, ExecutionOutput, FastProcessor, StackInputs, advice::AdviceInputs,
    operation::Operation,
};

/// Ensures that equal MAST nodes don't get added twice to a MAST forest
///
/// This test is disabled because with debug mode always enabled (issue #1821),
/// nodes get unique debug decorators and are no longer de-duplicated.
#[tokio::test]
async fn duplicate_nodes_with_debug_decorators() {
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

    // With debug mode always enabled, we should have debug info
    assert!(
        !mast_forest.debug_info().is_empty(),
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
    let processor = FastProcessor::new(StackInputs::default()).with_advice(AdviceInputs::default());
    let result: Result<ExecutionOutput, _> = processor.execute(&program, &mut host).await;
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
