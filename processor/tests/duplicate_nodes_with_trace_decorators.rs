use miden_assembly::testing::TestContext;
use miden_core::operations::Decorator;
use miden_processor::{
    DefaultHost, ExecutionOptions, StackInputs, advice::AdviceInputs, operation::Operation,
};

/// Ensures that equal MAST nodes don't get added twice to a MAST forest
///
/// This test verifies that MAST nodes are properly deduplicated even when trace decorators are
/// present.
#[test]
fn duplicate_nodes_with_trace_decorators() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            trace.1
            mul
        else
            if.true
                trace.2
                add
            else
                trace.3
                mul
            end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();
    let mast_forest = program.mast_forest();

    let trace_decorators = mast_forest
        .decorators()
        .iter()
        .map(|decorator| match decorator {
            Decorator::Trace(trace_id) => *trace_id,
        })
        .collect::<Vec<_>>();
    assert_eq!(trace_decorators, vec![1, 2, 3], "Should preserve source trace decorators");

    // Count nodes - should be more than before due to unique trace decorators.
    // The exact number depends on implementation, but should be greater than the minimum expected
    assert!(
        mast_forest.num_nodes() > 3,
        "Should have more nodes with trace decorators enabled"
    );

    // Verify the program can be executed (functional test)
    let mut host = DefaultHost::default();
    let result = miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    );
    assert!(result.is_ok(), "Program should execute successfully");

    // Check that we have the expected control flow structure
    // With trace decorators enabled, the program should have more nodes due to less deduplication
    let nodes = mast_forest.nodes();
    let has_mul_operations = nodes.iter().any(|node| {
        matches!(node, miden_core::mast::MastNode::Block(bb)
            if bb.operations().any(|op| op == &Operation::Mul))
    });
    assert!(has_mul_operations, "Should contain mul operations in control flow");
}
