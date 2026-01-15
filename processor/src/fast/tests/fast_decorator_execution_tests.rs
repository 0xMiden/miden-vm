use alloc::vec::Vec;

use miden_core::{
    Decorator, Felt, Operation,
    field::PrimeCharacteristicRing,
    mast::{BasicBlockNodeBuilder, DecoratorId, MastForest, MastForestContributor},
};

use crate::{
    AdviceInputs, Program, fast::FastProcessor,
    test_utils::test_consistency_host::TestConsistencyHost,
};

// Test helper to create a basic block with decorators for fast processor
fn create_test_program(
    before_enter: &[Decorator],
    after_exit: &[Decorator],
    operations: &[Operation],
) -> Program {
    let mut mast_forest = MastForest::new();

    // Collect decorator IDs
    let before_enter_ids: Vec<_> = before_enter
        .iter()
        .map(|decorator| mast_forest.add_decorator(decorator.clone()).unwrap())
        .collect();
    let after_exit_ids: Vec<_> = after_exit
        .iter()
        .map(|decorator| mast_forest.add_decorator(decorator.clone()).unwrap())
        .collect();

    // Create the basic block with decorators using builder pattern
    let basic_block_id = BasicBlockNodeBuilder::new(operations.to_vec(), Vec::new())
        .with_before_enter(before_enter_ids)
        .with_after_exit(after_exit_ids)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    Program::new(mast_forest.into(), basic_block_id)
}

// Test tracking decorator execution counts for fast processor
#[test]
fn test_before_enter_decorator_executed_once_fast() {
    let before_enter_decorator = Decorator::Trace(1);
    let after_exit_decorator = Decorator::Trace(2);
    let operations = [Operation::Noop];

    let program =
        create_test_program(&[before_enter_decorator], &[after_exit_decorator], &operations);

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify decorator execution counts
    assert_eq!(host.get_trace_count(1), 1, "before_enter decorator should execute exactly once");
    assert_eq!(host.get_trace_count(2), 1, "after_exit decorator should execute exactly once");

    // Verify execution order: before_enter should come before after_exit
    let order = host.get_execution_order();
    assert_eq!(order.len(), 2, "Should have exactly 2 trace events");
    assert_eq!(order[0].0, 1, "First trace should be before_enter");
    assert_eq!(order[1].0, 2, "Second trace should be after_exit");
}

#[test]
fn test_multiple_before_enter_decorators_each_once_fast() {
    let before_enter_decorators = [Decorator::Trace(1), Decorator::Trace(2), Decorator::Trace(3)];
    let after_exit_decorator = Decorator::Trace(4);
    let operations = [Operation::Noop];

    let program =
        create_test_program(&before_enter_decorators, &[after_exit_decorator], &operations);

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify decorator execution counts
    assert_eq!(
        host.get_trace_count(1),
        1,
        "first before_enter decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(2),
        1,
        "second before_enter decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(3),
        1,
        "third before_enter decorator should execute exactly once"
    );
    assert_eq!(host.get_trace_count(4), 1, "after_exit decorator should execute exactly once");

    // Verify execution order: all before_enter decorators should come before after_exit
    let order = host.get_execution_order();
    assert_eq!(order.len(), 4, "Should have exactly 4 trace events");
    assert_eq!(order[0].0, 1, "First trace should be first before_enter");
    assert_eq!(order[1].0, 2, "Second trace should be second before_enter");
    assert_eq!(order[2].0, 3, "Third trace should be third before_enter");
    assert_eq!(order[3].0, 4, "Fourth trace should be after_exit");
}

#[test]
fn test_multiple_after_exit_decorators_each_once_fast() {
    let before_enter_decorator = Decorator::Trace(1);
    let after_exit_decorators = [Decorator::Trace(2), Decorator::Trace(3), Decorator::Trace(4)];
    let operations = [Operation::Noop];

    let program =
        create_test_program(&[before_enter_decorator], &after_exit_decorators, &operations);

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify decorator execution counts
    assert_eq!(host.get_trace_count(1), 1, "before_enter decorator should execute exactly once");
    assert_eq!(
        host.get_trace_count(2),
        1,
        "first after_exit decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(3),
        1,
        "second after_exit decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(4),
        1,
        "third after_exit decorator should execute exactly once"
    );

    // Verify execution order: before_enter should come before all after_exit decorators
    let order = host.get_execution_order();
    assert_eq!(order.len(), 4, "Should have exactly 4 trace events");
    assert_eq!(order[0].0, 1, "First trace should be before_enter");
    assert_eq!(order[1].0, 2, "Second trace should be first after_exit");
    assert_eq!(order[2].0, 3, "Third trace should be second after_exit");
    assert_eq!(order[3].0, 4, "Fourth trace should be third after_exit");
}

#[test]
fn test_decorator_execution_order_fast() {
    let before_enter_decorators = [
        Decorator::Trace(1), // Executed first
        Decorator::Trace(2), // Executed second
    ];
    let after_exit_decorators = [
        Decorator::Trace(3), // Executed third (before operations)
        Decorator::Trace(4), // Executed fourth (after operations)
    ];
    let operations = [Operation::Noop];

    let program =
        create_test_program(&before_enter_decorators, &after_exit_decorators, &operations);

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify decorator execution counts
    assert_eq!(
        host.get_trace_count(1),
        1,
        "first before_enter decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(2),
        1,
        "second before_enter decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(3),
        1,
        "first after_exit decorator should execute exactly once"
    );
    assert_eq!(
        host.get_trace_count(4),
        1,
        "second after_exit decorator should execute exactly once"
    );

    // Verify execution order: before_enter decorators should come before after_exit decorators
    let order = host.get_execution_order();
    assert_eq!(order.len(), 4, "Should have exactly 4 trace events");
    assert_eq!(order[0].0, 1, "First trace should be first before_enter");
    assert_eq!(order[1].0, 2, "Second trace should be second before_enter");
    assert_eq!(order[2].0, 3, "Third trace should be first after_exit");
    assert_eq!(order[3].0, 4, "Fourth trace should be second after_exit");
}

#[test]
fn test_processor_decorator_execution() {
    let before_enter_decorator = Decorator::Trace(1);
    let after_exit_decorator = Decorator::Trace(2);
    let operations = [Operation::Noop];

    let program =
        create_test_program(&[before_enter_decorator], &[after_exit_decorator], &operations);

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    let execution_result = processor.execute_sync(&program, &mut host);
    assert!(execution_result.is_ok(), "Execution failed: {:?}", execution_result);

    // Check decorator execution
    insta::assert_debug_snapshot!(
        "trace_count",
        (host.get_trace_count(1), host.get_trace_count(2))
    );

    // Check execution order
    insta::assert_debug_snapshot!("execution_order", host.get_execution_order());
}

#[test]
fn test_no_duplication_between_inner_and_before_exit_decorators_fast() {
    // This test ensures that inner decorators (especially those attached to operation zero)
    // and before_enter/after_exit decorators are not duplicated in the fast processor

    let before_enter_decorator = Decorator::Trace(1);
    let after_exit_decorator = Decorator::Trace(2);
    let inner_decorator = Decorator::Trace(3); // Attached to operation 0 (first operation)

    // Use actual operations instead of just noop to have meaningful execution flow
    let operations = [
        Operation::Push(Felt::from_u32(1)), // Operation 0
        Operation::Push(Felt::from_u32(2)), // Operation 1
        Operation::Add,                     // Operation 2
        Operation::Drop,                    // Clean up stack to prevent overflow
    ];

    let program = create_test_program_with_inner_decorators(
        &[before_enter_decorator],
        &[after_exit_decorator],
        &operations,
        &[(0, inner_decorator)], // Inner decorator at operation 0
    );

    let mut host = TestConsistencyHost::new();
    let stack_slice = Vec::new();
    let processor = FastProcessor::new_debug(&stack_slice, AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    // Verify each decorator executes exactly once (no duplication)
    assert_eq!(host.get_trace_count(1), 1, "before_enter decorator should execute exactly once");
    assert_eq!(host.get_trace_count(2), 1, "after_exit decorator should execute exactly once");
    assert_eq!(host.get_trace_count(3), 1, "inner decorator should execute exactly once");

    // Verify execution order: before_enter -> inner decorator at op 0 -> after_exit
    let order = host.get_execution_order();
    assert_eq!(order.len(), 3, "Should have exactly 3 trace events");
    assert_eq!(order[0].0, 1, "First trace should be before_enter");
    assert_eq!(order[1].0, 3, "Second trace should be inner decorator");
    assert_eq!(order[2].0, 2, "Third trace should be after_exit");
}

// Test helper to create a basic block with both inner decorators and before_enter/after_exit
// decorators
fn create_test_program_with_inner_decorators(
    before_enter: &[Decorator],
    after_exit: &[Decorator],
    operations: &[Operation],
    inner_decorators: &[(usize, Decorator)], // (operation_index, decorator)
) -> Program {
    let mut mast_forest = MastForest::new();

    // Create the basic block with inner decorators
    let inner_decorator_list: Vec<(usize, DecoratorId)> = inner_decorators
        .iter()
        .map(|(op_idx, decorator)| {
            let decorator_id = mast_forest.add_decorator(decorator.clone()).unwrap();
            (*op_idx, decorator_id)
        })
        .collect();

    // Collect decorator IDs
    let before_enter_ids: Vec<_> = before_enter
        .iter()
        .map(|decorator| mast_forest.add_decorator(decorator.clone()).unwrap())
        .collect();
    let after_exit_ids: Vec<_> = after_exit
        .iter()
        .map(|decorator| mast_forest.add_decorator(decorator.clone()).unwrap())
        .collect();

    // Create the basic block with decorators using builder pattern
    let basic_block_id = BasicBlockNodeBuilder::new(operations.to_vec(), inner_decorator_list)
        .with_before_enter(before_enter_ids)
        .with_after_exit(after_exit_ids)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    Program::new(mast_forest.into(), basic_block_id)
}
// DECORATOR BYPASS SPY TESTS
// ================================================================================================

#[test]
fn test_decorator_bypass_in_release_mode() {
    let program =
        create_test_program(&[Decorator::Trace(1)], &[Decorator::Trace(2)], &[Operation::Noop]);
    let processor = FastProcessor::new(&[]);
    let counter = processor.decorator_retrieval_count.clone();
    let mut host = TestConsistencyHost::new();

    processor.execute_sync(&program, &mut host).unwrap();
    assert_eq!(counter.get(), 0, "decorators should not be retrieved in release mode");
}

#[test]
fn test_decorator_bypass_in_debug_mode() {
    let program =
        create_test_program(&[Decorator::Trace(1)], &[Decorator::Trace(2)], &[Operation::Noop]);
    let processor = FastProcessor::new_debug(&[], AdviceInputs::default());
    let counter = processor.decorator_retrieval_count.clone();
    let mut host = TestConsistencyHost::new();

    processor.execute_sync(&program, &mut host).unwrap();
    assert!(counter.get() > 0, "decorators should be retrieved in debug mode");
}
