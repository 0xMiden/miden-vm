use alloc::vec::Vec;

use miden_assembly::testing::regex;
use miden_core::{
    advice::AdviceMap,
    operations::{Decorator, Operation},
    utils::IndexVec,
};
use miden_utils_testing::{Test, assert_diagnostic_lines};

use crate::{
    FastProcessor, Program, StackInputs,
    advice::AdviceInputs,
    mast::{BasicBlockNodeBuilder, DebugInfo, DecoratorId, MastForest, MastForestContributor},
    test_utils::TestHost,
};

fn mast_forest_with_decorator_ids(
    decorators: impl IntoIterator<Item = Decorator>,
) -> (MastForest, Vec<DecoratorId>) {
    let mut debug_info = DebugInfo::new();
    let decorator_ids = decorators
        .into_iter()
        .map(|decorator| debug_info.add_decorator(decorator).unwrap())
        .collect();
    let mast_forest =
        MastForest::from_raw_parts(IndexVec::new(), Vec::new(), AdviceMap::default(), debug_info)
            .unwrap();

    (mast_forest, decorator_ids)
}

/// Creates a simple test program with a Trace decorator attached
fn create_debug_test_program() -> Program {
    let (mut mast_forest, decorator_ids) = mast_forest_with_decorator_ids([Decorator::Trace(999)]);
    let decorator_id = decorator_ids[0];

    // Create a simple basic block with 1 operation, decorator attached before_enter
    let operations = alloc::vec![Operation::Noop];
    let basic_block_id = BasicBlockNodeBuilder::new(operations, vec![])
        .with_before_enter(vec![decorator_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    mast_forest.make_root(basic_block_id);
    Program::new(mast_forest.into(), basic_block_id)
}

/// Test that verifies decorators only execute in debug mode
#[test]
fn test_decorators_only_execute_in_debug_mode() {
    // Create program with Trace decorator
    let (mut forest, decorator_ids) = mast_forest_with_decorator_ids([Decorator::Trace(999)]);
    let decorator_id = decorator_ids[0];
    let block = BasicBlockNodeBuilder::new(
        vec![Operation::Noop],
        vec![], // decorators on ops
    )
    .with_before_enter(vec![decorator_id])
    .add_to_forest(&mut forest)
    .unwrap();

    forest.make_root(block);
    let program = Program::new(forest.into(), block);

    // Test with debug mode OFF - decorator should NOT execute
    let mut host_debug_off = TestHost::new();
    let process_debug_off = FastProcessor::new(StackInputs::default());

    let result = process_debug_off.execute_sync(&program, &mut host_debug_off);
    assert!(result.is_ok(), "Execution failed: {result:?}");
    assert!(
        host_debug_off.get_trace_count(999) == 0,
        "Decorator should NOT execute when debug mode is OFF"
    );

    // Test with debug mode ON - decorator should execute
    let mut host_debug_on = TestHost::new();
    let process_debug_on = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits")
        .with_debugging(true)
        .with_tracing(true);

    let result = process_debug_on.execute_sync(&program, &mut host_debug_on);
    assert!(result.is_ok(), "Execution failed: {result:?}");
    assert!(
        host_debug_on.get_trace_count(999) == 1,
        "Decorator SHOULD execute when debug mode is ON"
    );
}

/// Test that verifies decorators do NOT execute when debug mode is OFF
#[test]
fn test_decorators_only_execute_in_debug_mode_off() {
    // Create a test program with a Trace decorator
    let program = create_debug_test_program();

    // Create a host that will track decorator execution
    let mut host = TestHost::new();

    // Create process with debug mode OFF (no tracing)
    let processor = FastProcessor::new(StackInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {result:?}");

    // Verify that the decorator was NOT executed (trace count should be 0)
    assert_eq!(
        host.get_trace_count(999),
        0,
        "Decorator should NOT execute when debug mode is OFF"
    );

    // Verify no execution events were recorded
    let order = host.get_execution_order();
    assert_eq!(order.len(), 0, "No trace events should occur when debug mode is OFF");
}

/// Test that verifies decorators DO execute when debug mode is ON
#[test]
fn test_decorators_only_execute_in_debug_mode_on() {
    // Create a test program with a Trace decorator
    let program = create_debug_test_program();

    // Create a host that will track decorator execution
    let mut host = TestHost::new();

    // Create processor with debug mode ON (tracing enabled)
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits")
        .with_debugging(true)
        .with_tracing(true);

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {result:?}");

    // Verify that the decorator WAS executed (trace count should be 1)
    assert_eq!(
        host.get_trace_count(999),
        1,
        "Decorator should execute exactly once when debug mode is ON"
    );

    // Verify execution event was recorded
    let order = host.get_execution_order();
    assert_eq!(order.len(), 1, "Should have exactly 1 trace event when debug mode is ON");
    assert_eq!(order[0].0, 999, "Trace event should have correct ID");
}

/// Test that demonstrates the zero overhead principle by comparing execution
/// with debug mode on vs off for a more complex program
#[test]
fn test_zero_overhead_when_debug_off() {
    // Add multiple trace decorators
    let decorator1 = Decorator::Trace(100);
    let decorator2 = Decorator::Trace(200);
    let decorator3 = Decorator::Trace(300);
    let (mut mast_forest, decorator_ids) =
        mast_forest_with_decorator_ids([decorator1, decorator2, decorator3]);
    let id1 = decorator_ids[0];
    let id2 = decorator_ids[1];
    let id3 = decorator_ids[2];

    // Create a program with multiple operations and decorators
    let operations = alloc::vec![Operation::Noop, Operation::Noop, Operation::Noop,];

    let basic_block_id = BasicBlockNodeBuilder::new(operations, vec![])
        .with_before_enter(vec![id1])
        .with_after_exit(vec![id2, id3])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);

    // Test with debug mode OFF
    let mut host_off = TestHost::new();
    let processor_off = FastProcessor::new(StackInputs::default());

    let result_off = processor_off.execute_sync(&program, &mut host_off);
    assert!(result_off.is_ok());

    // Verify no decorators executed
    assert_eq!(host_off.get_trace_count(100), 0);
    assert_eq!(host_off.get_trace_count(200), 0);
    assert_eq!(host_off.get_trace_count(300), 0);

    // Test with debug mode ON
    let mut host_on = TestHost::new();
    let processor_on = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits")
        .with_debugging(true)
        .with_tracing(true);

    let result_on = processor_on.execute_sync(&program, &mut host_on);
    assert!(result_on.is_ok());

    // Verify all decorators executed
    assert_eq!(host_on.get_trace_count(100), 1);
    assert_eq!(host_on.get_trace_count(200), 1);
    assert_eq!(host_on.get_trace_count(300), 1);
}

#[test]
fn assembled_static_import_debug_decorators_survive_finalization() {
    let test = Test::new(
        "debug_trace_static_import",
        r#"
        use e2e::helpers

        begin
            push.4
            exec.helpers::traced_helper
            trace.21
            debug.stack.4
            drop
        end
        "#,
        true,
    )
    .with_module(
        "e2e::helpers",
        r#"
        pub proc traced_helper
            trace.11
            debug.stack.4
            push.1 add
            push.1
            if.true
                trace.12
                debug.stack.4
                push.2 add
            else
                trace.13
                push.0 drop
            end
        end
        "#,
    );

    let (program, _) = test.compile().expect("test program should compile");
    let mut host = TestHost::new();
    host.source_manager = test.source_manager;
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits")
        .with_debugging(true)
        .with_tracing(true);

    processor.execute_sync(&program, &mut host).expect("execution should succeed");

    assert_eq!(host.debug_handler, ["stack.4", "stack.4", "stack.4"]);
    assert_eq!(host.get_trace_count(11), 1);
    assert_eq!(host.get_trace_count(12), 1);
    assert_eq!(host.get_trace_count(13), 0);
    assert_eq!(host.get_trace_count(21), 1);
}

#[test]
fn static_import_execution_error_keeps_imported_source_location() {
    let test = Test::new(
        "debug_trace_static_import_failure",
        r#"
        use e2e::fail

        begin
            exec.fail::fail_in_import
        end
        "#,
        true,
    )
    .with_module(
        "e2e::fail",
        r#"
        pub proc fail_in_import
            trace.31
            push.0
            inv
        end
        "#,
    );

    let err = test.execute().expect_err("expected imported procedure to fail");
    #[rustfmt::skip]
    assert_diagnostic_lines!(
        err,
        "  x division by zero",
        regex!(r#",-\[e2e::fail:5:13\]"#),
        " 4 |             push.0",
        " 5 |             inv",
        "   :             ^^^",
        " 6 |         end",
        "   `----",
        "  help: ensure the divisor (second stack element) is non-zero before division or modulo operations"
    );
}
