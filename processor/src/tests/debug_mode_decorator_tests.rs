use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Decorator, Operation,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
};
use miden_debug_types::{Location, SourceFile, SourceSpan};

use crate::{
    AdviceInputs, AdviceMutation, AsyncHost, BaseHost, DebugError, EventError, FutureMaybeSend,
    ProcessState, Program, SyncHost, TraceError, Word, fast::FastProcessor,
    test_utils::test_consistency_host::TestConsistencyHost,
};

/// Creates a simple test program with a Trace decorator attached
fn create_debug_test_program() -> Program {
    let mut mast_forest = MastForest::new();

    // Create a Trace decorator
    let trace_decorator = Decorator::Trace(999);
    let decorator_id = mast_forest.add_decorator(trace_decorator).unwrap();

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
#[ignore = "issue #2479"]
fn test_decorators_only_execute_in_debug_mode() {
    // Test implementation to verify decorators only execute in debug mode

    // Create program with Trace decorator
    let mut forest = MastForest::new();
    let decorator = Decorator::Trace(999);
    let decorator_id = forest.add_decorator(decorator).unwrap();
    let block = BasicBlockNodeBuilder::new(
        vec![Operation::Noop],
        vec![], // decorators on ops
    )
    .with_before_enter(vec![decorator_id])
    .add_to_forest(&mut forest)
    .unwrap();

    forest.make_root(block);
    let program = Program::new(forest.into(), block);

    // Custom host to track decorator execution
    struct TestHost {
        decorator_executed: bool,
    }

    impl BaseHost for TestHost {
        fn get_label_and_source_file(
            &self,
            _location: &Location,
        ) -> (SourceSpan, Option<Arc<SourceFile>>) {
            (SourceSpan::default(), None)
        }

        fn on_debug(
            &mut self,
            _process: &mut ProcessState,
            _options: &miden_core::DebugOptions,
        ) -> Result<(), DebugError> {
            Ok(())
        }

        fn on_trace(
            &mut self,
            _process: &mut ProcessState,
            trace_id: u32,
        ) -> Result<(), TraceError> {
            if trace_id == 999 {
                self.decorator_executed = true;
            }
            Ok(())
        }
    }

    impl SyncHost for TestHost {
        fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
            None
        }

        fn on_event(&mut self, _process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
            Ok(Vec::new())
        }
    }

    impl AsyncHost for TestHost {
        fn get_mast_forest(
            &self,
            node_digest: &Word,
        ) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
            async { <Self as SyncHost>::get_mast_forest(self, node_digest) }
        }

        fn on_event(
            &mut self,
            process: &ProcessState<'_>,
        ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
            async { <Self as SyncHost>::on_event(self, process) }
        }
    }

    // Test with debug mode OFF - decorator should NOT execute
    let mut host_debug_off = TestHost { decorator_executed: false };
    let process_debug_off = FastProcessor::new(&[]);

    let result = process_debug_off.execute_sync(&program, &mut host_debug_off);
    assert!(result.is_ok(), "Execution failed: {:?}", result);
    assert!(
        !host_debug_off.decorator_executed,
        "Decorator should NOT execute when debug mode is OFF"
    );

    // Test with debug mode ON - decorator should execute
    let mut host_debug_on = TestHost { decorator_executed: false };
    let process_debug_on = FastProcessor::new_debug(&[], AdviceInputs::default());

    let result = process_debug_on.execute_sync(&program, &mut host_debug_on);
    assert!(result.is_ok(), "Execution failed: {:?}", result);
    assert!(
        host_debug_on.decorator_executed,
        "Decorator SHOULD execute when debug mode is ON"
    );
}

/// Test that verifies decorators do NOT execute when debug mode is OFF
#[test]
#[ignore = "issue #2479"]
fn test_decorators_only_execute_in_debug_mode_off() {
    // Create a test program with a Trace decorator
    let program = create_debug_test_program();

    // Create a host that will track decorator execution
    let mut host = TestConsistencyHost::new();

    // Create process with debug mode OFF (no tracing)
    let processor = FastProcessor::new(&[]);

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

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
#[ignore = "issue #2479"]
fn test_decorators_only_execute_in_debug_mode_on() {
    // Create a test program with a Trace decorator
    let program = create_debug_test_program();

    // Create a host that will track decorator execution
    let mut host = TestConsistencyHost::new();

    // Create processor with debug mode ON (tracing enabled)
    let processor = FastProcessor::new_debug(&[], AdviceInputs::default());

    // Execute the program
    let result = processor.execute_sync(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

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
#[ignore = "issue #2479"]
fn test_zero_overhead_when_debug_off() {
    // Create a more complex program with multiple decorators
    let mut mast_forest = MastForest::new();

    // Add multiple trace decorators
    let decorator1 = Decorator::Trace(100);
    let decorator2 = Decorator::Trace(200);
    let decorator3 = Decorator::Trace(300);

    let id1 = mast_forest.add_decorator(decorator1).unwrap();
    let id2 = mast_forest.add_decorator(decorator2).unwrap();
    let id3 = mast_forest.add_decorator(decorator3).unwrap();

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
    let mut host_off = TestConsistencyHost::new();
    let processor_off = FastProcessor::new(&[]);

    let result_off = processor_off.execute_sync(&program, &mut host_off);
    assert!(result_off.is_ok());

    // Verify no decorators executed
    assert_eq!(host_off.get_trace_count(100), 0);
    assert_eq!(host_off.get_trace_count(200), 0);
    assert_eq!(host_off.get_trace_count(300), 0);

    // Test with debug mode ON
    let mut host_on = TestConsistencyHost::new();
    let processor_on = FastProcessor::new_debug(&[], AdviceInputs::default());

    let result_on = processor_on.execute_sync(&program, &mut host_on);
    assert!(result_on.is_ok());

    // Verify all decorators executed
    assert_eq!(host_on.get_trace_count(100), 1);
    assert_eq!(host_on.get_trace_count(200), 1);
    assert_eq!(host_on.get_trace_count(300), 1);
}
