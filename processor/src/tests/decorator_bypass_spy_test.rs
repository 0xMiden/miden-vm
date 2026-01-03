//! Tests that decorator retrieval is bypassed when `in_debug_mode` is false.

use alloc::vec::Vec;

use miden_core::{
    Decorator, Kernel, Operation,
    mast::{BasicBlockNodeBuilder, DecoratorId, MastForest, MastForestContributor},
};

use crate::{AdviceInputs, ExecutionOptions, Process, Program, StackInputs};

fn create_program_with_decorators() -> Program {
    let mut mast_forest = MastForest::new();

    let trace1 = Decorator::Trace(100);
    let trace2 = Decorator::Trace(200);
    let trace3 = Decorator::Trace(300);

    let id1 = mast_forest.add_decorator(trace1).unwrap();
    let id2 = mast_forest.add_decorator(trace2).unwrap();
    let id3 = mast_forest.add_decorator(trace3).unwrap();

    let operations = vec![
        Operation::Push(1_u32.into()),
        Operation::Push(2_u32.into()),
        Operation::Add,
        Operation::Drop,
    ];

    let op_decorators: Vec<(usize, DecoratorId)> = vec![(0, id3)];

    let basic_block_id = BasicBlockNodeBuilder::new(operations, op_decorators)
        .with_before_enter(vec![id1])
        .with_after_exit(vec![id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    mast_forest.make_root(basic_block_id);
    Program::new(mast_forest.into(), basic_block_id)
}

#[test]
fn test_decorator_retrieval_bypassed_in_release_mode() {
    let program = create_program_with_decorators();
    let mut host = crate::test_utils::test_consistency_host::TestConsistencyHost::new();

    let mut process = Process::new(
        Kernel::default(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );

    assert!(!process.decoder.in_debug_mode());

    let result = process.execute(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    assert_eq!(
        process.decorator_retrieval_count.get(),
        0,
        "decorator retrieval should be bypassed in release mode, got {} calls",
        process.decorator_retrieval_count.get()
    );
}

#[test]
fn test_decorator_retrieval_happens_in_debug_mode() {
    let program = create_program_with_decorators();
    let mut host = crate::test_utils::test_consistency_host::TestConsistencyHost::new();

    let mut process = Process::new(
        Kernel::default(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_tracing(),
    );

    assert!(process.decoder.in_debug_mode());

    let result = process.execute(&program, &mut host);
    assert!(result.is_ok(), "Execution failed: {:?}", result);

    assert!(
        process.decorator_retrieval_count.get() > 0,
        "decorator retrieval should occur in debug mode"
    );
}
