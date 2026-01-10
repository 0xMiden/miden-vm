use alloc::vec::Vec;

use miden_core::{
    Kernel, ONE, Operation, Program, Word, ZERO,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
};
use miden_utils_testing::rand::rand_array;

use super::{super::chiplets::init_state_from_words, ExecutionTrace, Felt};
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, StackInputs, fast::FastProcessor,
    parallel::build_trace,
};

mod chiplets;
mod decoder;
mod hasher;
mod range;
mod stack;

/// Size of trace fragments used in tests.
///
/// We make it relatively small to speed up the tests and reduce memory usage.
const TEST_TRACE_FRAGMENT_SIZE: usize = 1 << 10;

// TEST HELPERS
// ================================================================================================

/// Builds a sample trace by executing the provided code block against the provided stack inputs.
pub fn build_trace_from_program(program: &Program, stack_inputs: &[u64]) -> ExecutionTrace {
    let stack_inputs = stack_inputs.iter().map(|&v| Felt::new(v)).collect::<Vec<Felt>>();
    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        &stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    );
    let (execution_output, trace_generation_context) =
        processor.execute_for_trace_sync(program, &mut host).unwrap();

    build_trace(execution_output, trace_generation_context, program.hash(), Kernel::default())
}

/// Builds a sample trace by executing a span block containing the specified operations. This
/// results in 1 additional hash cycle (8 rows) at the beginning of the hash chiplet.
pub fn build_trace_from_ops(operations: Vec<Operation>, stack: &[u64]) -> ExecutionTrace {
    let mut mast_forest = MastForest::new();

    let basic_block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    build_trace_from_program(&program, stack)
}

/// Builds a sample trace by executing a span block containing the specified operations. Unlike the
/// function above, this function accepts the full [AdviceInputs] object, which means it can run
/// the programs with initialized advice provider.
pub fn build_trace_from_ops_with_inputs(
    operations: Vec<Operation>,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> ExecutionTrace {
    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    // StackInputs stores elements in "top-first" order (after reversal in its constructor).
    // FastProcessor expects "bottom-first" order where the last element becomes top of stack.
    // So we need to reverse the StackInputs elements.
    let stack_values: Vec<Felt> = stack_inputs.iter().rev().copied().collect();

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        &stack_values,
        advice_inputs,
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    );
    let (execution_output, trace_generation_context) =
        processor.execute_for_trace_sync(&program, &mut host).unwrap();

    build_trace(execution_output, trace_generation_context, program.hash(), Kernel::default())
}
