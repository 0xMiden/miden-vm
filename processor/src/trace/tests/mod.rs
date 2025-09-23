use alloc::vec::Vec;

use miden_core::{Kernel, ONE, Operation, Program, StackOutputs, Word, ZERO, mast::MastForest};
use miden_utils_testing::rand::rand_array;

use super::{
    super::chiplets::init_state_from_words, ExecutionTrace, Felt, FieldElement, NUM_RAND_ROWS,
    Process, Trace,
};
use crate::{AdviceInputs, DefaultHost, ExecutionOptions, StackInputs};

mod chiplets;
mod decoder;
mod hasher;
mod range;
mod stack;

// TEST HELPERS
// ================================================================================================

/// Builds a sample trace by executing the provided code block against the provided stack inputs.
pub fn build_trace_from_program(program: &Program, stack_inputs: &[u64]) -> ExecutionTrace {
    let stack_inputs = StackInputs::try_from_ints(stack_inputs.iter().copied()).unwrap();
    let mut host = DefaultHost::default();
    let mut process = Process::new(
        Kernel::default(),
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    process.execute(program, &mut host).unwrap();
    ExecutionTrace::new(process, StackOutputs::default())
}

/// Builds a sample trace by executing a span block containing the specified operations. This
/// results in 1 additional hash cycle (8 rows) at the beginning of the hash chiplet.
pub fn build_trace_from_ops(operations: Vec<Operation>, stack: &[u64]) -> ExecutionTrace {
    let mut mast_forest = MastForest::new();

    let basic_block_id = mast_forest.add_block(operations, Vec::new()).unwrap();
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
    let mut host = DefaultHost::default();
    let mut process =
        Process::new(Kernel::default(), stack_inputs, advice_inputs, ExecutionOptions::default());

    let mut mast_forest = MastForest::new();
    let basic_block_id = mast_forest.add_block(operations, Vec::new()).unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    process.execute(&program, &mut host).unwrap();
    ExecutionTrace::new(process, StackOutputs::default())
}
