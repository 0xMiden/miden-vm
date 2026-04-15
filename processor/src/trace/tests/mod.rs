use alloc::vec::Vec;

use miden_core::{
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
    operations::Operation,
    program::Program,
};
use miden_utils_testing::rand::rand_array;

use super::{ExecutionTrace, Felt};
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, StackInputs, trace::build_trace,
};

mod chiplets;
mod lookup;
mod lookup_harness;

// TODO(logup-overflow): restore the stack-overflow-table test once
// `BUS_STACK_OVERFLOW_TABLE` is wired into `MidenLookupAir`. The pre-deletion blob lives at
// `git show 974cde516^:processor/src/trace/tests/stack.rs`.

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
        StackInputs::new(&stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    );
    let trace_inputs = processor.execute_trace_inputs_sync(program, &mut host).unwrap();
    build_trace(trace_inputs).unwrap()
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

/// Builds a sample trace by executing a span block containing the specified operations. Unlike
/// [`build_trace_from_ops`], this variant accepts the full [`AdviceInputs`] object, so the
/// program can run against an initialised advice provider (e.g. to seed a Merkle tree for the
/// sibling-table tests).
#[allow(dead_code)]
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
    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    );
    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();
    build_trace(trace_inputs).unwrap()
}
