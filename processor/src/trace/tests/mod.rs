use alloc::vec::Vec;

use miden_air::PublicInputs;
use miden_core::{
    deferred::TRUE_DIGEST,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::Program,
};
use miden_utils_testing::rand::rand_array;

use super::{Felt, VmTrace};
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, StackInputs, trace::build_trace,
};

mod chiplets;
mod decoder;
mod lookup;
mod lookup_harness;
mod range;
mod stack;

/// Size of trace fragments used in tests.
///
/// We make it relatively small to speed up the tests and reduce memory usage.
const TEST_TRACE_FRAGMENT_SIZE: usize = 1 << 10;

// TEST HELPERS
// ================================================================================================

/// Builds a sample trace by executing the provided code block against the provided stack inputs.
pub fn build_trace_from_program(program: &Program, stack_inputs: &[u64]) -> VmTrace {
    let stack_inputs = stack_inputs.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<Felt>>();
    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(&stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let execution_witness = processor.execute_for_proving_sync(program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    build_trace(vm_witness).unwrap()
}

/// Builds a sample trace by executing the provided program with pre-built `StackInputs`.
///
/// Unlike [`build_trace_from_program`], this helper accepts a `StackInputs` value directly so
/// that callers can supply `Felt` elements (e.g. a procedure hash word) without having to
/// convert them through `u64` first.
pub fn build_trace_from_program_with_stack(
    program: &Program,
    stack_inputs: StackInputs,
) -> VmTrace {
    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let execution_witness = processor.execute_for_proving_sync(program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    build_trace(vm_witness).unwrap()
}

/// Builds a sample trace by executing a span block containing the specified operations. This
/// results in 1 additional hash cycle (8 rows) at the beginning of the hash chiplet.
pub fn build_trace_from_ops(operations: Vec<Operation>, stack: &[u64]) -> VmTrace {
    let mut mast_forest = MastForest::new();

    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    build_trace_from_program(&program, stack)
}

/// Builds a sample trace by executing a span block containing the specified operations. Unlike
/// [`build_trace_from_ops`], this variant accepts the full [`AdviceInputs`] object, so the
/// program can run against an initialised advice provider (e.g. to seed a Merkle tree for the
/// sibling-table tests).
pub fn build_trace_from_ops_with_inputs(
    operations: Vec<Operation>,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> VmTrace {
    let mut mast_forest = MastForest::new();
    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);
    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        ExecutionOptions::default()
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let execution_witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    build_trace(vm_witness).unwrap()
}

#[test]
fn non_empty_execution_witness_splits_with_matching_precompile_root() {
    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::LogDeferred])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);
    let stack_inputs =
        StackInputs::new(&[1, 2, 3, 4, 0, 0, 0, 0].map(Felt::new_unchecked)).unwrap();

    let mut host = DefaultHost::default();
    let execution_witness = FastProcessor::new(stack_inputs)
        .execute_for_proving_sync(&program, &mut host)
        .unwrap();
    let claim = execution_witness.claim();
    let (vm_witness, precompile_witness) = execution_witness.into_parts();
    let precompile_root = vm_witness.precompile_root;
    assert_ne!(precompile_root, TRUE_DIGEST);

    let precompile_witness = precompile_witness.expect("logged statement must be retained");
    assert_eq!(vm_witness.claim(), claim);
    assert_eq!(precompile_witness.roots(), &[precompile_root]);

    let trace = build_trace(vm_witness).unwrap();
    assert_eq!(trace.precompile_root(), precompile_root);
}

#[test]
fn empty_execution_witness_splits_and_replays_with_explicit_stack_inputs() {
    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);
    let stack_inputs = StackInputs::new(&[7, 9].map(Felt::new_unchecked)).unwrap();

    let mut host = DefaultHost::default();
    let execution_witness = FastProcessor::new(stack_inputs)
        .execute_for_proving_sync(&program, &mut host)
        .unwrap();

    let claim = execution_witness.claim();
    assert_eq!(claim.to_program_info(), program.to_info());
    assert_eq!(claim.stack_inputs(), &stack_inputs);
    let expected_public_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        TRUE_DIGEST,
    );

    let (vm_witness, precompile_witness) = execution_witness.into_parts();
    assert_eq!(vm_witness.claim(), claim);
    assert_eq!(vm_witness.precompile_root, TRUE_DIGEST);
    assert!(precompile_witness.is_none());

    let trace = build_trace(vm_witness).unwrap();
    assert_eq!(trace.init_stack_state(), stack_inputs);
    assert_eq!(trace.precompile_root(), TRUE_DIGEST);
    assert_eq!(trace.to_public_values(), expected_public_inputs.to_elements());
}
