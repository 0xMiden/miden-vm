use alloc::vec::Vec;

use miden_air_definitions::vm::PublicInputs;
use miden_core::{
    deferred::TRUE_DIGEST,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::Program,
};

use super::VmTrace;
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, ExecutionRequest, Felt, StackInputs,
    trace::build_trace,
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
    build_trace_from_program_with_stack(program, StackInputs::new(&stack_inputs).unwrap())
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
    build_trace_from_program_with_advice(program, stack_inputs, AdviceInputs::default())
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
    build_trace_from_program_with_advice(&program, stack_inputs, advice_inputs)
}

fn build_trace_from_program_with_advice(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> VmTrace {
    let options = ExecutionOptions::default()
        .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
        .unwrap()
        .with_overlapped_trace_build(false);
    ExecutionRequest::new(program)
        .with_stack_inputs(stack_inputs)
        .with_advice(advice_inputs)
        .with_options(options)
        .build_trace(miden_vm_stark::memory::default_budget())
        .run_sync(&mut DefaultHost::default())
        .unwrap()
        .trace
        .into_vm_trace()
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
        StackInputs::new(&[0, 0, 0, 0, 1, 2, 3, 4].map(Felt::new_unchecked)).unwrap();

    let mut host = DefaultHost::default();
    let execution_witness = ExecutionRequest::new(&program)
        .with_stack_inputs(stack_inputs)
        .record_witness()
        .run_sync(&mut host)
        .map(|output| output.witness)
        .unwrap();
    let claim = execution_witness.claim();
    let (vm_witness, precompile_witness) = execution_witness.into_parts();
    let precompile_root = vm_witness.precompile_root;
    assert_ne!(precompile_root, TRUE_DIGEST);

    let precompile_witness = precompile_witness.expect("logged statement must be retained");
    assert_eq!(vm_witness.claim(), claim);
    let output = ExecutionRequest::new(&program)
        .with_stack_inputs(stack_inputs)
        .execute()
        .run_sync(&mut host)
        .unwrap();
    assert_eq!(output.precompile_root(), precompile_root);
    assert_eq!(output.precompile_witness.as_ref(), Some(&precompile_witness));

    let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
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
    let execution_witness = ExecutionRequest::new(&program)
        .with_stack_inputs(stack_inputs)
        .record_witness()
        .run_sync(&mut host)
        .map(|output| output.witness)
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
    let output = ExecutionRequest::new(&program)
        .with_stack_inputs(stack_inputs)
        .execute()
        .run_sync(&mut host)
        .unwrap();
    assert_eq!(output.precompile_root(), TRUE_DIGEST);
    assert!(output.precompile_witness.is_none());

    let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
    assert_eq!(trace.init_stack_state(), stack_inputs);
    assert_eq!(trace.precompile_root(), TRUE_DIGEST);
    assert_eq!(trace.to_public_values(), expected_public_inputs.to_elements());
}

#[test]
fn clear_deferred_replays_across_fragments_and_retains_new_obligations() {
    use miden_core::{deferred::Node, serde::Serializable};

    use crate::ExecutionWitness;

    // Read the logged root after one fragment boundary, then read the cleared root after another.
    let source = alloc::format!(
        "begin
            log_deferred dropw
            repeat.{TEST_TRACE_FRAGMENT_SIZE} nop end
            adv.push_deferred_root adv_loadw
            clear_deferred
            repeat.{TEST_TRACE_FRAGMENT_SIZE} nop end
            adv.push_deferred_root padw adv_loadw
            assertz assertz assertz assertz
            log_deferred
        end"
    );
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", &source)
        .unwrap()
        .unwrap_program();
    let options = ExecutionOptions::default()
        .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
        .unwrap();
    let witness = ExecutionRequest::new(&program)
        .with_options(options)
        .record_witness()
        .run_sync(&mut DefaultHost::default())
        .unwrap()
        .witness;
    let restored = ExecutionWitness::read_from_bytes(&witness.to_bytes()).unwrap();
    let (trace, precompile_witness) = restored
        .build_trace(miden_vm_stark::memory::default_budget())
        .unwrap()
        .into_parts();
    let first_root = Node::and(TRUE_DIGEST, TRUE_DIGEST).digest();
    let expected_root = Node::and(TRUE_DIGEST, first_root).digest();
    assert_eq!(trace.precompile_root(), expected_root);
    assert!(precompile_witness.is_some());
    assert_eq!(trace.stack_outputs().get_word(0), Some(expected_root));
    assert_eq!(trace.precompile_root(), expected_root);
    miden_vm_stark::debug::check_constraints(&trace);
}
