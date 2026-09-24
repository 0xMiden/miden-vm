//! Regression tests for decoder REPEAT-predecessor soundness.

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, LoopNodeBuilder, MastForest},
    operations::Operation,
    program::{Program, StackOutputs},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

struct ForgedRepeatTrace {
    repro: ReproTrace,
    core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    poseidon2: RowMajorMatrix<Felt>,
    forged_outputs: StackOutputs,
}

fn build_program(root_ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(root_ops).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    Program::new(mast_forest.into(), root)
}

fn build_loop_program(body_ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(body_ops).add_to_forest(&mut mast_forest).unwrap();
    let root = LoopNodeBuilder::new(body).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    Program::new(mast_forest.into(), root)
}

fn execute(program: &Program, stack: &[u64]) -> miden_processor::trace::VmTrace {
    let stack = stack.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>();
    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::new(&stack).unwrap())
        .execute_and_build_trace_sync(program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());
    trace
}

fn matrix_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> Vec<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].to_vec()
}

fn set_matrix_row(matrix: &mut RowMajorMatrix<Felt>, row: usize, values: &[Felt]) {
    let width = matrix.width();
    assert_eq!(values.len(), width);
    matrix.values[row * width..(row + 1) * width].copy_from_slice(values);
}

fn copy_matrix_row(
    dst: &mut RowMajorMatrix<Felt>,
    dst_row: usize,
    src: &RowMajorMatrix<Felt>,
    src_row: usize,
) {
    assert_eq!(dst.width(), src.width());
    let values = matrix_row(src, src_row);
    set_matrix_row(dst, dst_row, &values);
}

fn core_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &miden_air::CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn set_core_clk(matrix: &mut RowMajorMatrix<Felt>, row: usize) {
    core_row_mut(matrix, row).system.clk = Felt::from_u32(row as u32);
}

fn copy_body_hash_evidence(
    chiplets: &mut RowMajorMatrix<Felt>,
    poseidon2: &mut RowMajorMatrix<Felt>,
    body_chiplets: &RowMajorMatrix<Felt>,
    body_poseidon2: &RowMajorMatrix<Felt>,
) {
    // In this fixture the injected body hash uses controller chip_clk 3/4 and Poseidon2 perm_id 1.
    copy_matrix_row(chiplets, 2, body_chiplets, 2);
    copy_matrix_row(chiplets, 3, body_chiplets, 3);
    for row in 16..32 {
        copy_matrix_row(poseidon2, row, body_poseidon2, row);
    }
}

fn build_forged_repeat_injection_trace() -> ForgedRepeatTrace {
    let victim = build_program(vec![Operation::Noop]);
    let victim_trace = execute(&victim, &[1, 1]);

    let body_ops = vec![Operation::Not];
    let one_iteration_loop = build_loop_program(body_ops.clone());
    let one_iteration_trace = execute(&one_iteration_loop, &[1]);

    let two_iteration_loop = build_loop_program(body_ops);
    let two_iteration_trace = execute(&two_iteration_loop, &[0, 1]);

    let (mut core, mut chiplets, mut poseidon2) = victim_trace.main_trace().to_air_matrices();
    let (repeat_core, ..) = two_iteration_trace.main_trace().to_air_matrices();
    let (body_core, body_chiplets, body_poseidon2) =
        one_iteration_trace.main_trace().to_air_matrices();

    let victim_end = matrix_row(&core, 2);

    // Victim rows are:
    //   0 SPAN_A | 1 NOOP_A | 2 END_A | 3 HALT...
    // Replace HALT padding so the forged trace becomes:
    //   0 SPAN_A | 1 NOOP_A | 2 REPEAT | 3 SPAN_X | 4 X | 5 END_X | 6 END_A | 7 HALT...
    copy_matrix_row(&mut core, 2, &repeat_core, 4);
    for (dst, src) in [(3, 1), (4, 2), (5, 3)] {
        copy_matrix_row(&mut core, dst, &body_core, src);
    }
    set_matrix_row(&mut core, 6, &victim_end);

    for row in 2..=6 {
        set_core_clk(&mut core, row);
    }

    let final_stack = core_row(&core, 5).stack.clone();
    core_row_mut(&mut core, 6).stack = final_stack.clone();
    for row in 7..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let forged_outputs = StackOutputs::from(final_stack.top);

    // Copy the body basic-block hash controller rows and their Poseidon2 cycle into victim padding.
    copy_body_hash_evidence(&mut chiplets, &mut poseidon2, &body_chiplets, &body_poseidon2);

    ForgedRepeatTrace {
        repro: ReproTrace::new(&victim_trace),
        core,
        chiplets,
        poseidon2,
        forged_outputs,
    }
}

fn build_direct_repeat_without_body_hash_evidence_trace() -> ForgedRepeatTrace {
    let victim = build_program(vec![Operation::Noop]);
    let victim_trace = execute(&victim, &[1, 1]);

    let two_iteration_loop = build_loop_program(vec![Operation::Not]);
    let two_iteration_trace = execute(&two_iteration_loop, &[0, 1]);

    let (mut core, chiplets, poseidon2) = victim_trace.main_trace().to_air_matrices();
    let (repeat_core, ..) = two_iteration_trace.main_trace().to_air_matrices();

    // Keep the illegal in-span -> REPEAT transition, but do not add the matching injected body
    // block or hash-chiplet evidence. This isolates the early-exit half from the free digest half.
    copy_matrix_row(&mut core, 2, &repeat_core, 4);
    set_core_clk(&mut core, 2);

    let final_stack = core_row(&core, 2).stack.clone();
    for row in 3..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let forged_outputs = StackOutputs::from(final_stack.top);

    ForgedRepeatTrace {
        repro: ReproTrace::new(&victim_trace),
        core,
        chiplets,
        poseidon2,
        forged_outputs,
    }
}

fn build_body_hash_evidence_without_direct_repeat_trace() -> ForgedRepeatTrace {
    let victim = build_program(vec![Operation::Noop]);
    let victim_trace = execute(&victim, &[1, 1]);

    let body = build_loop_program(vec![Operation::Not]);
    let body_trace = execute(&body, &[1]);

    let (core, mut chiplets, mut poseidon2) = victim_trace.main_trace().to_air_matrices();
    let (_, body_chiplets, body_poseidon2) = body_trace.main_trace().to_air_matrices();

    // Supply valid hash-table evidence for the attacker-chosen body, but leave the Core trace
    // honest: no in-span -> REPEAT edge consumes that evidence or changes the public outputs.
    copy_body_hash_evidence(&mut chiplets, &mut poseidon2, &body_chiplets, &body_poseidon2);

    ForgedRepeatTrace {
        repro: ReproTrace::new(&victim_trace),
        core,
        chiplets,
        poseidon2,
        forged_outputs: *victim_trace.stack_outputs(),
    }
}

#[test]
fn forged_in_span_repeat_injection_is_rejected_by_proof_pipeline() {
    let forged = build_forged_repeat_injection_trace();
    assert_ne!(forged.forged_outputs, forged.repro.outputs());

    let result = forged.repro.prove_and_verify_parts_allowing_lookup_rejection(
        forged.core,
        forged.chiplets,
        forged.poseidon2,
        forged.forged_outputs,
    );
    assert!(
        result.is_err(),
        "the proof pipeline must reject an in-span row exiting directly to REPEAT: {result:?}"
    );
}

#[test]
fn direct_repeat_without_body_hash_evidence_is_rejected() {
    let forged = build_direct_repeat_without_body_hash_evidence_trace();

    let result = forged.repro.prove_and_verify_parts_allowing_lookup_rejection(
        forged.core,
        forged.chiplets,
        forged.poseidon2,
        forged.forged_outputs,
    );
    assert!(
        result.is_err(),
        "the proof pipeline must reject the direct REPEAT edge when no matching body-hash evidence \
         is supplied: {result:?}"
    );
}

#[test]
fn body_hash_evidence_without_direct_repeat_is_rejected() {
    let forged = build_body_hash_evidence_without_direct_repeat_trace();

    let result = forged.repro.prove_and_verify_parts_allowing_lookup_rejection(
        forged.core,
        forged.chiplets,
        forged.poseidon2,
        forged.forged_outputs,
    );
    assert!(
        result.is_err(),
        "the proof pipeline must reject attacker body-hash evidence when no direct REPEAT edge \
         consumes it: {result:?}"
    );
}
