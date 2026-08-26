//! Repro for repeated-loop body digest telescoping.
//!
//! A forged trace used to be able to execute an attacker-selected first loop iteration while
//! keeping the final iteration equal to the committed loop body. The block-hash multiset
//! telescoped through REPEAT rows and only bound the final iteration to the LOOP row's committed
//! body digest. REPEAT rows no longer add loop-body entries, so this forgery must be rejected.

use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

use miden_air::{
    CYCLE_INPUT_ROW, CYCLE_OUTPUT_ROW, Poseidon2PermutationCols,
    trace::{
        RowIndex,
        chiplets::hasher::{CONTROLLER_ROWS_PER_PERMUTATION, HASH_CYCLE_LEN},
    },
};
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, LoopNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::{Program, StackOutputs},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

struct ForgedLoopTrace {
    repro: ReproTrace,
    core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    poseidon2: RowMajorMatrix<Felt>,
    outputs: StackOutputs,
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

fn set_controller_perm_id(matrix: &mut RowMajorMatrix<Felt>, row: usize, perm_id: Felt) {
    let width = matrix.width();
    // The hasher controller occupies the chiplet row payload after the top-level selector, and
    // `perm_id` is the final controller column immediately before `chip_clk`.
    matrix.values[row * width + width - 2] = perm_id;
}

fn poseidon2_row_mut(
    matrix: &mut RowMajorMatrix<Felt>,
    row: usize,
) -> &mut Poseidon2PermutationCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow_mut()
}

fn copy_basic_block_controller_rows(
    chiplets: &mut RowMajorMatrix<Felt>,
    attacker_chiplets: &RowMajorMatrix<Felt>,
    block_addr: Felt,
    perm_id: Felt,
) {
    let block_addr = block_addr.as_canonical_u64() as usize;
    assert!(block_addr > 0, "controller addresses are one-indexed");

    let controller_row = block_addr - 1;
    for row in controller_row..controller_row + CONTROLLER_ROWS_PER_PERMUTATION {
        copy_matrix_row(chiplets, row, attacker_chiplets, row);
        set_controller_perm_id(chiplets, row, perm_id);
    }
}

fn copy_poseidon2_cycle(
    poseidon2: &mut RowMajorMatrix<Felt>,
    dst_cycle: usize,
    src: &RowMajorMatrix<Felt>,
    src_cycle: usize,
    perm_id: Felt,
    multiplicity: Felt,
) {
    let dst_start = dst_cycle * HASH_CYCLE_LEN;
    let src_start = src_cycle * HASH_CYCLE_LEN;
    assert!(
        dst_start + HASH_CYCLE_LEN <= poseidon2.height(),
        "destination Poseidon2 cycle must fit in trace"
    );
    assert!(
        src_start + HASH_CYCLE_LEN <= src.height(),
        "source Poseidon2 cycle must fit in trace"
    );

    for (row, src_row) in
        (dst_start..dst_start + HASH_CYCLE_LEN).zip(src_start..src_start + HASH_CYCLE_LEN)
    {
        copy_matrix_row(poseidon2, row, src, src_row);
        poseidon2_row_mut(poseidon2, row).perm_id = perm_id;
    }

    poseidon2_row_mut(poseidon2, dst_start + CYCLE_INPUT_ROW).witnesses[0] = multiplicity;
    poseidon2_row_mut(poseidon2, dst_start + CYCLE_OUTPUT_ROW).witnesses[0] = multiplicity;
}

fn set_poseidon2_cycle_multiplicity(
    poseidon2: &mut RowMajorMatrix<Felt>,
    cycle: usize,
    multiplicity: Felt,
) {
    let start = cycle * HASH_CYCLE_LEN;
    poseidon2_row_mut(poseidon2, start + CYCLE_INPUT_ROW).witnesses[0] = multiplicity;
    poseidon2_row_mut(poseidon2, start + CYCLE_OUTPUT_ROW).witnesses[0] = multiplicity;
}

fn find_first_iteration_window(trace: &miden_processor::trace::VmTrace) -> (usize, usize, usize) {
    let main = trace.main_trace();
    let is =
        |row: usize, opcode: u8| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcode);

    let span = (1..main.core_height() - 5)
        .find(|&row| {
            is(row - 1, opcodes::LOOP)
                && is(row, opcodes::SPAN)
                && main.is_in_span(RowIndex::from(row + 1)) == Felt::ONE
                && main.is_in_span(RowIndex::from(row + 2)) == Felt::ONE
                && is(row + 3, opcodes::END)
                && is(row + 4, opcodes::REPEAT)
        })
        .expect("victim trace must start with LOOP | SPAN | op | op | END | REPEAT");

    let body_addr = main.addr(RowIndex::from(span + 1));
    assert_ne!(body_addr, Felt::ZERO, "body address must be nonzero");
    (span, span + 4, span + 1)
}

fn build_forged_early_iteration_trace() -> ForgedLoopTrace {
    let victim = build_loop_program(vec![Operation::Not, Operation::Not]);
    let victim_trace = execute(&victim, &[1, 1, 0]);

    // Same row count and stack effect as `NOT NOT`, but a different basic-block digest.
    let attacker = build_loop_program(vec![Operation::Noop, Operation::Noop]);
    let attacker_trace = execute(&attacker, &[1, 1, 0]);

    let (first_span, first_repeat, first_body_op) = find_first_iteration_window(&victim_trace);
    let (attacker_first_span, attacker_first_repeat, attacker_first_body_op) =
        find_first_iteration_window(&attacker_trace);

    let (mut core, mut chiplets, mut poseidon2) = victim_trace.main_trace().to_air_matrices();
    let (attacker_core, attacker_chiplets, attacker_poseidon2) =
        attacker_trace.main_trace().to_air_matrices();

    // Replace only the first iteration and its following REPEAT row:
    //
    //   committed: LOOP(B) | SPAN_B | NOT  | NOT  | END_B | REPEAT(B) | ...
    //   forged:    LOOP(B) | SPAN_X | NOOP | NOOP | END_X | REPEAT(X) | ...
    //
    // Before the schema fix, the later iterations stayed honest and the block-hash multiset
    // balanced as `{B, X, B} == {X, B, B}`. Under the fixed schema, only the original LOOP row
    // adds body entries, so the forged END_X has no matching add.
    for (dst, src) in (first_span..=first_repeat).zip(attacker_first_span..=attacker_first_repeat) {
        copy_matrix_row(&mut core, dst, &attacker_core, src);
    }

    let body_addr = core_row(&core, first_body_op).decoder.addr;
    let attacker_body_addr = core_row(&attacker_core, attacker_first_body_op).decoder.addr;
    assert_eq!(body_addr, attacker_body_addr, "fixture traces must align body addresses");
    let body_cycle = (body_addr.as_canonical_u64() as usize - 1) / CONTROLLER_ROWS_PER_PERMUTATION;
    let attacker_perm_id = Felt::new_unchecked(2);
    let attacker_cycle = attacker_perm_id.as_canonical_u64() as usize;
    copy_basic_block_controller_rows(
        &mut chiplets,
        &attacker_chiplets,
        body_addr,
        attacker_perm_id,
    );
    set_poseidon2_cycle_multiplicity(&mut poseidon2, body_cycle, Felt::new_unchecked(2));
    copy_poseidon2_cycle(
        &mut poseidon2,
        attacker_cycle,
        &attacker_poseidon2,
        body_cycle,
        attacker_perm_id,
        Felt::ONE,
    );

    for row in first_span..=first_repeat {
        core_row_mut(&mut core, row).system.clk = Felt::new_unchecked(row as u64);
    }

    ForgedLoopTrace {
        repro: ReproTrace::new(&victim_trace),
        core,
        chiplets,
        poseidon2,
        outputs: *victim_trace.stack_outputs(),
    }
}

#[test]
fn forged_early_loop_iteration_body_is_rejected() {
    let forged = build_forged_early_iteration_trace();

    let result = forged.repro.prove_and_verify_parts_allowing_lookup_rejection(
        forged.core,
        forged.chiplets,
        forged.poseidon2,
        forged.outputs,
    );
    assert!(
        result.is_err(),
        "the proof pipeline must reject a REPEAT whose body digest was not committed by LOOP: {result:?}"
    );
}

#[test]
fn forged_intermediate_repeat_parent_addr_is_rejected() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    let (first_span, first_repeat, _) = find_first_iteration_window(&trace);

    let second_span = first_repeat + 1;
    let second_repeat = second_span + (first_repeat - first_span);

    let main = trace.main_trace();
    assert_eq!(main.get_op_code(RowIndex::from(second_span)), Felt::from_u8(opcodes::SPAN));
    assert_eq!(main.get_op_code(RowIndex::from(second_repeat)), Felt::from_u8(opcodes::REPEAT));

    let (mut core, chiplets, poseidon2) = main.to_air_matrices();
    let forged_parent = Felt::new_unchecked(99);

    // The second iteration is followed by another REPEAT, so this mutates both endpoints of that
    // iteration's parent edge. Before REPEAT parent-address continuity and LOOP-side body
    // multiplicities, this shape could keep the local add/remove edges balanced. The proof
    // pipeline must reject it.
    core_row_mut(&mut core, second_span).decoder.addr = forged_parent;
    core_row_mut(&mut core, second_repeat).decoder.addr = forged_parent;

    let repro = ReproTrace::new(&trace);
    let result = repro.prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        poseidon2,
        *trace.stack_outputs(),
    );
    assert!(
        result.is_err(),
        "the proof pipeline must reject a REPEAT row whose successor changes parent address: {result:?}"
    );
}
