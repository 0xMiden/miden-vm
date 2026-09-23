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

fn count_loop_body_end_removals(
    core: &RowMajorMatrix<Felt>,
    parent: Felt,
    child_hash: [Felt; 4],
) -> usize {
    (0..core.height() - 1)
        .filter(|&row| {
            let local = core_row(core, row);
            let next = core_row(core, row + 1);
            let next_is_not_first_child =
                [opcodes::END, opcodes::REPEAT, opcodes::RESPAN, opcodes::HALT]
                    .contains(&decode_opcode(&next.decoder.op_bits));
            local.decoder.op_bits == opcode_bits(opcodes::END)
                && local.decoder.hasher_state[..4] == child_hash
                && local.decoder.hasher_state[4] == Felt::ONE
                && next.decoder.addr == parent
                && next_is_not_first_child
        })
        .count()
}

fn decode_opcode(op_bits: &[Felt; 7]) -> u8 {
    op_bits.iter().enumerate().fold(0u8, |opcode, (bit_idx, bit)| {
        opcode | ((bit.as_canonical_u64() as u8) << bit_idx)
    })
}

fn opcode_bits(opcode: u8) -> [Felt; 7] {
    core::array::from_fn(|bit_idx| Felt::from_u8((opcode >> bit_idx) & 1))
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

fn set_chip_clk(chiplets: &mut RowMajorMatrix<Felt>, row: usize) {
    let width = chiplets.width();
    chiplets.values[row * width + width - 1] = Felt::new_unchecked(row as u64 + 1);
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
fn honest_repeated_loop_verifies() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    let main = trace.main_trace();
    assert!(
        (0..main.core_height())
            .any(|row| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::REPEAT)),
        "fixture must execute REPEAT"
    );

    let outcome = ReproTrace::new(&trace)
        .prove_and_verify_current()
        .expect("honest loop must verify");
    assert!(outcome.is_complete(), "honest loop proof must verify completely");
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
fn loop_skip_body_with_retired_hasher_rows_is_rejected() {
    let program = build_loop_program(vec![Operation::Noop, Operation::Noop]);
    let trace = execute(&program, &[0]);
    let main = trace.main_trace();

    // Honest fixture:
    //   LOOP(gc=1) | SPAN | NOOP | NOOP | END_body | END_loop | HALT...
    //
    // Forged:
    //   LOOP(gc=0) | END_loop | HALT | HALT | HALT | HALT | HALT...
    //
    // This skips the committed do-while body. Retiring the body's two hasher-controller rows
    // avoids the incidental lookup imbalance from the earlier dead-end probe, so the current
    // tree must reject this specifically through the new LOOP -> END decoder constraint.
    let loop_row = 0usize;
    let body_op_row = 2usize;
    let loop_end_row = 5usize;
    let first_halt_row = 6usize;
    assert_eq!(main.get_op_code(RowIndex::from(loop_row)), Felt::from_u8(opcodes::LOOP));
    assert_eq!(main.get_op_code(RowIndex::from(loop_row + 1)), Felt::from_u8(opcodes::SPAN));
    assert_eq!(main.get_op_code(RowIndex::from(loop_end_row)), Felt::from_u8(opcodes::END));
    assert_eq!(main.get_op_code(RowIndex::from(first_halt_row)), Felt::from_u8(opcodes::HALT));

    let body_addr = main.addr(RowIndex::from(body_op_row)).as_canonical_u64() as usize;
    assert!(body_addr > 0, "body hash controller address is one-indexed");
    let body_controller_row = body_addr - 1;
    let body_cycle = body_controller_row / CONTROLLER_ROWS_PER_PERMUTATION;
    let controller_padding_row = body_controller_row + CONTROLLER_ROWS_PER_PERMUTATION;

    let (mut core, mut chiplets, mut poseidon2) = main.to_air_matrices();
    let honest_core = core.clone();
    let honest_chiplets = chiplets.clone();

    // Pull the loop's own END up to directly follow LOOP, then pad over the old body rows.
    copy_matrix_row(&mut core, loop_row + 1, &honest_core, loop_end_row);
    for row in (loop_row + 2)..=loop_end_row {
        copy_matrix_row(&mut core, row, &honest_core, first_halt_row);
    }
    for row in (loop_row + 1)..=loop_end_row {
        core_row_mut(&mut core, row).system.clk = Felt::new_unchecked(row as u64);
    }

    // With multiplicity zero, the LOOP row emits no loop-body block-hash entry.
    core_row_mut(&mut core, loop_row).decoder.group_count = Felt::ZERO;

    // Remove the now-unrequested body hash response by replacing its controller input/output pair
    // with existing controller-padding rows, preserving the positional chiplet clock.
    for offset in 0..CONTROLLER_ROWS_PER_PERMUTATION {
        let dst = body_controller_row + offset;
        copy_matrix_row(&mut chiplets, dst, &honest_chiplets, controller_padding_row + offset);
        set_chip_clk(&mut chiplets, dst);
    }
    set_poseidon2_cycle_multiplicity(&mut poseidon2, body_cycle, Felt::ZERO);

    let repro = ReproTrace::new(&trace);
    let result = repro.prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        poseidon2,
        *trace.stack_outputs(),
    );
    let error = result.expect_err("D15 must reject a LOOP row that jumps directly to END");
    assert!(
        error.starts_with("verifier rejected:"),
        "the completed skip-body witness should produce a proof and fail verification, not fail \
         lookup construction or another prover precheck: {error}"
    );
}

#[test]
fn loop_body_end_flag_cannot_be_reassigned_to_another_end() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    let main = trace.main_trace();

    let (first_span, first_repeat, first_body_op) = find_first_iteration_window(&trace);
    let loop_row = first_span - 1;
    assert_eq!(main.get_op_code(RowIndex::from(loop_row)), Felt::from_u8(opcodes::LOOP));
    assert_eq!(main.get_op_code(RowIndex::from(first_body_op)), Felt::from_u8(opcodes::NOT));
    let body_end_row = first_repeat - 1;
    assert_eq!(main.get_op_code(RowIndex::from(body_end_row)), Felt::from_u8(opcodes::END));
    assert_eq!(main.is_loop_body_flag(RowIndex::from(body_end_row)), Felt::ONE);

    let non_body_end_row = ((first_repeat + 1)..main.core_height())
        .find(|&row| {
            main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::END)
                && main.is_loop_body_flag(RowIndex::from(row)) == Felt::ZERO
        })
        .expect("fixture must end the root LOOP after ending its bodies");

    let loop_parent = main.addr(RowIndex::from(first_span));
    let hasher_state = main.decoder_hasher_state(RowIndex::from(loop_row));
    let loop_body_hash = [hasher_state[0], hasher_state[1], hasher_state[2], hasher_state[3]];

    let (mut core, chiplets, poseidon2) = main.to_air_matrices();
    let honest_body_count = count_loop_body_end_removals(&core, loop_parent, loop_body_hash);
    assert_eq!(
        core_row(&core, loop_row).decoder.group_count,
        Felt::new_unchecked(honest_body_count as u64),
        "fixture sanity: honest LOOP multiplicity must match same-key body END count"
    );

    // `is_loop_body` is not directly copied out of the block-stack message. Its 0/1 value is
    // nevertheless authenticated by the full block-hash key: child digest + dynamic parent +
    // entry kind. Moving the flag from a real loop-body END to a different END preserves the
    // global number of zero/one flags, but changes two lookup keys and must be rejected.
    core_row_mut(&mut core, body_end_row).decoder.hasher_state[4] = Felt::ZERO;
    core_row_mut(&mut core, non_body_end_row).decoder.hasher_state[4] = Felt::ONE;

    let repro = ReproTrace::new(&trace);
    let result = repro.prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        poseidon2,
        *trace.stack_outputs(),
    );
    let error = result.expect_err("reassigning is_loop_body between END rows must be rejected");
    assert!(
        error.starts_with("prover rejected an unbalanced lookup:"),
        "the forged END flags must fail at lookup construction, not for an incidental reason: {error}"
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
