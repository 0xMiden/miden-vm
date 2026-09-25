//! Prover and verifier regressions for the LOOP body and REPEAT parent constraints.

use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;

use miden_air::{
    ChipletCols, MidenAir,
    logup::{BlockHashMsg, BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{Challenges, LookupMessage, build_lookup_fractions},
    trace::{
        MIN_TRACE_LEN, RowIndex,
        chiplets::hasher::{HASH_ABSORB, LINEAR_HASH, PADDING},
        eidos_compression::{NUM_EIDOS_COMPRESSION_COLS, retag_felt_trace_block_cycle_id},
    },
};
use miden_core::{
    Felt,
    field::QuadFelt,
    mast::{BasicBlockNodeBuilder, LoopNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::{Program, StackOutputs},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::BaseAir;
use miden_processor::{
    DefaultHost, FastProcessor, StackInputs,
    trace::{VmTrace, chiplets::build_external_eidos_compression_traces},
};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

fn build_loop_program(body_ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(body_ops).add_to_forest(&mut mast_forest).unwrap();
    let root = LoopNodeBuilder::new(body).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    Program::new(mast_forest.into(), root)
}

fn build_basic_program(ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(ops).add_to_forest(&mut mast_forest).unwrap();
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

fn core_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &miden_air::CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn chiplet_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &ChipletCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn copy_chiplet_row(
    dst: &mut RowMajorMatrix<Felt>,
    dst_row: usize,
    src: &RowMajorMatrix<Felt>,
    src_row: usize,
) {
    let width = dst.width();
    let row: &mut ChipletCols<Felt> =
        dst.values[dst_row * width..(dst_row + 1) * width].borrow_mut();
    let clock = row.chip_clk;
    *row = chiplet_row(src, src_row).clone();
    row.chip_clk = clock;
}

/// Rebuilds the compression witnesses for fixtures containing only linear hash requests.
fn compression_witness(
    chiplets: &RowMajorMatrix<Felt>,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
    let requests = (0..chiplets.height()).filter_map(|index| {
        let row = chiplet_row(chiplets, index);
        if row.chiplet_selectors()[0] == Felt::ZERO {
            return None;
        }
        let controller = row.controller();
        let selectors = [controller.s0, controller.s1, controller.s2];
        if selectors == PADDING {
            return None;
        }
        assert!(selectors == LINEAR_HASH || selectors == HASH_ABSORB);
        Some((controller.state, 1))
    });
    let (mut compression, mut and8) = build_external_eidos_compression_traces(requests);
    if compression.height() < MIN_TRACE_LEN {
        // The external builder permits one 32-row cycle; VM traces require at least 64 rows.
        let (mut padding, padding_counts) = build_external_eidos_compression_traces([]);
        retag_felt_trace_block_cycle_id(
            padding.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
            1,
        );
        compression.values.extend(padding.values);
        assert_eq!(compression.height(), MIN_TRACE_LEN);
        for (count, padding_count) in and8.values.iter_mut().zip(padding_counts.values) {
            *count += padding_count;
        }
    }
    (compression, and8)
}

/// Preserves non-hasher byte-table demand while replacing all controller compression requests.
fn rebuild_hash_witnesses(
    trace: &VmTrace,
    chiplets: &RowMajorMatrix<Felt>,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
    let (_, honest_chiplets, honest_compression, mut and8) =
        trace.main_trace().clone_air_matrices();
    let (rebuilt, old_counts) = compression_witness(&honest_chiplets);
    assert!(
        rebuilt.values == honest_compression.values,
        "honest compression witness must match"
    );
    let (compression, new_counts) = compression_witness(chiplets);
    for ((count, old), new) in and8.values.iter_mut().zip(old_counts.values).zip(new_counts.values)
    {
        assert!(count.as_canonical_u64() >= old.as_canonical_u64());
        *count = *count - old + new;
    }
    (compression, and8)
}

/// Compares lookup-message multiplicities at a fixed challenge point, including the hash and byte
/// tables. Public boundary messages stay unchanged in these fixtures.
fn assert_lookup_delta(
    trace: &VmTrace,
    forged: [&RowMajorMatrix<Felt>; 4],
    expected: &[(BlockHashMsg<Felt>, Felt)],
) {
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([Felt::from_u32(3), Felt::from_u32(5)]),
        QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let (core, chiplets, compression, and8) = trace.main_trace().clone_air_matrices();
    let mut delta = HashMap::new();
    for ((air, honest), forged) in [
        MidenAir::CORE,
        MidenAir::CHIPLETS,
        MidenAir::EIDOS_COMPRESSION,
        MidenAir::AND8_LOOKUP,
    ]
    .into_iter()
    .zip([&core, &chiplets, &compression, &and8])
    .zip(forged)
    {
        let preprocessed = air.preprocessed_trace();
        let periodic = BaseAir::<Felt>::periodic_columns(&air);
        for (matrix, sign) in [(honest, -Felt::ONE), (forged, Felt::ONE)] {
            let fractions =
                build_lookup_fractions(&air, matrix, preprocessed.as_ref(), &periodic, &challenges);
            for &(multiplicity, denominator) in fractions.fractions() {
                *delta.entry(denominator).or_insert(Felt::ZERO) += sign * multiplicity;
            }
        }
    }
    delta.retain(|_, multiplicity| *multiplicity != Felt::ZERO);
    let expected: HashMap<_, _> = expected
        .iter()
        .map(|(message, multiplicity)| (message.encode(&challenges), *multiplicity))
        .collect();
    assert_eq!(delta, expected, "forged witness must change only the expected lookup messages");
}

fn decode_opcode(op_bits: &[Felt; 7]) -> u8 {
    op_bits.iter().enumerate().fold(0u8, |opcode, (bit_idx, bit)| {
        opcode | ((bit.as_canonical_u64() as u8) << bit_idx)
    })
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
            local.decoder.op_bits
                == core::array::from_fn(|bit_idx| Felt::from_u8((opcodes::END >> bit_idx) & 1))
                && local.decoder.hasher_state[..4] == child_hash
                && local.decoder.hasher_state[4] == Felt::ONE
                && next.decoder.addr == parent
                && next_is_not_first_child
        })
        .count()
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
        .expect("fixture must contain LOOP | SPAN | op | op | END | REPEAT");
    (span, span + 4, span + 1)
}

#[test]
fn honest_repeated_loop_verifies() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    assert!(
        (0..trace.main_trace().core_height()).any(|row| {
            trace.main_trace().get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::REPEAT)
        }),
        "fixture must execute REPEAT"
    );
    assert!(ReproTrace::new(&trace).prove_and_verify_current().unwrap().is_complete());
}

#[test]
fn forged_early_loop_iteration_body_is_rejected() {
    let victim = execute(&build_loop_program(vec![Operation::Not, Operation::Not]), &[1, 1, 0]);
    let attacker = execute(&build_loop_program(vec![Operation::Noop, Operation::Noop]), &[1, 1, 0]);
    assert_eq!(victim.stack_outputs(), attacker.stack_outputs());
    let (span, repeat, body_op) = find_first_iteration_window(&victim);
    assert_eq!((span, repeat, body_op), find_first_iteration_window(&attacker));
    let (mut core, mut chiplets, ..) = victim.main_trace().clone_air_matrices();
    let (attacker_core, attacker_chiplets, ..) = attacker.main_trace().clone_air_matrices();
    let parent = core_row(&core, span).decoder.addr;
    let committed = core_row(&core, span - 1).decoder.hasher_state[..4].try_into().unwrap();
    let substituted =
        core_row(&attacker_core, span - 1).decoder.hasher_state[..4].try_into().unwrap();
    assert_ne!(committed, substituted);

    // Keep LOOP's commitment and later iterations intact; replace only the first body and REPEAT.
    for row in span..=repeat {
        *core_row_mut(&mut core, row) = core_row(&attacker_core, row).clone();
    }
    let controller_row = core_row(&core, body_op).decoder.addr.as_canonical_u64() as usize - 1;
    copy_chiplet_row(&mut chiplets, controller_row, &attacker_chiplets, controller_row);
    let (compression, and8) = rebuild_hash_witnesses(&victim, &chiplets);
    assert_lookup_delta(
        &victim,
        [&core, &chiplets, &compression, &and8],
        &[
            (BlockHashMsg::LoopBody { parent, child_hash: committed }, Felt::ONE),
            (BlockHashMsg::LoopBody { parent, child_hash: substituted }, -Felt::ONE),
        ],
    );
    let error = ReproTrace::new(&victim)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            *victim.stack_outputs(),
        )
        .expect_err("each iteration must execute the body committed by LOOP");
    assert!(error.starts_with("prover rejected an unbalanced lookup:"), "{error}");
}

#[test]
fn loop_skip_body_with_retired_hasher_rows_is_rejected() {
    let trace = execute(&build_loop_program(vec![Operation::Noop, Operation::Noop]), &[0]);
    let (mut core, mut chiplets, ..) = trace.main_trace().clone_air_matrices();
    let honest_core = core.clone();
    let honest_chiplets = chiplets.clone();
    let loop_end = (1..core.height())
        .find(|&row| {
            let row = core_row(&core, row);
            decode_opcode(&row.decoder.op_bits) == opcodes::END
                && row.decoder.hasher_state[5] == Felt::ONE
        })
        .unwrap();
    assert_eq!(decode_opcode(&core_row(&core, loop_end + 1).decoder.op_bits), opcodes::HALT);
    let body_controller = core_row(&core, 2).decoder.addr.as_canonical_u64() as usize - 1;
    for row in 1..=loop_end {
        let source = if row == 1 { loop_end } else { loop_end + 1 };
        *core_row_mut(&mut core, row) = core_row(&honest_core, source).clone();
        core_row_mut(&mut core, row).system.clk = Felt::from_u32(row as u32);
    }
    core_row_mut(&mut core, 0).decoder.group_count = Felt::ZERO;

    let padding = (0..chiplets.height())
        .find(|&row| {
            let row = chiplet_row(&chiplets, row);
            let controller = row.controller();
            row.chiplet_selectors()[0] == Felt::ONE
                && [controller.s0, controller.s1, controller.s2] == PADDING
        })
        .unwrap();
    copy_chiplet_row(&mut chiplets, body_controller, &honest_chiplets, padding);
    let (compression, and8) = rebuild_hash_witnesses(&trace, &chiplets);
    assert_lookup_delta(&trace, [&core, &chiplets, &compression, &and8], &[]);
    let error = ReproTrace::new(&trace)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            *trace.stack_outputs(),
        )
        .expect_err("LOOP must execute its body even when its lookup multiplicity is zero");
    assert!(error.starts_with("verifier rejected:"), "balanced lookup fixture: {error}");
}

#[test]
fn forged_in_span_repeat_with_body_hash_evidence_is_rejected() {
    // Hash evidence is valid; lookup construction rejects the unauthorized loop-body removal.
    // This exercises the block-hash relation without isolating the REPEAT predecessor constraint.
    let victim = execute(&build_basic_program(vec![Operation::Noop]), &[1, 1]);
    let body_program = build_loop_program(vec![Operation::Not]);
    let body = execute(&body_program, &[1]);
    let repeated = execute(&body_program, &[0, 1]);
    let (mut core, mut chiplets, ..) = victim.main_trace().clone_air_matrices();
    let (body_core, body_chiplets, ..) = body.main_trace().clone_air_matrices();
    let (repeat_core, ..) = repeated.main_trace().clone_air_matrices();
    let victim_end = core_row(&core, 2).clone();
    assert_eq!(decode_opcode(&victim_end.decoder.op_bits), opcodes::END);
    assert_eq!(decode_opcode(&core_row(&repeat_core, 4).decoder.op_bits), opcodes::REPEAT);

    // SPAN_A | NOOP | REPEAT | SPAN_X | NOT | END_X | END_A | HALT...
    *core_row_mut(&mut core, 2) = core_row(&repeat_core, 4).clone();
    for (dst, src) in [(3, 1), (4, 2), (5, 3)] {
        *core_row_mut(&mut core, dst) = core_row(&body_core, src).clone();
    }
    *core_row_mut(&mut core, 6) = victim_end;
    for row in 2..=6 {
        core_row_mut(&mut core, row).system.clk = Felt::from_u32(row as u32);
    }
    let final_stack = core_row(&core, 5).stack.clone();
    for row in 6..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let outputs = StackOutputs::from(final_stack.top);
    assert_ne!(outputs, *victim.stack_outputs());

    let controller_row = core_row(&core, 4).decoder.addr.as_canonical_u64() as usize - 1;
    copy_chiplet_row(&mut chiplets, controller_row, &body_chiplets, controller_row);
    let (compression, and8) = rebuild_hash_witnesses(&victim, &chiplets);
    assert_lookup_delta(
        &victim,
        [&core, &chiplets, &compression, &and8],
        &[(
            BlockHashMsg::LoopBody {
                parent: core_row(&core, 6).decoder.addr,
                child_hash: core_row(&core, 5).decoder.hasher_state[..4].try_into().unwrap(),
            },
            -Felt::ONE,
        )],
    );
    let error = ReproTrace::new(&victim)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            outputs,
        )
        .expect_err("an injected REPEAT cannot authorize an uncommitted body");
    assert!(error.starts_with("prover rejected an unbalanced lookup:"), "{error}");
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
    let (mut core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
    let honest_body_count = count_loop_body_end_removals(&core, loop_parent, loop_body_hash);
    assert_eq!(
        core_row(&core, loop_row).decoder.group_count,
        Felt::new_unchecked(honest_body_count as u64),
        "fixture LOOP multiplicity must match the body END count"
    );

    core_row_mut(&mut core, body_end_row).decoder.hasher_state[4] = Felt::ZERO;
    core_row_mut(&mut core, non_body_end_row).decoder.hasher_state[4] = Felt::ONE;

    let result = ReproTrace::new(&trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        *trace.stack_outputs(),
    );
    let error = result.expect_err("reassigning is_loop_body between END rows must be rejected");
    assert!(
        error.starts_with("prover rejected an unbalanced lookup:"),
        "the forged END flags must fail at lookup construction: {error}"
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

    let (mut core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
    let forged_parent = Felt::new_unchecked(99);
    core_row_mut(&mut core, second_span).decoder.addr = forged_parent;
    core_row_mut(&mut core, second_repeat).decoder.addr = forged_parent;

    let result = ReproTrace::new(&trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        *trace.stack_outputs(),
    );
    assert!(result.is_err(), "REPEAT must preserve its parent address: {result:?}");
}

#[test]
fn direct_repeat_without_body_hash_evidence_is_rejected() {
    let victim = build_basic_program(vec![Operation::Noop]);
    let victim_trace = execute(&victim, &[1, 1]);
    let loop_program = build_loop_program(vec![Operation::Not]);
    let loop_trace = execute(&loop_program, &[0, 1]);
    let (mut core, chiplets, eidos_compression, and8) =
        victim_trace.main_trace().clone_air_matrices();
    let (repeat_core, ..) = loop_trace.main_trace().clone_air_matrices();
    assert_eq!(decode_opcode(&core_row(&repeat_core, 4).decoder.op_bits), opcodes::REPEAT);

    let repeat = core_row(&repeat_core, 4).clone();
    *core_row_mut(&mut core, 2) = repeat;
    core_row_mut(&mut core, 2).system.clk = Felt::from_u32(2);
    let final_stack = core_row(&core, 2).stack.clone();
    for row in 3..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let forged_outputs = StackOutputs::from(final_stack.top);

    let result = ReproTrace::new(&victim_trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        forged_outputs,
    );
    assert!(
        result.is_err(),
        "REPEAT without body hash evidence must be rejected: {result:?}"
    );
}
