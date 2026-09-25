//! Decoder virtual-table bus tests.
//!
//! Covers the block-stack table (merged with the u32 and Merkle-depth range checks and the
//! log-deferred capacity bus) and the block-hash + op-group table column.
//!
//! Under the LogUp framework the interactions look like "+1 / encode(Msg)" on push rows
//! and "-1 / encode(Msg)" on pop rows. Each test runs a tiny program that exercises one
//! push/pop pair (or a small batch) and checks both halves land via the subset matcher.
//!
//! Coverage is targeted rather than exhaustive: the tests below hit the control-flow variants
//! prone to off-by-one or selector-muxing bugs (JOIN, LOOP+REPEAT, CALL, SPAN/RESPAN op-group
//! batching). Broader end-to-end soundness comes from
//! `build_lookup_fractions_runs_on_execution_trace` in `tests/lookup.rs`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::borrow::BorrowMut;

use miden_air::{
    CoreCols,
    logup::{BlockHashMsg, BlockStackMsg, OpGroupMsg, StackOverflowMsg},
    trace::decoder::{OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS},
};
use miden_core::{
    Felt, ONE, ZERO,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest,
        MastNodeExt, SplitNodeBuilder,
    },
    operations::{Operation, opcodes},
    program::{KernelDescriptor, Program},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    VmTrace, build_trace_from_ops, build_trace_from_program, build_trace_from_program_with_stack,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::{RowIndex, StackInputs, trace::MainTrace};

// HELPERS
// ================================================================================================

/// Mirrors the `is_first_child = 1 - end_next - repeat_next - respan_next - halt_next`
/// arithmetic from the END-overlay constraint. Since END/REPEAT/RESPAN/HALT are distinct
/// 7-bit opcodes, at most one term is non-zero per row, so the arithmetic form collapses to
/// the trace-level OR — but we encode it arithmetically to mirror the constraint expression.
fn next_op_first_child_flag(main: &MainTrace, next: RowIndex) -> Felt {
    let op_next = main.get_op_code(next);
    let is = |code: u8| if op_next == Felt::from_u8(code) { ONE } else { ZERO };
    ONE - is(opcodes::END) - is(opcodes::REPEAT) - is(opcodes::RESPAN) - is(opcodes::HALT)
}

/// Calls `f(row, opcode)` for every row except the last.
///
/// Most decoder tests need `row + 1` lookups (next-row flags, addr_next, etc.) so stopping one
/// short of the end avoids per-test bounds checks.
fn for_each_op<F>(trace: &VmTrace, mut f: F)
where
    F: FnMut(usize, Felt),
{
    let main = trace.main_trace();
    let core_h = main.core_height();
    for row in 0..core_h - 1 {
        let idx = RowIndex::from(row);
        f(row, main.get_op_code(idx));
    }
}

fn batch_row(trace: &VmTrace, expected_encoding: [Felt; 2]) -> usize {
    let main = trace.main_trace();
    (0..main.core_height())
        .find(|&row| {
            let row = RowIndex::from(row);
            let op = main.get_op_code(row);
            (op == Felt::from_u8(opcodes::SPAN) || op == Felt::from_u8(opcodes::RESPAN))
                && main.op_batch_encoding(row) == expected_encoding
        })
        .unwrap_or_else(|| panic!("trace does not contain batch encoding {expected_encoding:?}"))
}

fn non_batch_row(trace: &VmTrace) -> usize {
    let main = trace.main_trace();
    (0..main.core_height())
        .find(|&row| {
            let op = main.get_op_code(RowIndex::from(row));
            op != Felt::from_u8(opcodes::SPAN) && op != Felt::from_u8(opcodes::RESPAN)
        })
        .expect("trace must contain a non-SPAN/RESPAN row")
}

fn core_row_mut(core_matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut CoreCols<Felt> {
    let width = core_matrix.width();
    let start = row * width;
    core_matrix.values[start..start + width].borrow_mut()
}

fn assert_core_mutation_rejected(
    trace: &VmTrace,
    row: usize,
    mutate: impl FnOnce(&mut CoreCols<Felt>),
) {
    let (mut core_matrix, chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();
    mutate(core_row_mut(&mut core_matrix, row));
    super::lookup::assert_trace_constraints_reject(
        trace,
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        and8_matrix,
    );
}

// BLOCK STACK TABLE (M1) TESTS
// ================================================================================================

/// A lone SPAN pushes one continuation entry and the matching END pops it.
#[test]
fn block_stack_span_push_pop() {
    let ops = vec![Operation::Add, Operation::Mul];
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let addr = main.addr(idx);
        let addr_next = main.addr(RowIndex::from(row + 1));

        if op == Felt::from_u8(opcodes::SPAN) {
            exp.add(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop: ZERO,
                },
            );
        } else if op == Felt::from_u8(opcodes::END) {
            exp.remove(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop: ZERO,
                },
            );
        }
    });

    assert_eq!(exp.count_adds(), 1, "expected exactly one SPAN push");
    assert_eq!(exp.count_removes(), 1, "expected exactly one matching END pop");
    log.assert_contains(&exp);
}

/// CALL pushes a `CallerFrame` entry saving the caller context, stack depth, overflow pointer,
/// and function hash. Its matching END pops that entry using the restored state from the next row.
#[test]
fn block_stack_call_frame_push_pop() {
    let program = {
        let mut forest = MastForest::new();
        let callee = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();
        let call_id = CallNodeBuilder::new(callee).add_to_forest(&mut forest).unwrap();
        forest.make_root(call_id);
        Program::new(forest.into(), call_id)
    };
    let trace = build_trace_from_program(&program, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);

        if op == Felt::from_u8(opcodes::CALL) {
            exp.add(
                row,
                &BlockStackMsg::CallerFrame {
                    block_id: main.addr(next),
                    parent_id: main.addr(idx),
                    caller_ctx: main.ctx(idx),
                    caller_stack_depth: main.stack_depth(idx),
                    caller_overflow_addr: main.parent_overflow_address(idx),
                    caller_fn_hash: main.fn_hash(idx),
                },
            );
        }

        // Caller-frame END: caller state is restored on the *next* row, so the emitter reads it
        // from row+1.
        if op == Felt::from_u8(opcodes::END) && main.restores_caller_frame_flag(idx) == ONE {
            exp.remove(
                row,
                &BlockStackMsg::CallerFrame {
                    block_id: main.addr(idx),
                    parent_id: main.addr(next),
                    caller_ctx: main.ctx(next),
                    caller_stack_depth: main.stack_depth(next),
                    caller_overflow_addr: main.parent_overflow_address(next),
                    caller_fn_hash: main.fn_hash(next),
                },
            );
        }
    });

    assert_eq!(exp.count_adds(), 1, "expected exactly one CALL push");
    assert_eq!(exp.count_removes(), 1, "expected exactly one matching END pop");
    log.assert_contains(&exp);
}

/// SPLIT pushes a `Continuation { is_loop: 0 }` entry (parent = current block,
/// block = addr_next) and
/// the matching END pops it. Runs twice — once with `s0 = 1` (TRUE branch), once with `s0 = 0`
/// (FALSE branch) — since the block-stack emission is identical either way but the END reached
/// for the matching pop differs between branches.
#[rstest::rstest]
#[case::taken(1)]
#[case::not_taken(0)]
fn block_stack_split_push_pop(#[case] cond: u64) {
    let program = {
        let mut f = MastForest::new();
        let t = BasicBlockNodeBuilder::new(vec![Operation::Add]).add_to_forest(&mut f).unwrap();
        let e = BasicBlockNodeBuilder::new(vec![Operation::Mul]).add_to_forest(&mut f).unwrap();
        let s = SplitNodeBuilder::new([t, e]).add_to_forest(&mut f).unwrap();
        f.make_root(s);
        Program::new(f.into(), s)
    };
    let trace = build_trace_from_program(&program, &[cond]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut split_adds = 0usize;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let addr = main.addr(idx);
        let addr_next = main.addr(RowIndex::from(row + 1));

        if op == Felt::from_u8(opcodes::SPLIT) {
            exp.add(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop: ZERO,
                },
            );
            split_adds += 1;
        } else if op == Felt::from_u8(opcodes::END) && main.restores_caller_frame_flag(idx) == ZERO
        {
            // is_loop on the END overlay comes from the typed END flags; for non-loop ENDs it
            // is zero. We can read it back from the trace to stay agnostic about which END row
            // matches which push.
            let is_loop = main.is_loop_flag(idx);
            exp.remove(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop,
                },
            );
        }
    });

    assert_eq!(split_adds, 1, "expected exactly one SPLIT push");
    // One END for the taken inner branch, one for the SPLIT itself (parent). Both pop
    // Continuation entries.
    assert_eq!(exp.count_removes(), 2, "expected two Continuation pops (child END + SPLIT END)");
    log.assert_contains(&exp);
}

/// LOOP pushes a `Continuation { is_loop: 1 }` entry and the matching END pops it. With do-while
/// semantics the body always runs at least once, so a raw LoopNode never produces an
/// `is_loop = 0` push. The skip-without-entering path lives in the wrapping SPLIT inserted by
/// the assembler for `while.true` and is covered by the Split-node tests.
#[test]
fn block_stack_loop_uses_loop_continuation() {
    let program = {
        let mut f = MastForest::new();
        let body = BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
            .add_to_forest(&mut f)
            .unwrap();
        let loop_id = LoopNodeBuilder::new(body).add_to_forest(&mut f).unwrap();
        f.make_root(loop_id);
        Program::new(f.into(), loop_id)
    };
    // Stack is top-first: 1 requests one repeat, then 0 exits the loop.
    let trace = build_trace_from_program(&program, &[1, 0]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut loop_pushes = 0usize;
    let mut loop_pops = 0usize;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let addr = main.addr(idx);
        let addr_next = main.addr(RowIndex::from(row + 1));

        if op == Felt::from_u8(opcodes::LOOP) {
            exp.add(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop: ONE,
                },
            );
            loop_pushes += 1;
        } else if op == Felt::from_u8(opcodes::END)
            && main.restores_caller_frame_flag(idx) == ZERO
            && main.is_loop_flag(idx) == ONE
            && main.is_loop_body_flag(idx) == ZERO
        {
            exp.remove(
                row,
                &BlockStackMsg::Continuation {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop: ONE,
                },
            );
            loop_pops += 1;
        }
    });

    assert_eq!(loop_pushes, 1, "expected one LOOP push");
    assert_eq!(loop_pops, 1, "expected one matching LOOP END pop");
    log.assert_contains(&exp);
}

/// Regression: when a `LoopNode` is wrapped in a `SplitNode` (the shape the assembler emits
/// for `while.true`), the LOOP row's `s_0` is whatever sat below the entry condition that the
/// SPLIT consumed — not necessarily 1. The block-stack push for LOOP must therefore use the
/// constant `is_loop = 1` (matching `h_5 = 1` at the loop END under do-while semantics),
/// otherwise the bus push and the matching pop encode different values and the block-stack
/// bus does not balance.
///
/// Layout `Split { Loop { Pad Drop }, Noop }` driven by stack `[1, 0]`: the SPLIT pops the
/// entry condition `1` and the LOOP enters the body with `s_0 = 0`. If the push erroneously
/// reads `s_0`, this test fails because the expected `is_loop = 1` push is absent from the log.
#[test]
fn block_stack_split_wrapped_loop_uses_constant_is_loop() {
    let program = {
        let mut f = MastForest::new();
        let body = BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
            .add_to_forest(&mut f)
            .unwrap();
        let loop_id = LoopNodeBuilder::new(body).add_to_forest(&mut f).unwrap();
        let noop = BasicBlockNodeBuilder::new(vec![Operation::Noop]).add_to_forest(&mut f).unwrap();
        let split_id = SplitNodeBuilder::new([loop_id, noop]).add_to_forest(&mut f).unwrap();
        f.make_root(split_id);
        Program::new(f.into(), split_id)
    };
    // Stack top-first: `1` drives SPLIT (enter true branch → LOOP), `0` is the value the LOOP
    // sees on `s_0` after the SPLIT-pop. Pad+Drop is net-zero, so the trailing condition at
    // REPEAT/END is also `0` and the loop exits cleanly after one iteration.
    let trace = build_trace_from_program(&program, &[1, 0]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut loop_push_row: Option<usize> = None;
    let mut loop_end_row: Option<usize> = None;
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        if op == Felt::from_u8(opcodes::LOOP) {
            assert_eq!(
                main.stack_element(0, idx),
                ZERO,
                "test setup: expected s_0 = 0 at LOOP row to expose the bug",
            );
            loop_push_row = Some(row);
        } else if op == Felt::from_u8(opcodes::END)
            && main.is_loop_flag(idx) == ONE
            && main.is_loop_body_flag(idx) == ZERO
        {
            loop_end_row = Some(row);
        }
    });

    let push_row = loop_push_row.expect("expected one LOOP row in the trace");
    let pop_row = loop_end_row.expect("expected one loop-closing END row in the trace");

    let push_idx = RowIndex::from(push_row);
    let pop_idx = RowIndex::from(pop_row);
    let push_block_id = main.addr(RowIndex::from(push_row + 1));
    let push_parent_id = main.addr(push_idx);
    let pop_block_id = main.addr(pop_idx);
    let pop_parent_id = main.addr(RowIndex::from(pop_row + 1));

    let mut exp = Expectations::new(&log);
    // Correct push: `is_loop` is a constant `1`, regardless of `s_0`.
    exp.add(
        push_row,
        &BlockStackMsg::Continuation {
            block_id: push_block_id,
            parent_id: push_parent_id,
            is_loop: ONE,
        },
    );
    // Matching pop: `is_loop = h_5 = 1` at every loop END under do-while.
    exp.remove(
        pop_row,
        &BlockStackMsg::Continuation {
            block_id: pop_block_id,
            parent_id: pop_parent_id,
            is_loop: ONE,
        },
    );
    log.assert_contains(&exp);
}

/// RESPAN fires a simultaneous push + pop on the block-stack bus (batch addition is recorded
/// as an Add, and the prior batch's entry is simultaneously Removed). Uses a SPAN long enough
/// to require two batches so at least one RESPAN row exists.
#[test]
fn block_stack_respan_add_and_remove() {
    // 80 Noops require two batches (each batch holds up to 72 ops), so the SPAN decomposes
    // into SPAN + 64 ops + RESPAN + remaining ops + END.
    let ops: Vec<Operation> = (0..80).map(|_| Operation::Noop).collect();
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut respan_rows = 0usize;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        if op != Felt::from_u8(opcodes::RESPAN) {
            return;
        }
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let addr = main.addr(idx);
        let addr_next = main.addr(next);
        // The RESPAN emitter uses `h1_next` as the parent link for both the add and remove.
        let parent = main.decoder_hasher_state_element(1, next);

        exp.add(
            row,
            &BlockStackMsg::Continuation {
                block_id: addr_next,
                parent_id: parent,
                is_loop: ZERO,
            },
        );
        exp.remove(
            row,
            &BlockStackMsg::Continuation {
                block_id: addr,
                parent_id: parent,
                is_loop: ZERO,
            },
        );
        respan_rows += 1;
    });

    assert!(respan_rows >= 1, "program did not produce a RESPAN row");
    assert_eq!(exp.count_adds(), respan_rows);
    assert_eq!(exp.count_removes(), respan_rows);
    log.assert_contains(&exp);
}

// BLOCK HASH / OP-GROUP COLUMN TESTS
// ================================================================================================

/// A JOIN enqueues two children (first + subsequent) and the two child ENDs dequeue them.
#[test]
fn block_hash_join_enqueue_dequeue() {
    let program = {
        let mut mast_forest = MastForest::new();
        let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let join_id = JoinNodeBuilder::new([bb1, bb2]).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(join_id);
        Program::new(mast_forest.into(), join_id)
    };
    let trace = build_trace_from_program(&program, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let addr_next = main.addr(next);
        let first = main.decoder_hasher_state_first_half(idx);
        let h0: [Felt; 4] = [first[0], first[1], first[2], first[3]];
        let second = main.decoder_hasher_state_second_half(idx);
        let h1: [Felt; 4] = [second[0], second[1], second[2], second[3]];

        if op == Felt::from_u8(opcodes::JOIN) {
            exp.add(row, &BlockHashMsg::FirstChild { parent: addr_next, child_hash: h0 });
            exp.add(row, &BlockHashMsg::Child { parent: addr_next, child_hash: h1 });
        }

        if op == Felt::from_u8(opcodes::END) {
            let is_first_child = next_op_first_child_flag(main, next);
            let is_loop_body = main.is_loop_body_flag(idx);
            exp.remove(
                row,
                &BlockHashMsg::End {
                    parent: addr_next,
                    child_hash: h0,
                    is_first_child,
                    is_loop_body,
                },
            );
        }
    });

    // JOIN enqueues 2 children; ENDs fire for bb1, bb2, and the JOIN itself (3 total).
    assert_eq!(exp.count_adds(), 2, "expected JOIN to enqueue FirstChild + Child");
    assert_eq!(exp.count_removes(), 3, "expected an END dequeue for bb1, bb2, and JOIN");
    log.assert_contains(&exp);
}

/// LOOP enqueues one weighted `LoopBody` entry for all executions of the body, and the END at the
/// end of each body dequeues it with `is_loop_body = 1`. Runs two iterations (inputs `[1, 0]`) so
/// the LOOP entry has multiplicity 2 and the REPEAT branch fires without adding a body entry.
#[test]
fn block_hash_loop_body_with_repeat() {
    let program = {
        let mut mast_forest = MastForest::new();
        let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Pad])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Drop])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let join_id = JoinNodeBuilder::new([bb1, bb2]).add_to_forest(&mut mast_forest).unwrap();
        let loop_id = LoopNodeBuilder::new(join_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_id);
        Program::new(mast_forest.into(), loop_id)
    };

    // Pad+Drop is a net-zero body, so the trailing condition at REPEAT/END is whatever the
    // stack already had: input `[1, 0]` drives two iterations (first the do-while-entered body
    // sees a `1` on top → REPEAT, then `0` on top → END).
    let trace = build_trace_from_program(&program, &[1, 0]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut fired_loop_body_enqueue = 0usize;
    let mut fired_loop_body_end = 0usize;
    let mut repeat_rows = 0usize;

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let first = main.decoder_hasher_state_first_half(idx);
        let h0: [Felt; 4] = [first[0], first[1], first[2], first[3]];
        let addr_next = main.addr(next);

        // Under do-while the LOOP unconditionally enqueues the committed body digest. REPEAT
        // re-enters the loop but does not add a block-hash entry from its own row.
        if op == Felt::from_u8(opcodes::LOOP) {
            let multiplicity = main.group_count(idx);
            assert_eq!(
                multiplicity,
                Felt::new_unchecked(2),
                "the LOOP row must carry one body entry per iteration"
            );
            exp.push(
                row,
                multiplicity,
                &BlockHashMsg::LoopBody { parent: addr_next, child_hash: h0 },
            );
            fired_loop_body_enqueue += 1;
        } else if op == Felt::from_u8(opcodes::REPEAT) {
            assert_eq!(
                main.group_count(idx),
                ZERO,
                "REPEAT rows must not carry the LOOP-side body multiplicity"
            );
            repeat_rows += 1;
        }

        // END of the loop body: `is_loop_body` bit is set on the END overlay.
        if op == Felt::from_u8(opcodes::END) && main.is_loop_body_flag(idx) == ONE {
            let is_first_child = next_op_first_child_flag(main, next);
            exp.remove(
                row,
                &BlockHashMsg::End {
                    parent: addr_next,
                    child_hash: h0,
                    is_first_child,
                    is_loop_body: ONE,
                },
            );
            fired_loop_body_end += 1;
        }
    });

    // Sanity: one weighted LOOP enqueue covers both iterations; REPEAT itself fires no enqueue.
    assert_eq!(fired_loop_body_enqueue, 1, "expected one weighted LOOP body enqueue");
    assert_eq!(repeat_rows, 1, "fixture must execute one REPEAT row");
    assert_eq!(fired_loop_body_end, 2, "expected one END-of-loop-body remove per iteration");

    log.assert_contains(&exp);
}

/// Nested loops exercise the keying of LOOP-side body multiplicities by dynamic loop
/// address. This fixture produces three dynamic LOOP rows with body-execution counts `[2, 2, 3]`.
/// The same static inner loop node appears multiple times, but each dynamic instance has a
/// distinct controller address and therefore its own multiplicity.
#[test]
fn block_hash_nested_loop_body_multiplicities_are_keyed_by_dynamic_address() {
    let program = {
        let mut mast_forest = MastForest::new();
        let body = BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let inner_loop = LoopNodeBuilder::new(body).add_to_forest(&mut mast_forest).unwrap();
        let outer_loop = LoopNodeBuilder::new(inner_loop).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(outer_loop);
        Program::new(mast_forest.into(), outer_loop)
    };

    // Stack inputs mirror the nested-loop fragmentation fixture. The exact fixture shape is pinned
    // below; the important invariant is that every LOOP multiplicity is keyed by the dynamic
    // controller address reached from that LOOP row.
    let trace = build_trace_from_program(&program, &[1, 1, 0, 1, 1, 0, 0, 9999]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut body_end_counts = BTreeMap::<u64, u64>::new();
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        if op == Felt::from_u8(opcodes::END) && main.is_loop_body_flag(idx) == ONE {
            let loop_addr = main.addr(RowIndex::from(row + 1)).as_canonical_u64();
            *body_end_counts.entry(loop_addr).or_insert(0) += 1;
        }
    });

    let mut exp = Expectations::new(&log);
    let mut loop_multiplicities = Vec::new();
    let mut body_end_rows = 0usize;
    let mut repeat_rows = 0usize;

    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let first = main.decoder_hasher_state_first_half(idx);
        let h0: [Felt; 4] = [first[0], first[1], first[2], first[3]];
        let addr_next = main.addr(next);

        if op == Felt::from_u8(opcodes::LOOP) {
            let expected_count = body_end_counts
                .get(&addr_next.as_canonical_u64())
                .copied()
                .expect("every dynamic LOOP must have at least one body END");
            let multiplicity = main.group_count(idx);
            assert_eq!(
                multiplicity,
                Felt::new_unchecked(expected_count),
                "row {row}: honest LOOP.group_count must equal body END count at its dynamic address"
            );

            loop_multiplicities.push(expected_count);
            exp.push(
                row,
                multiplicity,
                &BlockHashMsg::LoopBody { parent: addr_next, child_hash: h0 },
            );
        } else if op == Felt::from_u8(opcodes::REPEAT) {
            assert_eq!(
                main.group_count(idx),
                ZERO,
                "row {row}: REPEAT rows must not carry the LOOP-side body multiplicity"
            );
            repeat_rows += 1;
        }

        if op == Felt::from_u8(opcodes::END) && main.is_loop_body_flag(idx) == ONE {
            let is_first_child = next_op_first_child_flag(main, next);
            exp.remove(
                row,
                &BlockHashMsg::End {
                    parent: addr_next,
                    child_hash: h0,
                    is_first_child,
                    is_loop_body: ONE,
                },
            );
            body_end_rows += 1;
        }
    });

    loop_multiplicities.sort_unstable();
    assert_eq!(
        loop_multiplicities,
        vec![2, 2, 3],
        "expected the nested fixture's dynamic loop body counts"
    );
    assert_eq!(repeat_rows, 4, "fixture must execute four REPEAT rows");
    assert_eq!(body_end_rows, 7, "fixture must produce seven loop-body END rows");

    log.assert_contains(&exp);
}

/// SPLIT enqueues exactly one `Child` entry carrying the `s0`-muxed child hash
/// (`s0 * h_0 + (1 - s0) * h_1`); the matching END on the taken branch dequeues it.
#[rstest::rstest]
#[case::taken(1)]
#[case::not_taken(0)]
fn block_hash_split_enqueue_dequeue(#[case] cond: u64) {
    let program = {
        let mut f = MastForest::new();
        let t = BasicBlockNodeBuilder::new(vec![Operation::Add]).add_to_forest(&mut f).unwrap();
        let e = BasicBlockNodeBuilder::new(vec![Operation::Mul]).add_to_forest(&mut f).unwrap();
        let s = SplitNodeBuilder::new([t, e]).add_to_forest(&mut f).unwrap();
        f.make_root(s);
        Program::new(f.into(), s)
    };
    let trace = build_trace_from_program(&program, &[cond]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut split_rows = 0usize;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let addr_next = main.addr(next);
        let first = main.decoder_hasher_state_first_half(idx);
        let second = main.decoder_hasher_state_second_half(idx);

        if op == Felt::from_u8(opcodes::SPLIT) {
            let s0 = main.stack_element(0, idx);
            let one_minus_s0 = ONE - s0;
            let child_hash: [Felt; 4] =
                std::array::from_fn(|i| s0 * first[i] + one_minus_s0 * second[i]);
            exp.add(row, &BlockHashMsg::Child { parent: addr_next, child_hash });
            split_rows += 1;
        }

        if op == Felt::from_u8(opcodes::END) {
            let is_loop_body = main.is_loop_body_flag(idx);
            let h0: [Felt; 4] = [first[0], first[1], first[2], first[3]];
            let is_first_child = next_op_first_child_flag(main, next);
            exp.remove(
                row,
                &BlockHashMsg::End {
                    parent: addr_next,
                    child_hash: h0,
                    is_first_child,
                    is_loop_body,
                },
            );
        }
    });

    assert_eq!(split_rows, 1, "expected exactly one SPLIT enqueue");
    // END fires for: taken branch's child, the SPLIT itself. Two removes total.
    assert_eq!(exp.count_removes(), 2, "expected END pops for child + SPLIT: cond={cond}");
    log.assert_contains(&exp);
}

// OP GROUP TABLE TESTS
// ================================================================================================

/// A SPAN whose batch holds 8 op groups triggers the g8 insert batch (7 adds for positions 1..=7;
/// position 0 is consumed inline by the SPAN decode row and not inserted). Each in-span decode
/// row where `group_count` decrements emits a matching remove — covered in
/// [`op_group_span_removal_covers_decode_rows`].
///
/// A batch of 64 simple stack-depth-neutral ops was picked because each op group packs 9 seven-bit
/// opcodes into a 63-bit group value, so 8 groups hold 72 ops max; 64 ops reliably fills the
/// batch up to the g8 threshold without spilling into a second batch.
#[test]
fn op_group_span_8_groups_inserts() {
    let pattern = [Operation::Noop, Operation::Incr, Operation::Neg, Operation::Eqz];
    let ops: Vec<Operation> = (0..64).map(|i| pattern[i % pattern.len()]).collect();
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut g8_rows_seen = 0usize;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        if op != Felt::from_u8(opcodes::SPAN) && op != Felt::from_u8(opcodes::RESPAN) {
            return;
        }
        if main.op_batch_encoding(idx) != OP_BATCH_8_GROUPS {
            return;
        }
        g8_rows_seen += 1;

        let addr_next = main.addr(RowIndex::from(row + 1));
        let gc = main.group_count(idx);
        let first = main.decoder_hasher_state_first_half(idx);
        let second = main.decoder_hasher_state_second_half(idx);
        for i in 1u16..=3 {
            let group_value = first[i as usize];
            exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, group_value));
        }
        for i in 4u16..=7 {
            let group_value = second[(i - 4) as usize];
            exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, group_value));
        }
    });

    assert!(g8_rows_seen > 0, "program did not produce a g8 SPAN/RESPAN batch");
    assert_eq!(
        exp.count_adds(),
        7 * g8_rows_seen,
        "expected 7 g8 inserts per SPAN/RESPAN row (positions 1..=7)"
    );
    assert_eq!(exp.count_removes(), 0, "op_group_span_8_groups_inserts only checks inserts");

    log.assert_contains(&exp);
}

/// Every in-span decode row where `group_count` strictly decrements removes one entry from the
/// op-group table. The removal's `group_value` is muxed by `is_push`:
///
/// - PUSH rows: pull the immediate from `stk_next[0]` (pushed value is at stack top next cycle).
/// - Non-PUSH rows: `group_value = h0_next · 128 + opcode_next` — the residual group value after
///   the current op is "peeled off" the low 7 bits.
///
/// Includes at least one PUSH to exercise both mux branches and enough in-group ops to force a
/// boundary decrement where the emitter could otherwise off-by-one.
#[test]
fn op_group_span_removal_covers_decode_rows() {
    // Two full groups (9 Noops) + PUSH(immediate) + a handful more. The 9th Noop closes the
    // first op group (non-PUSH decrement, exercising the `h0_next * 128 + opcode_next` branch)
    // and the PUSH pulls its immediate from a dedicated group (exercising the `stk_next[0]`
    // branch).
    let mut ops: Vec<Operation> = (0..9).map(|_| Operation::Noop).collect();
    ops.push(Operation::Push(Felt::new_unchecked(42)));
    ops.extend(vec![Operation::Add, Operation::Mul, Operation::Drop]);
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut fired_push_branch = false;
    let mut fired_nonpush_branch = false;

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        if main.is_in_span(idx) != ONE {
            return;
        }
        let gc = main.group_count(idx);
        let gc_next = main.group_count(next);
        if gc == gc_next {
            return;
        }

        let addr = main.addr(idx);
        let group_value = if op == Felt::from_u8(opcodes::PUSH) {
            fired_push_branch = true;
            main.stack_element(0, next)
        } else {
            fired_nonpush_branch = true;
            let h0_next = main.decoder_hasher_state_element(0, next);
            let opcode_next = main.get_op_code(next);
            h0_next * Felt::from_u16(128) + opcode_next
        };
        exp.remove(
            row,
            &OpGroupMsg {
                batch_id: addr,
                group_pos: gc,
                group_value,
            },
        );
    });

    assert!(
        fired_push_branch,
        "test did not cover the PUSH-mux branch of the op-group remove"
    );
    assert!(
        fired_nonpush_branch,
        "test did not cover the non-PUSH branch of the op-group remove"
    );

    log.assert_contains(&exp);
}

/// A SPAN that spans two batches exercises the RESPAN-boundary op-group dispatch. Runs with
/// op counts that force each non-g8 batch variant in the second batch to catch off-by-one /
/// batch-encoding dispatch bugs at the transition:
///
/// - 80 Noops: first batch g8 (7 adds) + RESPAN + g1 second batch (0 adds — single group consumed
///   inline; emitter has no g1 branch).
/// - 88 Noops: first batch g8 + RESPAN + g2 second batch (1 add for position 1).
/// - 100 Noops: first batch g8 + RESPAN + g4 second batch (3 adds for positions 1..=3).
/// - 144 Noops: two full g8 batches.
///
/// The dispatch below matches the canonical two-column operation-batch encoding.
#[rstest::rstest]
#[case::g8_plus_g1(80, 1, 0, 0, 1)]
#[case::g8_plus_g2(88, 1, 0, 1, 0)]
#[case::g8_plus_g4(100, 1, 1, 0, 0)]
#[case::g8_plus_g8(144, 2, 0, 0, 0)]
fn op_group_span_two_batch_transition_inserts(
    #[case] noop_count: usize,
    #[case] expected_g8_rows: usize,
    #[case] expected_g4_rows: usize,
    #[case] expected_g2_rows: usize,
    #[case] expected_g1_rows: usize,
) {
    let ops: Vec<Operation> = (0..noop_count).map(|_| Operation::Noop).collect();
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut g8_rows = 0usize;
    let mut g4_rows = 0usize;
    let mut g2_rows = 0usize;
    let mut g1_rows = 0usize;
    let mut respan_observed = false;
    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        if op != Felt::from_u8(opcodes::SPAN) && op != Felt::from_u8(opcodes::RESPAN) {
            return;
        }
        if op == Felt::from_u8(opcodes::RESPAN) {
            respan_observed = true;
        }
        let batch_encoding = main.op_batch_encoding(idx);
        let addr_next = main.addr(RowIndex::from(row + 1));
        let gc = main.group_count(idx);
        let first = main.decoder_hasher_state_first_half(idx);
        let second = main.decoder_hasher_state_second_half(idx);

        if batch_encoding == OP_BATCH_8_GROUPS {
            g8_rows += 1;
            for i in 1u16..=3 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, first[i as usize]));
            }
            for i in 4u16..=7 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, second[(i - 4) as usize]));
            }
        } else if batch_encoding == OP_BATCH_4_GROUPS {
            g4_rows += 1;
            for i in 1u16..=3 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, first[i as usize]));
            }
        } else if batch_encoding == OP_BATCH_2_GROUPS {
            g2_rows += 1;
            exp.add(row, &OpGroupMsg::new(&addr_next, gc, 1, first[1]));
        } else if batch_encoding == OP_BATCH_1_GROUPS {
            // g1 batch: single group consumed inline by the RESPAN decode row; no inserts.
            g1_rows += 1;
        } else {
            panic!("unexpected operation-batch encoding on SPAN/RESPAN row: {batch_encoding:?}");
        }
    });

    assert!(respan_observed, "program did not produce a RESPAN row");
    assert_eq!(g8_rows, expected_g8_rows);
    assert_eq!(g4_rows, expected_g4_rows);
    assert_eq!(g2_rows, expected_g2_rows);
    assert_eq!(g1_rows, expected_g1_rows);
    assert_eq!(exp.count_adds(), 7 * g8_rows + 3 * g4_rows + g2_rows);
    assert_eq!(exp.count_removes(), 0);

    log.assert_contains(&exp);
}

#[rstest::rstest]
#[case::g8(64, OP_BATCH_8_GROUPS)]
#[case::g4(100, OP_BATCH_4_GROUPS)]
#[case::g2(88, OP_BATCH_2_GROUPS)]
#[case::g1(80, OP_BATCH_1_GROUPS)]
fn canonical_op_batch_encodings_satisfy_the_full_air(
    #[case] noop_count: usize,
    #[case] encoding: [Felt; 2],
) {
    let trace = build_trace_from_ops(vec![Operation::Noop; noop_count], &[]);
    batch_row(&trace, encoding);
    trace.check_constraints();
    super::lookup::assert_global_lookup_balance(&trace);
}

#[test]
fn op_batch_encoding_rejects_invalid_and_off_batch_values() {
    let trace = build_trace_from_ops(vec![Operation::Noop; 100], &[]);
    let active_row = batch_row(&trace, OP_BATCH_4_GROUPS);

    assert_core_mutation_rejected(&trace, active_row, |row| {
        row.decoder.full_batch = Felt::from_u8(2);
    });
    assert_core_mutation_rejected(&trace, active_row, |row| {
        row.decoder.full_batch = -ONE;
    });
    assert_core_mutation_rejected(&trace, active_row, |row| {
        row.decoder.batch_size_code = Felt::from_u8(2);
    });
    assert_core_mutation_rejected(&trace, active_row, |row| {
        row.decoder.full_batch = ONE;
        row.decoder.batch_size_code = ONE;
    });

    let inactive_row = non_batch_row(&trace);
    assert_core_mutation_rejected(&trace, inactive_row, |row| {
        row.decoder.full_batch = ONE;
    });
    assert_core_mutation_rejected(&trace, inactive_row, |row| {
        row.decoder.batch_size_code = -ONE;
    });
}

#[rstest::rstest]
#[case::g4(100, OP_BATCH_4_GROUPS, 4..8)]
#[case::g2(88, OP_BATCH_2_GROUPS, 2..8)]
#[case::g1(80, OP_BATCH_1_GROUPS, 1..8)]
fn op_batch_encoding_pins_every_unused_hasher_lane(
    #[case] noop_count: usize,
    #[case] encoding: [Felt; 2],
    #[case] unused_lanes: core::ops::Range<usize>,
) {
    let trace = build_trace_from_ops(vec![Operation::Noop; noop_count], &[]);
    let row = batch_row(&trace, encoding);
    let (honest_core, chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();

    for lane in unused_lanes {
        let mut core_matrix = honest_core.clone();
        let decoder = &mut core_row_mut(&mut core_matrix, row).decoder;
        assert_eq!(decoder.hasher_state[lane], ZERO, "lane h{lane} must start unused");
        decoder.hasher_state[lane] = ONE;
        super::lookup::assert_trace_constraints_reject(
            &trace,
            core_matrix,
            chip_matrix.clone(),
            eidos_compression_matrix.clone(),
            and8_matrix.clone(),
        );
    }
}

/// Every directed substitution between otherwise valid encodings must change the OpGroup
/// multiset. This checks global lookup balance directly, independently of whether a smaller
/// replacement also violates the unused-lane constraints.
#[rstest::rstest]
#[case::g8_to_g4(64, OP_BATCH_8_GROUPS, OP_BATCH_4_GROUPS)]
#[case::g8_to_g2(64, OP_BATCH_8_GROUPS, OP_BATCH_2_GROUPS)]
#[case::g8_to_g1(64, OP_BATCH_8_GROUPS, OP_BATCH_1_GROUPS)]
#[case::g4_to_g8(100, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS)]
#[case::g4_to_g2(100, OP_BATCH_4_GROUPS, OP_BATCH_2_GROUPS)]
#[case::g4_to_g1(100, OP_BATCH_4_GROUPS, OP_BATCH_1_GROUPS)]
#[case::g2_to_g8(88, OP_BATCH_2_GROUPS, OP_BATCH_8_GROUPS)]
#[case::g2_to_g4(88, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS)]
#[case::g2_to_g1(88, OP_BATCH_2_GROUPS, OP_BATCH_1_GROUPS)]
#[case::g1_to_g8(80, OP_BATCH_1_GROUPS, OP_BATCH_8_GROUPS)]
#[case::g1_to_g2(80, OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS)]
#[case::g1_to_g4(80, OP_BATCH_1_GROUPS, OP_BATCH_4_GROUPS)]
fn valid_op_batch_encoding_swaps_unbalance_the_op_group_bus(
    #[case] noop_count: usize,
    #[case] original_encoding: [Felt; 2],
    #[case] replacement_encoding: [Felt; 2],
) {
    let trace = build_trace_from_ops(vec![Operation::Noop; noop_count], &[]);
    let row = batch_row(&trace, original_encoding);
    let (mut core_matrix, chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();
    let decoder = &mut core_row_mut(&mut core_matrix, row).decoder;
    decoder.full_batch = replacement_encoding[0];
    decoder.batch_size_code = replacement_encoding[1];

    super::lookup::assert_global_lookup_balance_rejects(
        "valid operation-batch encoding swap",
        &trace,
        &core_matrix,
        &chip_matrix,
        &eidos_compression_matrix,
        &and8_matrix,
        "OpGroupMsg",
    );
}

// DYNCALL REGRESSION TESTS
// ================================================================================================

#[test]
fn decoder_dyncall_at_min_stack_depth_records_post_drop_ctx_info() {
    use std::sync::Arc;

    use crate::{MIN_STACK_DEPTH, mast::DynNodeBuilder, operation::opcodes};

    // Build exactly the same program shape as `dyncall_program()` in parallel/tests.rs:
    //   join(
    //       block(push(HASH_ADDR), mem_storew, drop, drop, drop, drop, push(HASH_ADDR)),
    //       dyncall,
    //   )
    // The target procedure (single SWAP) is added as a second root so the VM can find it.
    //
    // The caller passes the 4-element procedure hash as the initial stack contents
    // (top-of-stack first).  The preamble stores that word at HASH_ADDR so that DYNCALL
    // can load it and dispatch to the correct procedure.
    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    // --- build the forest in the same order as dyncall_program() ---
    let mut forest = MastForest::new();

    // 1. Build the root join node first (preamble + dyncall).
    let root = {
        let preamble = BasicBlockNodeBuilder::new(vec![
            Operation::Push(HASH_ADDR),
            Operation::MStoreW,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(HASH_ADDR),
        ])
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();

        JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap()
    };
    forest.make_root(root);

    // 2. Add the procedure that DYNCALL will call, as a second forest root.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(target);

    // 3. Derive the stack inputs from the target's digest (4 Felts, top-of-stack first).
    let target_hash: Vec<Felt> =
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect();

    let program = Program::new(Arc::new(forest), root);

    let trace =
        build_trace_from_program_with_stack(&program, StackInputs::new(&target_hash).unwrap());
    let main = trace.main_trace();

    // Locate the DYNCALL row.
    let dyncall_opcode = Felt::from_u8(opcodes::DYNCALL);
    let row = (0..main.core_height())
        .map(RowIndex::from)
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    // second_hasher_state[0] = caller stack depth        → decoder_hasher_state_element(4)
    // second_hasher_state[1] = caller overflow address   → decoder_hasher_state_element(5)
    //
    // DYNCALL consumes the memory address at the top of the stack. At the minimum represented
    // depth, that pop is clamped at MIN_STACK_DEPTH (16) and the empty overflow table leaves no
    // previous overflow address to record, so the caller overflow address must be ZERO.
    assert_eq!(
        main.decoder_hasher_state_element(4, row),
        Felt::new_unchecked(MIN_STACK_DEPTH as u64),
        "the caller stack depth should equal MIN_STACK_DEPTH"
    );
    assert_eq!(
        main.decoder_hasher_state_element(5, row),
        ZERO,
        "the caller overflow address should be ZERO when stack is at MIN_STACK_DEPTH"
    );
}

#[test]
fn decoder_dyncall_with_multiple_overflow_entries_records_correct_overflow_addr() {
    // Regression test: when the caller context has more than one overflow entry, the
    // serial ExecutionTracer must record the post-pop overflow address (the clock of
    // the second-to-last entry), not the pre-pop address (the clock of the top entry).
    use std::sync::Arc;

    use crate::{mast::DynNodeBuilder, operation::opcodes};

    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    let mut forest = MastForest::new();

    // 1. Build the callee procedure first so we can get its digest.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(target);

    let target_hash: Vec<Felt> =
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect();

    // 2. Build the main program.
    let root = {
        let preamble = BasicBlockNodeBuilder::new(vec![
            Operation::Push(HASH_ADDR),
            Operation::MStoreW,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(ZERO),      // depth=17, overflow[0]=0 (clk=T1)
            Operation::Push(HASH_ADDR), // depth=18, overflow[1]=0 (clk=T2)
        ])
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        let inner_join =
            JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap();

        let cleanup = BasicBlockNodeBuilder::new(vec![Operation::Drop])
            .add_to_forest(&mut forest)
            .unwrap();

        JoinNodeBuilder::new([inner_join, cleanup]).add_to_forest(&mut forest).unwrap()
    };
    forest.make_root(root);

    let program = Program::new(Arc::new(forest), root);

    let trace =
        build_trace_from_program_with_stack(&program, StackInputs::new(&target_hash).unwrap());
    let main = trace.main_trace();

    // Locate the DYNCALL row.
    let dyncall_opcode = Felt::from_u8(opcodes::DYNCALL);
    let dyncall_row = (0..main.core_height())
        .map(RowIndex::from)
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    let recorded_depth = main.decoder_hasher_state_element(4, dyncall_row);
    let recorded_overflow_addr = main.decoder_hasher_state_element(5, dyncall_row);

    // At DYNCALL time depth=18 (>MIN_STACK_DEPTH), so post-drop depth = 17.
    assert_eq!(
        recorded_depth,
        Felt::new_unchecked(17),
        "the caller stack depth should be 17 (= pre-DYNCALL depth 18 minus 1)"
    );

    // Independently determine T1 (clock of push(0)) by scanning for all PUSH rows before DYNCALL.
    let push_opcode = Felt::from_u8(opcodes::PUSH);
    let push_rows_before_dyncall: Vec<_> = (0..main.core_height())
        .map(RowIndex::from)
        .filter(|&i| i < dyncall_row && main.get_op_code(i) == push_opcode)
        .collect();
    let n = push_rows_before_dyncall.len();
    assert!(n >= 2, "expected at least 2 PUSH rows before DYNCALL, found {n}");
    let t1_row = push_rows_before_dyncall[n - 2]; // push(0) → overflow[0]
    let t2_row = push_rows_before_dyncall[n - 1]; // push(HASH_ADDR) → overflow[1]
    let t1 = main.clk(t1_row);
    let t2 = main.clk(t2_row);
    assert_eq!(t2, t1 + ONE, "push(0) and push(HASH_ADDR) must be at consecutive clocks");

    // clk_after_pop_in_current_ctx() returns T1 (the second-to-last overflow entry's clock).
    assert_eq!(
        recorded_overflow_addr, t1,
        "the caller overflow address must equal T1 (second-to-last overflow clock = {t1}); \
         T2 (top overflow clock = {t2}) would indicate the buggy path"
    );

    // The lookup must bind h5 as the predecessor of the row consumed by DYNCALL.
    assert_eq!(main.parent_overflow_address(dyncall_row), t2);
    let next = RowIndex::from(usize::from(dyncall_row) + 1);
    assert_eq!(main.stack_element(15, next), ZERO);
    let log = InteractionLog::new(&trace);
    let mut expected = Expectations::new(&log);
    expected.remove(usize::from(dyncall_row), &StackOverflowMsg { clk: t2, val: ZERO, prev: t1 });
    log.assert_contains(&expected);
}

// END-FLAG / SYSTEM-STATE COUPLING
// ================================================================================================

/// The AIR gates `ctx`/`fn_hash` preservation on the caller-frame restoration selector: an END
/// carrying no caller-frame restoration flag must preserve both columns, because only a
/// caller-frame block-stack entry authorizes restoring them.
///
/// The AIR rejects an END that changes system state without this flag, but it cannot ensure future
/// processor finish paths keep emitting the flag. This property protects honest trace construction.
///
/// Coverage is asserted, not assumed: the test fails if any END variety it claims to exercise
/// never actually appears, so it cannot quietly go vacuous if program lowering changes.
#[test]
fn system_state_changes_across_end_imply_a_caller_frame_flag() {
    #[derive(Debug, Default)]
    struct EndObservations {
        continuation: usize,
        loop_continuation: usize,
        caller_frame: usize,
    }

    let observe_and_check = |label: &str, trace: &VmTrace| {
        let main = trace.main_trace();
        let mut observations = EndObservations::default();
        for row in 0..(main.core_height() - 1) {
            let idx = RowIndex::from(row);
            if main.get_op_code(idx) != Felt::from_u8(opcodes::END) {
                continue;
            }
            let next = RowIndex::from(row + 1);
            let restores_caller_frame = main.restores_caller_frame_flag(idx);

            if restores_caller_frame == ZERO {
                if main.is_loop_flag(idx) == ONE {
                    observations.loop_continuation += 1;
                } else {
                    observations.continuation += 1;
                }
            } else {
                assert_eq!(
                    restores_caller_frame, ONE,
                    "row {row} of `{label}`: the caller-frame restoration flag must be boolean"
                );
                observations.caller_frame += 1;
            }

            let changed =
                main.ctx(idx) != main.ctx(next) || main.fn_hash(idx) != main.fn_hash(next);
            if !changed {
                continue;
            }
            assert_eq!(
                restores_caller_frame, ONE,
                "row {row} of `{label}`: an END that changes ctx or fn_hash must restore a caller \
                 frame, or the AIR's preservation mask rejects the honest trace"
            );
        }
        observations
    };

    let count_opcode = |trace: &VmTrace, opcode: u8| {
        let main = trace.main_trace();
        (0..main.core_height())
            .map(RowIndex::from)
            .filter(|&row| main.get_op_code(row) == Felt::from_u8(opcode))
            .count()
    };

    // Assembled programs: ordinary basic block, JOIN/SPLIT, loop body + REPEAT + loop exit, and
    // a CALL whose callee itself contains a nested ordinary END.
    // Stack inputs are top-first. The loop program is the only one reading them: it pops 1 to
    // enter, 1 to repeat, then 0 to exit -- giving LOOP, REPEAT and a loop END. The others push
    // their own conditions.
    let run_assembled = |source: &str, inputs: &[u64], expected_opcodes: &[(u8, usize)]| {
        let program = miden_assembly::Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let trace = build_trace_from_program(&program, inputs);
        for &(opcode, expected_count) in expected_opcodes {
            assert_eq!(
                count_opcode(&trace, opcode),
                expected_count,
                "fixture must execute opcode {opcode} exactly {expected_count} time(s)"
            );
        }
        observe_and_check(source, &trace)
    };

    let ordinary = run_assembled("begin push.1 nop drop end", &[], &[]);
    assert!(ordinary.continuation > 0, "ordinary fixture executed no continuation END");

    let split = run_assembled(
        "begin push.1 if.true push.7 drop else push.8 drop end push.9 drop end",
        &[],
        &[(opcodes::SPLIT, 1)],
    );
    assert!(split.continuation > 0, "SPLIT fixture executed no continuation END");

    let loop_program = run_assembled(
        "begin while.true nop end end",
        &[1, 1, 0],
        &[(opcodes::LOOP, 1), (opcodes::REPEAT, 1)],
    );
    assert!(loop_program.loop_continuation > 0, "LOOP fixture executed no LOOP END");

    let call = run_assembled(
        "proc inner push.1 if.true nop else nop end nop end begin call.inner end",
        &[],
        &[(opcodes::CALL, 1)],
    );
    assert_eq!(call.caller_frame, 1, "CALL fixture executed the wrong frame ENDs");

    // DYN and DYNCALL: both reach a target by digest read from memory, and only DYNCALL creates a
    // caller frame. Assembled separately because the target digest must be
    // supplied as a `Felt` stack input rather than through `u64`.
    let run_dynamic = |op: &str, expected_opcode: u8| {
        let source = format!(
            "proc target nop end\n begin call.target mem_storew_le.40 dropw push.40 {op} end"
        );
        let program = miden_assembly::Assembler::default()
            .assemble_program("program", source.as_str())
            .unwrap()
            .unwrap_program();
        let root = program.hash();
        let target_digest = program
            .mast_forest()
            .procedure_digests()
            .find(|d| *d != root)
            .expect("the dynamic target must survive as its own procedure");

        let mut stack_values = vec![Felt::ZERO; 16];
        for (i, limb) in target_digest.as_elements().iter().enumerate() {
            stack_values[i] = *limb;
        }
        let stack_inputs = StackInputs::new(&stack_values).unwrap();
        let trace = build_trace_from_program_with_stack(&program, stack_inputs);
        assert_eq!(
            count_opcode(&trace, expected_opcode),
            1,
            "{op} fixture must execute its dynamic start opcode exactly once"
        );
        observe_and_check(op, &trace).caller_frame
    };
    let dyn_call_frames = run_dynamic("dynexec", opcodes::DYN);
    let dyncall_call_frames = run_dynamic("dyncall", opcodes::DYNCALL);
    assert_eq!(dyn_call_frames, 1, "DYN fixture must contain only the explicit CALL frame");
    assert_eq!(dyncall_call_frames, 2, "DYNCALL fixture must add exactly one caller frame");

    // SYSCALL, built through the MAST directly since it needs a kernel.
    {
        let mut forest = MastForest::new();
        let kernel_proc_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(kernel_proc_id);
        let kernel_digest = forest[kernel_proc_id].digest();
        let kernel = KernelDescriptor::new(&[kernel_digest]).unwrap();

        let syscall_id =
            CallNodeBuilder::new_syscall(kernel_proc_id).add_to_forest(&mut forest).unwrap();
        let body_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();
        let root_id =
            JoinNodeBuilder::new([body_id, syscall_id]).add_to_forest(&mut forest).unwrap();
        forest.make_root(root_id);
        let program = Program::with_kernel(forest.into(), root_id, kernel);

        let trace = build_trace_from_program(&program, &[]);
        assert_eq!(
            count_opcode(&trace, opcodes::SYSCALL),
            1,
            "SYSCALL fixture must execute its SYSCALL start opcode exactly once"
        );
        let observations = observe_and_check("syscall", &trace);
        assert_eq!(
            observations.caller_frame, 1,
            "SYSCALL fixture must contribute exactly one caller-frame END"
        );
    }
}
