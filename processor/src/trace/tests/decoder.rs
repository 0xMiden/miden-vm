//! Decoder virtual-table bus tests.
//!
//! The legacy names P1/P2/P3 refer to the block-stack, block-hash queue, and op-group tables
//! respectively. Those dedicated running-product columns no longer exist: block-stack rides M1
//! (merged with u32 range checks and the log-precompile capacity bus), and block-hash + op-group
//! share M_2+5. The names are kept as historical shorthand for the interaction families.
//!
//! Under the LogUp framework the interactions still look like "+1 / encode(Msg)" on push rows
//! and "-1 / encode(Msg)" on pop rows. Each test runs a tiny program that exercises one
//! push/pop pair (or a small batch) and checks both halves land via the subset matcher.
//!
//! Coverage is targeted rather than exhaustive: the tests below hit the control-flow variants
//! that have historically harbored off-by-one or selector-muxing bugs (JOIN, LOOP+REPEAT, CALL,
//! SPAN/RESPAN op-group batching). Broader end-to-end soundness comes from
//! `build_lookup_fractions_matches_constraint_path_oracle` in `tests/lookup.rs`.

use alloc::vec::Vec;

use miden_air::logup::{BlockHashMsg, BlockStackMsg, OpGroupMsg};
use miden_core::{
    Felt, ONE, ZERO,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest,
        MastForestContributor,
    },
    operations::{Operation, opcodes},
    program::Program,
};

use super::{
    ExecutionTrace, build_trace_from_ops, build_trace_from_program,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::RowIndex;

// HELPERS
// ================================================================================================

/// Calls `f(row, opcode)` for every row except the last.
///
/// Most decoder tests need `row + 1` lookups (next-row flags, addr_next, etc.) so stopping one
/// short of the end avoids per-test bounds checks.
fn for_each_op<F>(trace: &ExecutionTrace, mut f: F)
where
    F: FnMut(usize, Felt),
{
    let main = trace.main_trace();
    let num_rows = main.num_rows();
    for row in 0..num_rows - 1 {
        let idx = RowIndex::from(row);
        f(row, main.get_op_code(idx));
    }
}

// BLOCK STACK TABLE (M1) TESTS
// ================================================================================================

/// A lone SPAN pushes one simple entry and the matching END pops it.
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
                &BlockStackMsg::Simple {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop: ZERO,
                },
            );
        } else if op == Felt::from_u8(opcodes::END) {
            exp.remove(
                row,
                &BlockStackMsg::Simple {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop: ZERO,
                },
            );
        }
    });

    log.assert_contains(&exp);
}

/// CALL pushes a `Full` entry saving caller context (ctx, fmp, depth, fn_hash); the matching
/// END pops a `Full` entry reading the *next* row's system/stack state (the restored caller
/// context).
#[test]
fn block_stack_call_full_push_pop() {
    let program = {
        let mut forest = MastForest::new();
        let callee = BasicBlockNodeBuilder::new(vec![Operation::Noop], Vec::new())
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
                &BlockStackMsg::Full {
                    block_id: main.addr(next),
                    parent_id: main.addr(idx),
                    is_loop: ZERO,
                    ctx: main.ctx(idx),
                    fmp: main.stack_depth(idx),
                    depth: main.parent_overflow_address(idx),
                    fn_hash: main.fn_hash(idx),
                },
            );
        }

        // END-of-CALL branch: `is_call_flag` at the END row selects the Full variant. Caller
        // context is restored on the *next* row, so the emitter reads ctx/b0/b1/fn_hash from
        // row+1.
        if op == Felt::from_u8(opcodes::END) && main.is_call_flag(idx) == ONE {
            exp.remove(
                row,
                &BlockStackMsg::Full {
                    block_id: main.addr(idx),
                    parent_id: main.addr(next),
                    is_loop: ZERO,
                    ctx: main.ctx(next),
                    fmp: main.stack_depth(next),
                    depth: main.parent_overflow_address(next),
                    fn_hash: main.fn_hash(next),
                },
            );
        }
    });

    log.assert_contains(&exp);
}

// BLOCK HASH QUEUE (M_2+5) TESTS
// ================================================================================================

/// A JOIN enqueues two children (first + subsequent) and the two child ENDs dequeue them.
#[test]
fn block_hash_join_enqueue_dequeue() {
    let program = {
        let mut mast_forest = MastForest::new();
        let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
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

        // Emitter uses `is_first_child = 1 - end_next - repeat_next - halt_next` (arithmetic).
        // Since END/REPEAT/HALT are distinct 7-bit opcodes, at most one flag is non-zero per
        // row, so the arithmetic form collapses to the trace-level OR. We still encode it
        // arithmetically to mirror the constraint expression exactly.
        if op == Felt::from_u8(opcodes::END) {
            let next_end = if main.get_op_code(next) == Felt::from_u8(opcodes::END) {
                ONE
            } else {
                ZERO
            };
            let next_repeat = if main.get_op_code(next) == Felt::from_u8(opcodes::REPEAT) {
                ONE
            } else {
                ZERO
            };
            let next_halt = if main.get_op_code(next) == Felt::from_u8(opcodes::HALT) {
                ONE
            } else {
                ZERO
            };
            let is_first_child = ONE - next_end - next_repeat - next_halt;
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

    log.assert_contains(&exp);
}

/// LOOP (when `s0 = 1`) and REPEAT both enqueue a `LoopBody` entry for the body, and the END
/// at the end of each body dequeues it with `is_loop_body = 1`. Runs two iterations
/// (advice/inputs `[1, 1, 0]`) so both the LOOP and REPEAT branches fire.
#[test]
fn block_hash_loop_body_with_repeat() {
    let program = {
        let mut mast_forest = MastForest::new();
        let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Pad], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let join_id = JoinNodeBuilder::new([bb1, bb2]).add_to_forest(&mut mast_forest).unwrap();
        let loop_id = LoopNodeBuilder::new(join_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_id);
        Program::new(mast_forest.into(), loop_id)
    };

    // Stack `[1, 1, 0]` drives two iterations: enter, repeat, exit.
    let trace = build_trace_from_program(&program, &[1, 1, 0]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut fired_loop_body = 0usize;
    let mut fired_loop_body_end = 0usize;

    let mut exp = Expectations::new(&log);
    for_each_op(&trace, |row, op| {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let first = main.decoder_hasher_state_first_half(idx);
        let h0: [Felt; 4] = [first[0], first[1], first[2], first[3]];
        let addr_next = main.addr(next);

        // `f_loop_body = loop_op * s0 + repeat`. LOOP with `s0 = 0` does not enter the body, so
        // the body is only enqueued when `s0 = 1` (first iteration entry) or on REPEAT.
        let is_loop_entering =
            op == Felt::from_u8(opcodes::LOOP) && main.stack_element(0, idx) == ONE;
        let is_repeat = op == Felt::from_u8(opcodes::REPEAT);
        if is_loop_entering || is_repeat {
            exp.add(row, &BlockHashMsg::LoopBody { parent: addr_next, child_hash: h0 });
            fired_loop_body += 1;
        }

        // END of the loop body: `is_loop_body` bit is set on the END overlay.
        if op == Felt::from_u8(opcodes::END) && main.is_loop_body_flag(idx) == ONE {
            let next_end = if main.get_op_code(next) == Felt::from_u8(opcodes::END) {
                ONE
            } else {
                ZERO
            };
            let next_repeat = if main.get_op_code(next) == Felt::from_u8(opcodes::REPEAT) {
                ONE
            } else {
                ZERO
            };
            let next_halt = if main.get_op_code(next) == Felt::from_u8(opcodes::HALT) {
                ONE
            } else {
                ZERO
            };
            let is_first_child = ONE - next_end - next_repeat - next_halt;
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

    // Sanity: each iteration fires one LoopBody enqueue and one body-ending END remove.
    assert_eq!(fired_loop_body, 2, "expected LOOP + REPEAT to each fire a LoopBody enqueue");
    assert_eq!(fired_loop_body_end, 2, "expected one END-of-loop-body remove per iteration");

    log.assert_contains(&exp);
}

// OP GROUP TABLE (M_2+5) TESTS
// ================================================================================================

/// A SPAN whose batch holds 8 op groups triggers the g8 insert batch (7 adds for positions 1..=7;
/// position 0 is consumed inline by the SPAN decode row and not inserted). Each in-span decode
/// row where `group_count` decrements emits a matching remove — covered in
/// [`op_group_span_removal_covers_decode_rows`].
///
/// A batch of 64 Noops was picked because each op group packs 9 seven-bit opcodes into a 63-bit
/// group value, so 8 groups hold 72 ops max; 64 Noops reliably fills the batch up to the g8
/// threshold (`c0 == 1`) without spilling into a second batch.
#[test]
fn op_group_span_8_groups_inserts() {
    let ops: Vec<Operation> = (0..64).map(|_| Operation::Noop).collect();
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
        let batch_flags = main.op_batch_flag(idx);
        if batch_flags[0] != ONE {
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
    ops.push(Operation::Push(Felt::new(42)));
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
