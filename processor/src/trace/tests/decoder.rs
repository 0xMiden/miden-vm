//! Decoder virtual-table bus tests.
//!
//! Covers the block-stack table (merged with u32 range checks and the log-precompile
//! capacity bus) and the block-hash + op-group table column.
//!
//! Under the LogUp framework the interactions look like "+1 / encode(Msg)" on push rows
//! and "-1 / encode(Msg)" on pop rows. Each test runs a tiny program that exercises one
//! push/pop pair (or a small batch) and checks both halves land via the subset matcher.
//!
//! Coverage is targeted rather than exhaustive: the tests below hit the control-flow variants
//! prone to off-by-one or selector-muxing bugs (JOIN, LOOP+REPEAT, CALL, SPAN/RESPAN op-group
//! batching). Broader end-to-end soundness comes from
//! `build_lookup_fractions_matches_constraint_path_oracle` in `tests/lookup.rs`.

use alloc::vec::Vec;

use miden_air::logup::{BlockHashMsg, BlockStackMsg, OpGroupMsg};
use miden_core::{
    Felt, ONE, ZERO,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest,
        MastForestContributor, MastNodeExt, SplitNodeBuilder,
    },
    operations::{Operation, opcodes},
    program::Program,
};

use super::{
    ExecutionTrace, build_trace_from_ops, build_trace_from_program,
    build_trace_from_program_with_stack,
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

    assert_eq!(exp.count_adds(), 1, "expected exactly one SPAN push");
    assert_eq!(exp.count_removes(), 1, "expected exactly one matching END pop");
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

    assert_eq!(exp.count_adds(), 1, "expected exactly one CALL push");
    assert_eq!(exp.count_removes(), 1, "expected exactly one matching END pop");
    log.assert_contains(&exp);
}

/// SPLIT pushes a `Simple { is_loop: 0 }` entry (parent = current block, block = addr_next) and
/// the matching END pops it. Runs twice — once with `s0 = 1` (TRUE branch), once with `s0 = 0`
/// (FALSE branch) — since the block-stack emission is identical either way but the END reached
/// for the matching pop differs between branches.
#[rstest::rstest]
#[case::taken(1)]
#[case::not_taken(0)]
fn block_stack_split_push_pop(#[case] cond: u64) {
    let program = {
        let mut f = MastForest::new();
        let t = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut f)
            .unwrap();
        let e = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut f)
            .unwrap();
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
                &BlockStackMsg::Simple {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop: ZERO,
                },
            );
            split_adds += 1;
        } else if op == Felt::from_u8(opcodes::END) && main.is_call_flag(idx) == ZERO {
            // is_loop on the END overlay comes from the typed END flags; for non-loop ENDs it
            // is zero. We can read it back from the trace to stay agnostic about which END row
            // matches which push.
            let is_loop = main.is_loop_flag(idx);
            exp.remove(
                row,
                &BlockStackMsg::Simple {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop,
                },
            );
        }
    });

    assert_eq!(split_adds, 1, "expected exactly one SPLIT push");
    // One END for the taken inner branch, one for the SPLIT itself (parent). Both pop Simple.
    assert_eq!(exp.count_removes(), 2, "expected two Simple pops (child END + SPLIT END)");
    log.assert_contains(&exp);
}

/// LOOP with `s0 = 1` pushes a `Simple { is_loop: 1 }` entry and the matching END pops it.
/// LOOP with `s0 = 0` also pushes (emitter is unconditional on LOOP), but with `is_loop = 0`
/// and no body executes — the END on the very next row pops immediately. This test runs both
/// variants via `rstest`.
#[rstest::rstest]
#[case::enters(1, ONE)]
#[case::skips(0, ZERO)]
fn block_stack_loop_is_loop_flag(#[case] cond: u64, #[case] expected_is_loop: Felt) {
    let program = {
        let mut f = MastForest::new();
        let body = BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
            .add_to_forest(&mut f)
            .unwrap();
        let loop_id = LoopNodeBuilder::new(body).add_to_forest(&mut f).unwrap();
        f.make_root(loop_id);
        Program::new(f.into(), loop_id)
    };
    // Stack is laid out top-first: `cond` on top (drives LOOP), trailing zero drives the
    // single REPEAT/exit read when `cond == 1`.
    let trace = build_trace_from_program(&program, &[cond, 0]);
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
            let is_loop = main.stack_element(0, idx);
            assert_eq!(is_loop, expected_is_loop, "s0 sanity at LOOP row");
            exp.add(
                row,
                &BlockStackMsg::Simple {
                    block_id: addr_next,
                    parent_id: addr,
                    is_loop,
                },
            );
            loop_pushes += 1;
        } else if op == Felt::from_u8(opcodes::END)
            && main.is_call_flag(idx) == ZERO
            && main.is_loop_flag(idx) == expected_is_loop
            && main.is_loop_body_flag(idx) == ZERO
        {
            exp.remove(
                row,
                &BlockStackMsg::Simple {
                    block_id: addr,
                    parent_id: addr_next,
                    is_loop: expected_is_loop,
                },
            );
            loop_pops += 1;
        }
    });

    assert_eq!(loop_pushes, 1, "expected one LOOP push");
    assert_eq!(
        loop_pops, 1,
        "expected one matching LOOP END pop (is_loop={expected_is_loop:?})"
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
            &BlockStackMsg::Simple {
                block_id: addr_next,
                parent_id: parent,
                is_loop: ZERO,
            },
        );
        exp.remove(
            row,
            &BlockStackMsg::Simple {
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

    // Sanity: each iteration fires one LoopBody enqueue and one body-ending END remove.
    assert_eq!(fired_loop_body, 2, "expected LOOP + REPEAT to each fire a LoopBody enqueue");
    assert_eq!(fired_loop_body_end, 2, "expected one END-of-loop-body remove per iteration");

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
        let t = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut f)
            .unwrap();
        let e = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut f)
            .unwrap();
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
/// batch up to the g8 threshold (`c0 == 1`) without spilling into a second batch.
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
/// batch-flag muxing bugs at the transition:
///
/// - 80 Noops: first batch g8 (7 adds) + RESPAN + g1 second batch (0 adds — single group consumed
///   inline; emitter has no branch for `(c0, c1, c2) = (0, 1, 1)`).
/// - 100 Noops: first batch g8 + RESPAN + g4 second batch (3 adds for positions 1..=3).
///
/// The batch-flag dispatch below mirrors the emitter exactly: `c0` is the g8 selector,
/// `(1-c0)·c1·(1-c2)` is g4, `(1-c0)·(1-c1)·c2` is g2, and `(1-c0)·c1·c2` is g1.
#[rstest::rstest]
#[case::g8_plus_g1(80, 1, 0, 0, 1)]
#[case::g8_plus_g4(100, 1, 1, 0, 0)]
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
        let batch_flags = main.op_batch_flag(idx);
        let (c0, c1, c2) = (batch_flags[0], batch_flags[1], batch_flags[2]);
        let addr_next = main.addr(RowIndex::from(row + 1));
        let gc = main.group_count(idx);
        let first = main.decoder_hasher_state_first_half(idx);
        let second = main.decoder_hasher_state_second_half(idx);

        if c0 == ONE && c1 == ZERO && c2 == ZERO {
            g8_rows += 1;
            for i in 1u16..=3 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, first[i as usize]));
            }
            for i in 4u16..=7 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, second[(i - 4) as usize]));
            }
        } else if c0 == ZERO && c1 == ONE && c2 == ZERO {
            g4_rows += 1;
            for i in 1u16..=3 {
                exp.add(row, &OpGroupMsg::new(&addr_next, gc, i, first[i as usize]));
            }
        } else if c0 == ZERO && c1 == ZERO && c2 == ONE {
            g2_rows += 1;
            exp.add(row, &OpGroupMsg::new(&addr_next, gc, 1, first[1]));
        } else if c0 == ZERO && c1 == ONE && c2 == ONE {
            // g1 batch: single group consumed inline by the RESPAN decode row; no inserts.
            g1_rows += 1;
        } else {
            panic!("unexpected batch_flags on SPAN/RESPAN row: ({c0:?}, {c1:?}, {c2:?})");
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

// DYNCALL REGRESSION TESTS
// ================================================================================================

#[test]
fn decoder_dyncall_at_min_stack_depth_records_post_drop_ctx_info() {
    use std::sync::Arc;

    use crate::{
        MIN_STACK_DEPTH,
        mast::{DynNodeBuilder, MastForestContributor},
        operation::opcodes,
    };

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
        let preamble = BasicBlockNodeBuilder::new(
            vec![
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Push(HASH_ADDR),
            ],
            Vec::new(),
        )
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();

        JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap()
    };
    forest.make_root(root);

    // 2. Add the procedure that DYNCALL will call, as a second forest root.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
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
    let row = main
        .row_iter()
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    // second_hasher_state[0] = parent_stack_depth        → decoder_hasher_state_element(4)
    // second_hasher_state[1] = parent_next_overflow_addr → decoder_hasher_state_element(5)
    //
    // With 4 hash elements on the stack the depth is still MIN_STACK_DEPTH (16); after
    // DYNCALL drops those 4 elements the post-drop depth is 12 = MIN_STACK_DEPTH, which
    // means no overflow entry was pushed, so parent_next_overflow_addr must be ZERO.
    assert_eq!(
        main.decoder_hasher_state_element(4, row),
        Felt::new_unchecked(MIN_STACK_DEPTH as u64),
        "parent_stack_depth should equal MIN_STACK_DEPTH"
    );
    assert_eq!(
        main.decoder_hasher_state_element(5, row),
        ZERO,
        "parent_next_overflow_addr should be ZERO when stack is at MIN_STACK_DEPTH"
    );
}

#[test]
fn decoder_dyncall_with_multiple_overflow_entries_records_correct_overflow_addr() {
    // Regression test: when the caller context has more than one overflow entry, the
    // serial ExecutionTracer must record the post-pop overflow address (the clock of
    // the second-to-last entry), not the pre-pop address (the clock of the top entry).
    use std::sync::Arc;

    use crate::{
        mast::{DynNodeBuilder, MastForestContributor},
        operation::opcodes,
    };

    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    let mut forest = MastForest::new();

    // 1. Build the callee procedure first so we can get its digest.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(target);

    let target_hash: Vec<Felt> =
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect();

    // 2. Build the main program.
    let root = {
        let preamble = BasicBlockNodeBuilder::new(
            vec![
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Push(ZERO),      // depth=17, overflow[0]=0 (clk=T1)
                Operation::Push(HASH_ADDR), // depth=18, overflow[1]=0 (clk=T2)
            ],
            Vec::new(),
        )
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        let inner_join =
            JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap();

        let cleanup = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
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
    let dyncall_row = main
        .row_iter()
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    let recorded_depth = main.decoder_hasher_state_element(4, dyncall_row);
    let recorded_overflow_addr = main.decoder_hasher_state_element(5, dyncall_row);

    // At DYNCALL time depth=18 (>MIN_STACK_DEPTH), so post-drop depth = 17.
    assert_eq!(
        recorded_depth,
        Felt::new_unchecked(17),
        "parent_stack_depth should be 17 (= pre-DYNCALL depth 18 minus 1)"
    );

    // Independently determine T1 (clock of push(0)) by scanning for all PUSH rows before DYNCALL.
    let push_opcode = Felt::from_u8(opcodes::PUSH);
    let push_rows_before_dyncall: Vec<_> = main
        .row_iter()
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
        "parent_next_overflow_addr must equal T1 (second-to-last overflow clock = {t1}); \
         T2 (top overflow clock = {t2}) would indicate the buggy path"
    );
}
