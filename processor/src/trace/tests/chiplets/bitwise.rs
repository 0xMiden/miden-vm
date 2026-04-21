//! Bitwise chiplet bus test.
//!
//! Runs a program with `U32and` + `U32xor` operations and verifies that every bitwise request
//! row emits the expected `BitwiseMsg` on the chiplet-requests side AND that every bitwise
//! chiplet cycle-end row emits the matching `BitwiseResponseMsg` on the chiplet-responses side.
//!
//! Column-blind by design: the subset matcher in `lookup_harness` compares `(mult, denom)`
//! pairs regardless of which aux column the framework routes them onto.

use alloc::vec::Vec;

use miden_air::{
    logup_msg::{BitwiseMsg, BitwiseResponseMsg},
    trace::chiplets::BITWISE_SELECTOR_COL_IDX,
};
use miden_core::{
    Felt,
    operations::{Operation, opcodes},
};

use super::super::{
    build_trace_from_ops,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::RowIndex;

/// Period of the bitwise chiplet cycle. The response fires on the last row of each cycle.
const BITWISE_CYCLE_LEN: usize = 8;

#[test]
fn bitwise_chiplet_bus_emits_per_request_row() {
    // Two distinct operand pairs for the two AND requests so per-row denominators differ:
    // a copy-paste bug attaching an expectation to the wrong row can't pass the subset check.
    let a1: u32 = 0x1111_2222;
    let b1: u32 = 0x3333_4444;
    let a2: u32 = 0x5555_6666;
    let b2: u32 = 0x7777_8888;
    let a3: u32 = 0xdead_beef;
    let b3: u32 = 0x1234_5678;

    // `Drop` between ops isn't strictly required under subset semantics (extra pushes are
    // ignored), but it keeps the stack overflow table from growing and matches sibling tests.
    let ops = vec![
        Operation::Push(Felt::from_u32(a1)),
        Operation::Push(Felt::from_u32(b1)),
        Operation::U32and,
        Operation::Drop,
        Operation::Push(Felt::from_u32(a2)),
        Operation::Push(Felt::from_u32(b2)),
        Operation::U32and,
        Operation::Drop,
        Operation::Push(Felt::from_u32(a3)),
        Operation::Push(Felt::from_u32(b3)),
        Operation::U32xor,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(ops, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);

    // ---- Request side: decoder emits a `-1` push of `BitwiseMsg` at each U32AND/U32XOR row.
    //
    // Operands are hardcoded (not read back from the trace) so a bug that swaps `s0`/`s1` in
    // the request emitter would produce a message with the `a`/`b` fields flipped and fail
    // the subset check. The stack pushes `a` then `b`, so `b` ends up on top (`s0`) and `a`
    // sits at slot 1 (`s1`); `BitwiseMsg::and(s0, s1, c)` = `BitwiseMsg::and(b, a, a & b)`.
    let and_expected = [(a1, b1, a1 & b1), (a2, b2, a2 & b2)];
    let xor_expected = [(a3, b3, a3 ^ b3)];

    let mut and_rows: Vec<RowIndex> = Vec::new();
    let mut xor_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op == opcodes::U32AND as u64 {
            and_rows.push(idx);
        } else if op == opcodes::U32XOR as u64 {
            xor_rows.push(idx);
        }
    }
    assert_eq!(
        and_rows.len(),
        and_expected.len(),
        "request cardinality guardrail: expected {} U32AND rows, found {}",
        and_expected.len(),
        and_rows.len(),
    );
    assert_eq!(
        xor_rows.len(),
        xor_expected.len(),
        "request cardinality guardrail: expected {} U32XOR rows, found {}",
        xor_expected.len(),
        xor_rows.len(),
    );

    for (&row, &(a, b, c)) in and_rows.iter().zip(and_expected.iter()) {
        let msg = BitwiseMsg::and(Felt::from_u32(b), Felt::from_u32(a), Felt::from_u32(c));
        exp.remove(usize::from(row), &msg);
    }
    for (&row, &(a, b, c)) in xor_rows.iter().zip(xor_expected.iter()) {
        let msg = BitwiseMsg::xor(Felt::from_u32(b), Felt::from_u32(a), Felt::from_u32(c));
        exp.remove(usize::from(row), &msg);
    }

    // ---- Response side: each bitwise-chiplet cycle-end row emits `+1 × BitwiseResponseMsg`.
    //
    // Cycle-end = `row % BITWISE_CYCLE_LEN == BITWISE_CYCLE_LEN - 1` (the periodic `k_transition`
    // column is `0` on the last row of every 8-row cycle, starting from trace row 0). The bitwise
    // chiplet segment starts at a multiple of `HASH_CYCLE_LEN = 16`, which is a multiple of 8,
    // so this alignment condition holds across the whole trace.
    let mut response_rows_seen = 0usize;
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if !main.is_bitwise_row(idx) {
            continue;
        }
        if row % BITWISE_CYCLE_LEN != BITWISE_CYCLE_LEN - 1 {
            continue;
        }
        response_rows_seen += 1;

        let op = main.get(idx, BITWISE_SELECTOR_COL_IDX);
        let a = main.chiplet_bitwise_a(idx);
        let b = main.chiplet_bitwise_b(idx);
        let z = main.chiplet_bitwise_z(idx);
        exp.add(row, &BitwiseResponseMsg { op, a, b, z });
    }
    let expected_responses = and_expected.len() + xor_expected.len();
    assert_eq!(
        response_rows_seen, expected_responses,
        "response cardinality guardrail: expected {expected_responses} cycle-end bitwise rows, \
         found {response_rows_seen}",
    );

    log.assert_contains(&exp);
}
