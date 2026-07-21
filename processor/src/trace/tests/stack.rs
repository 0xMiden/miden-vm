//! Stack overflow table bus test.
//!
//! Runs a PAD/DROP sequence and verifies that every interaction the stack-overflow bus emitter
//! fires at a right-shift (`PAD`) or left-shift-with-non-empty-overflow (`DROP`) row appears
//! somewhere in that row's bag of prover pushes. The test is column-blind — see
//! `processor/src/trace/tests/lookup_harness.rs` for the subset matcher.
//!
//! The DYNCALL branch of the bus is intentionally not exercised here; constructing a DYNCALL
//! with a non-empty overflow requires a full program around a host and fits better in an
//! integration test.

use alloc::vec::Vec;

use miden_air::logup::StackOverflowMsg;
use miden_core::{
    Felt, ONE,
    field::PrimeCharacteristicRing,
    operations::{Operation, opcodes},
};

use super::{
    build_trace_from_ops,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::RowIndex;

#[test]
fn stack_overflow_bus_emits_per_interaction_row() {
    // Mix of right-shifts (PAD) and left-shifts (DROP) around a couple of U32add no-shift ops,
    // ending with the overflow table empty.
    // Overflow depth before each op (determines whether DROP emits):
    //   U32add:0 Pad:0→1 Pad:1→2 U32add:2 Drop:2→1 Pad:1→2 Drop:2→1 Drop:1→0 Drop:0 Pad:0→1
    // Drop:1→0 Four of the five DROPs run against a non-empty table and emit; the fourth DROP
    // sees overflow=0 and is a no-op. All four PADs emit.
    let ops = vec![
        Operation::U32add, // no shift
        Operation::Pad,    // right shift
        Operation::Pad,    // right shift
        Operation::U32add, // no shift
        Operation::Drop,   // left shift (overflow=2 → remove)
        Operation::Pad,    // right shift
        Operation::Drop,   // left shift (overflow=2 → remove)
        Operation::Drop,   // left shift (overflow=1 → remove)
        Operation::Drop,   // left shift (overflow=0 → no interaction)
        Operation::Pad,    // right shift
        Operation::Drop,   // left shift (overflow=1 → remove)
    ];
    let init_stack = (1..17).rev().collect::<Vec<u64>>();
    let trace = build_trace_from_ops(ops, &init_stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let op = main.core_row(idx).decoder.op_code();

        if op == Felt::from_u8(opcodes::PAD) {
            // Right shift: `add (clk, s15, b1)`.
            exp.add(
                row,
                &StackOverflowMsg {
                    clk: main.core_row(idx).system.clk,
                    val: main.core_row(idx).stack.get(15),
                    prev: main.core_row(idx).stack.b1,
                },
            );
        } else if op == Felt::from_u8(opcodes::DROP)
            && (main.core_row(idx).stack.b0 - Felt::from_u64(16)) * main.core_row(idx).stack.h0
                == ONE
        {
            // Left shift with non-empty overflow: `remove (b1, s15', b1')`.
            exp.remove(
                row,
                &StackOverflowMsg {
                    clk: main.core_row(idx).stack.b1,
                    val: main.core_row(next).stack.get(15),
                    prev: main.core_row(next).stack.b1,
                },
            );
        }
    }

    // 4 PADs and 4 DROPs-with-non-empty-overflow (only the lone DROP on an empty overflow
    // table emits nothing).
    assert_eq!(exp.count_adds(), 4, "expected one add per PAD");
    assert_eq!(exp.count_removes(), 4, "expected one remove per DROP with non-empty overflow");
    log.assert_contains(&exp);
}
