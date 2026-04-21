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
    Felt,
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
    let ops = vec![
        Operation::U32add, // no shift
        Operation::Pad,    // right shift
        Operation::Pad,    // right shift
        Operation::U32add, // no shift
        Operation::Drop,   // left shift
        Operation::Pad,    // right shift
        Operation::Drop,   // left shift
        Operation::Drop,   // left shift (overflow empty → no interaction)
        Operation::Drop,   // left shift (overflow empty → no interaction)
        Operation::Pad,    // right shift
        Operation::Drop,   // left shift
    ];
    let init_stack = (1..17).rev().collect::<Vec<u64>>();
    let trace = build_trace_from_ops(ops, &init_stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let next = RowIndex::from(row + 1);
        let op = main.get_op_code(idx);

        if op == Felt::from_u8(opcodes::PAD) {
            // Right shift: `add (clk, s15, b1)`.
            exp.add(
                row,
                &StackOverflowMsg {
                    clk: main.clk(idx),
                    val: main.stack_element(15, idx),
                    prev: main.parent_overflow_address(idx),
                },
            );
        } else if op == Felt::from_u8(opcodes::DROP) && main.is_non_empty_overflow(idx) {
            // Left shift with non-empty overflow: `remove (b1, s15', b1')`.
            exp.remove(
                row,
                &StackOverflowMsg {
                    clk: main.parent_overflow_address(idx),
                    val: main.stack_element(15, next),
                    prev: main.parent_overflow_address(next),
                },
            );
        }
    }

    log.assert_contains(&exp);
}
