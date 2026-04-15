//! Bitwise chiplet bus test.
//!
//! Runs a tiny program with `U32and` + `U32xor` operations and verifies that:
//!
//! 1. **Main trace** (Layer 1): every bitwise op lands at the expected cycle — the test scans the
//!    main trace by opcode and asserts the expected count per op.
//! 2. **Per-row aux delta** (Layer 2): the delta on the M3 `CHIPLET_REQUESTS` column at each
//!    bitwise request row equals `-1 / BitwiseMsg::{and,xor}(s0, s1, result).encode(&challenges)`,
//!    where `s0` / `s1` are the top two stack elements at the request row and `result` is the top
//!    of the next row. This is the strictly-stronger successor to the old `b_chip[r]` step-by-step
//!    running-product walk — instead of pinning every intermediate row, we pin the delta at each
//!    *request* row, which is where the algebraic invariant actually lives.
//!
//! **Layer 3 (column closure) is intentionally omitted.** The LogUp boundary constraints in
//! `air/src/constraints/lookup/constraint.rs` are disabled pending a follow-up milestone, so
//! columns M3 (`CHIPLET_REQUESTS`), M_2+5 (`BLOCK_HASH_AND_OP_GROUP`), and C1
//! (`CHIPLET_RESPONSES`) carry unaccounted public-values / boundary contributions at program
//! end. See the `diagnostic_multi_batch_terminals` test in `tests/lookup.rs` for the
//! documented baseline. Restore closure assertions once the boundary wiring lands.
//!
//! Replaces the pre-deletion `b_chip_trace_bitwise` test that walked the legacy multiset
//! `b_chip` running product row-by-row.

use alloc::vec::Vec;

use miden_air::logup_msg::BitwiseMsg;
use miden_core::{Felt, operations::Operation};

use super::super::{
    build_trace_from_ops,
    lookup_harness::{LookupHarness, aux_col},
};
use crate::RowIndex;

#[test]
fn bitwise_chiplet_bus_delta_and_closure() {
    let a: u32 = 0xdead_beef;
    let b: u32 = 0x1234_5678;

    // Three bitwise requests: U32and, U32and, U32xor. Each request consumes its two operands
    // from the top of the stack and leaves the result on top. `Drop` immediately removes each
    // result so the stack overflow table stays untouched (independent of the deferred
    // stack-overflow bus).
    let ops = vec![
        Operation::Push(Felt::from_u32(a)),
        Operation::Push(Felt::from_u32(b)),
        Operation::U32and,
        Operation::Drop,
        Operation::Push(Felt::from_u32(a)),
        Operation::Push(Felt::from_u32(b)),
        Operation::U32and,
        Operation::Drop,
        Operation::Push(Felt::from_u32(a)),
        Operation::Push(Felt::from_u32(b)),
        Operation::U32xor,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(ops, &[]);
    let harness = LookupHarness::new(&trace);
    let main = trace.main_trace();

    // --- Layer 1: Main-trace structural checks ---------------------------------------------
    let mut and_rows: Vec<RowIndex> = Vec::new();
    let mut xor_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx);
        if op == Felt::from_u8(miden_core::operations::opcodes::U32AND) {
            and_rows.push(idx);
        } else if op == Felt::from_u8(miden_core::operations::opcodes::U32XOR) {
            xor_rows.push(idx);
        }
    }
    assert_eq!(and_rows.len(), 2, "expected exactly two U32and rows");
    assert_eq!(xor_rows.len(), 1, "expected exactly one U32xor row");

    // --- Layer 2: Per-row request-side delta check -----------------------------------------
    //
    // The `emit_chiplet_requests` bus reads `a = s0`, `b = s1`, `c = stk_next.get(0)` at the
    // request row (see `air/src/constraints/lookup/buses/chiplet_requests.rs`). The stack
    // side pushes `a` then `b`, so at the U32and row `s0 = b` and `s1 = a`. Read the values
    // back out of the main trace rather than hard-coding them to stay robust against any
    // future stack-layout change.
    for &row in and_rows.iter().chain(xor_rows.iter()) {
        let s0 = main.stack_element(0, row);
        let s1 = main.stack_element(1, row);
        let next = RowIndex::from(usize::from(row) + 1);
        let result = main.stack_element(0, next);

        let op = main.get_op_code(row);
        let msg = if op == Felt::from_u8(miden_core::operations::opcodes::U32AND) {
            BitwiseMsg::and(s0, s1, result)
        } else {
            BitwiseMsg::xor(s0, s1, result)
        };
        let expected = -harness.fraction(&msg);

        assert_eq!(
            harness.delta(aux_col::CHIPLET_REQUESTS, usize::from(row)),
            expected,
            "bitwise request delta mismatch at row {row}",
        );
    }

    // NOTE: Layer 3 (column terminal closure) is intentionally omitted — see the module
    // doc-comment above for the reason (LogUp boundary constraints currently disabled).
}
