//! Range-check bus test.
//!
//! Verifies that every expected `RangeMsg` interaction fires at the right row, whether it
//! comes from a u32 stack op (decoder-side `user_op_helpers`) or a memory chiplet row (delta
//! limbs + word-address decomposition). The test is column-blind — since both call sites are
//! currently packed into different aux columns (M1 for u32rc, C2 for memory range checks),
//! the subset-based [`InteractionLog`] happens to pick up both without the test having to
//! know where each one landed.
//!
//! Covers the ground the pre-deletion `b_range_trace_stack` + `b_range_trace_mem` tests did,
//! minus the `b_range + v_wiring = 0` closure identity (no longer meaningful under the new
//! bus packing — cross-column closure is an AIR-side invariant, not something a processor
//! test should describe).

use alloc::vec::Vec;

use miden_air::{
    logup::RangeMsg,
    trace::{
        MainTrace, RANGE_CHECK_TRACE_OFFSET,
        chiplets::{MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX},
    },
};
use miden_core::{Felt, operations::Operation};
use miden_utils_testing::stack;

use super::{
    build_trace_from_ops,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::RowIndex;

/// `U32add` range-checks its four decoder helper columns: for `1 + 255 = 256`, the four
/// values are `{0, 256, 0, 0}`, so we expect exactly three removes of `RangeMsg { value: 0 }`
/// and one remove of `RangeMsg { value: 256 }` at the U32add row.
#[test]
fn u32_stack_op_emits_range_check_removes() {
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let u32add_row = find_op_row(main, miden_core::operations::opcodes::U32ADD);

    let mut exp = Expectations::new(&log);
    for i in 0..4 {
        let value = main.helper_register(i, u32add_row);
        exp.remove(usize::from(u32add_row), &RangeMsg { value });
    }

    assert_eq!(exp.count_removes(), 4, "expected 4 helper-register range-check removes");
    assert_eq!(exp.count_adds(), 0);
    log.assert_contains(&exp);
}

/// Two memory ops (`MStoreW` + `MLoadW`) on the same word address emit 5 `RangeMsg` removes
/// per memory chiplet row: `d0`, `d1` (the 16-bit delta limbs used for sorted-access
/// constraints) and `w0`, `w1`, `4·w1` (the word-address decomposition).
///
/// The address `262148 = 4 · 65537` is word-aligned with `word_index = 65537 = 0x10001`, so
/// `w0 = 1`, `w1 = 1`, `4·w1 = 4` — a non-trivial decomposition that exercises the full
/// five-way range-check batch.
#[test]
fn memory_chiplet_row_emits_range_check_removes() {
    let addr: u64 = 262148;
    let stack_input = stack![addr, 1, 2, 3, 4, addr];

    // MStoreW + 4×Drop + MLoadW, then 60 Noops so the memory chiplet segment does not overlap
    // with the range checker's table segment at the end of the chiplet trace.
    let mut operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    operations.resize(operations.len() + 60, Operation::Noop);
    let trace = build_trace_from_ops(operations, &stack_input);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect every memory chiplet row — we expect exactly two for the two memory ops.
    let mut mem_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if main.is_memory_row(idx) {
            mem_rows.push(idx);
        }
    }
    assert_eq!(mem_rows.len(), 2, "expected exactly two memory chiplet rows");

    let mut exp = Expectations::new(&log);
    for mem_row in &mem_rows {
        let row = usize::from(*mem_row);
        let d0 = main.get(*mem_row, MEMORY_D0_COL_IDX);
        let d1 = main.get(*mem_row, MEMORY_D1_COL_IDX);
        let w0 = main.chiplet_memory_word_addr_lo(*mem_row);
        let w1 = main.chiplet_memory_word_addr_hi(*mem_row);
        let four_w1 = w1 * Felt::from_u8(4);

        for value in [d0, d1, w0, w1, four_w1] {
            exp.remove(row, &RangeMsg { value });
        }
    }

    assert_eq!(exp.count_removes(), 5 * mem_rows.len(), "expected 5 RC removes per memory row");
    assert_eq!(exp.count_adds(), 0);
    log.assert_contains(&exp);
}

/// Every trace row carries the range-checker table's response: a `RangeMsg { value: v }` add
/// with runtime multiplicity `m`. This test verifies the per-row add side of the bus using
/// hardcoded request demand: a `U32add` requests 4 values (helper columns) and each chiplet
/// row with a range-check demand adds its `m` copies of that value to the bus.
///
/// Catches regressions where the range-checker add-back emitter misreads the multiplicity
/// column, the value column, or drops the always-active gate — bugs that the per-request
/// removes-only tests above cannot detect.
#[test]
fn range_checker_table_emits_per_row_adds() {
    // U32add issues 4 range-check requests for values {0, 256, 0, 0} on 1 + 255 = 256. The
    // range-checker chiplet will then add back four multiplicities of those values distributed
    // across its trace rows. We don't need to predict where — subset semantics lets us verify
    // that *every* row's add matches its `(m, v)` columns.
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    const M_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET;
    const V_COL_IDX: usize = RANGE_CHECK_TRACE_OFFSET + 1;

    let mut nonzero_mult_rows = 0usize;
    let mut exp = Expectations::new(&log);
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let m = main.get(idx, M_COL_IDX);
        let v = main.get(idx, V_COL_IDX);
        exp.push(row, m, &RangeMsg { value: v });
        if m != Felt::from_u8(0) {
            nonzero_mult_rows += 1;
        }
    }

    assert!(nonzero_mult_rows > 0, "range checker table is empty — test is vacuous");
    log.assert_contains(&exp);
}

fn find_op_row(main: &MainTrace, opcode: u8) -> RowIndex {
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if main.get_op_code(idx) == Felt::from_u8(opcode) {
            return idx;
        }
    }
    panic!("no row with opcode 0x{opcode:02x} in trace");
}
