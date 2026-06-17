//! Range-check bus test.
//!
//! Verifies that every expected `RangeMsg` interaction fires at the right row, whether it
//! comes from a u32 stack op (decoder-side `user_op_helpers`) or a memory chiplet row (delta
//! limbs + word-address decomposition). The test is column-blind: the subset-based
//! [`InteractionLog`] picks up both call sites without the test having to know which aux column
//! carries each one.

use alloc::vec::Vec;

use miden_air::{
    logup::RangeMsg,
    trace::{
        MainTrace,
        and8_lookup::{NUM_AND8_LOOKUP_COLS, RANGE_CHECK_LOOKUP_COL},
    },
};
use miden_core::{Felt, operations::Operation, utils::Matrix};
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
/// constraints) and `w0`, `w1`, `4 * w1` (the word-address decomposition).
///
/// The address `262148 = 4 * 65537` is word-aligned with `word_index = 65537 = 0x10001`, so
/// `w0 = 1`, `w1 = 1`, `4 * w1 = 4` - a non-trivial decomposition that exercises the full
/// five-way range-check batch.
#[test]
fn memory_chiplet_row_emits_range_check_removes() {
    let addr: u64 = 262148;
    let stack_input = stack![addr, 1, 2, 3, 4, addr];

    // MStoreW + 4xDrop + MLoadW, followed by enough Noops to keep the memory-row checks
    // separated from the byte-pair table rows used later in this file.
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

    // Collect every memory chiplet row; we expect exactly two for the two memory ops.
    let mut mem_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.chiplets_height() {
        let idx = RowIndex::from(row);
        if main.is_memory_row(idx) {
            mem_rows.push(idx);
        }
    }
    assert_eq!(mem_rows.len(), 2, "expected exactly two memory chiplet rows");

    let mut exp = Expectations::new(&log);
    for mem_row in &mem_rows {
        let row = usize::from(*mem_row);
        let mem = main.chiplet_cols(*mem_row).memory();
        let d0 = mem.d0;
        let d1 = mem.d1;
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

/// Byte-pair rows with nonzero range-check multiplicity emit a `RangeMsg { value: v }` add with
/// runtime multiplicity `m`. This test verifies the table add side of the range-check bus.
///
/// Catches regressions where the byte-pair add-back emitter misreads the multiplicity column or
/// the `value = 256 * a + b` row mapping; bugs that the per-request removes-only tests
/// above cannot detect.
#[test]
fn range_checker_table_emits_per_row_adds() {
    // U32add issues 4 range-check requests for values {0, 256, 0, 0} on 1 + 255 = 256. The
    // byte-pair lookup AIR then adds back four multiplicities of those values from row 0 and row
    // 256. We scan all rows so the test also catches accidental extra nonzero range counts.
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let (_, _, _, and8_matrix) = trace.main_trace().to_air_matrices();

    let mut nonzero_mult_rows = 0usize;
    let mut exp = Expectations::new(&log);
    for row in 0..and8_matrix.height() {
        let m = and8_matrix.values[row * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL];
        if m != Felt::from_u8(0) {
            nonzero_mult_rows += 1;
            exp.push(row, m, &RangeMsg { value: Felt::from_u32(row as u32) });
        }
    }

    assert!(nonzero_mult_rows > 0, "range-check table side is empty - test is vacuous");
    log.assert_contains(&exp);
}

fn find_op_row(main: &MainTrace, opcode: u8) -> RowIndex {
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        if main.get_op_code(idx) == Felt::from_u8(opcode) {
            return idx;
        }
    }
    panic!("no row with opcode 0x{opcode:02x} in trace");
}
