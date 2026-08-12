//! Range-check bus tests.
//!
//! Verifies `RangeMsg` interactions from u32, Merkle, and memory operations. [`InteractionLog`]
//! collects messages across all auxiliary columns, so these tests do not depend on the current
//! column packing.

use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air::{
    CoreCols,
    logup::{HasherMsg, RangeMsg},
    trace::{
        MainTrace,
        chiplets::hasher::{
            CONTROLLER_ROWS_PER_PERM_FELT, MAX_MERKLE_DEPTH, MERKLE_DEPTH_RANGE_SCALE,
        },
    },
};
use miden_core::{
    Felt, Word, ZERO,
    crypto::merkle::{MerkleStore, SimpleSmt},
    field::PrimeCharacteristicRing,
    operations::{Operation, opcodes},
    utils::{Matrix, RowMajorMatrix},
};
use miden_utils_testing::{stack, stack_inputs_from_ints};

use super::{
    build_trace_from_ops, build_trace_from_ops_with_inputs,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::{AdviceInputs, RowIndex};

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

    let u32add_row = find_op_row(main, opcodes::U32ADD);
    let helper_values: [Felt; 4] = core::array::from_fn(|i| main.helper_register(i, u32add_row));
    assert_eq!(
        helper_values.iter().filter(|&&value| value == ZERO).count(),
        3,
        "expected three zero-valued helpers"
    );
    assert_eq!(
        helper_values.iter().filter(|&&value| value == Felt::from_u16(256)).count(),
        1,
        "expected one helper with value 256"
    );

    let mut exp = Expectations::new(&log);
    for value in helper_values {
        exp.remove(usize::from(u32add_row), &RangeMsg { value });
    }
    log.assert_contains(&exp);

    for value in helper_values {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced u32 range-check value {value}"
        );
    }
}

/// MPVERIFY at depth 1 and MRUPDATE at the supported maximum depth exercise both opcode gates and
/// both accepted endpoints. Besides checking the request interactions, this verifies that execution
/// replay adds both values to the range-check table with the expected multiplicities.
#[test]
fn merkle_ops_emit_depth_range_checks_at_accepted_boundaries() {
    let mpverify_trace = build_mpverify_trace::<1>();
    assert_merkle_depth_range_checks(&mpverify_trace, opcodes::MPVERIFY, 1);

    let mrupdate_trace = build_mrupdate_trace::<MAX_MERKLE_DEPTH>();
    assert_merkle_depth_range_checks(&mrupdate_trace, opcodes::MRUPDATE, MAX_MERKLE_DEPTH.into());
}

/// Mutate a real maximum-depth MPVERIFY row and verify that the forged value drives both the range
/// requests and the hasher return address. The honest tables cannot balance either request.
#[test]
fn forged_merkle_depths_emit_unbalanced_lookup_requests() {
    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>();

    let main = trace.main_trace();
    let op_row = find_op_row(main, opcodes::MPVERIFY);
    let helper0 = main.helper_register(0, op_row);
    let root = core::array::from_fn(|i| main.stack_element(6 + i, op_row));
    let (honest_core, chip_matrix, poseidon2_matrix) = main.to_air_matrices();
    let first_unsupported_depth = Felt::new_unchecked(u64::from(MAX_MERKLE_DEPTH) + 1);

    for forged_depth in [ZERO, first_unsupported_depth, Felt::NEG_ONE] {
        let mut forged_core = honest_core.clone();
        set_stack_element(&mut forged_core, op_row, 4, forged_depth);

        let log = InteractionLog::from_air_matrices(&forged_core, &chip_matrix, &poseidon2_matrix);
        let scaled_depth = (forged_depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE);
        let messages = [RangeMsg { value: forged_depth }, RangeMsg { value: scaled_depth }];
        let mut exp = Expectations::new(&log);
        for message in &messages {
            exp.remove(usize::from(op_row), message);
        }
        let return_addr = helper0 + forged_depth * CONTROLLER_ROWS_PER_PERM_FELT - Felt::ONE;
        let return_message = HasherMsg::return_hash(return_addr, root);
        exp.remove(usize::from(op_row), &return_message);
        log.assert_contains(&exp);
        for message in &messages {
            assert_eq!(log.net_multiplicity(message), -Felt::ONE);
        }
        assert_eq!(log.net_multiplicity(&return_message), -Felt::ONE);
    }
}

/// U32DIV uses four helper limbs for the quotient and remainder and two more for
/// `divisor - remainder - 1`. All six must reach the range-check bus, even though the final pair
/// is packed into a different lookup column.
#[test]
fn u32div_emits_all_range_check_removes() {
    let operations = vec![Operation::U32div, Operation::Drop, Operation::Drop, Operation::U32div];
    let trace = build_trace_from_ops(operations, &[0x0008_000b, 0x003b_0051, 3, 0x0003_0004]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let rows: Vec<RowIndex> = (0..main.core_height())
        .map(RowIndex::from)
        .filter(|&row| {
            main.get_op_code(row) == Felt::from_u8(miden_core::operations::opcodes::U32DIV)
        })
        .collect();
    assert_eq!(rows.len(), 2, "expected two U32DIV rows");

    // The first division has nonzero limbs for the remainder and its bound. The second has a
    // nonzero high quotient limb. Distinct values in the first row also expose limb swaps.
    let expected_helpers = [[7, 0, 4, 3, 6, 5], [1, 1, 1, 0, 1, 0]];
    let mut expected = Expectations::new(&log);
    for (row, expected_row) in rows.into_iter().zip(expected_helpers) {
        let helpers: [Felt; 6] = core::array::from_fn(|i| main.helper_register(i, row));
        assert_eq!(helpers, expected_row.map(Felt::new_unchecked));
        for value in helpers {
            expected.remove(usize::from(row), &RangeMsg { value });
        }
    }
    log.assert_contains(&expected);
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

    let operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    let trace = build_trace_from_ops(operations, &stack_input);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect every memory chiplet row — we expect exactly two for the two memory ops.
    let mut mem_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.chiplets_height() {
        let idx = RowIndex::from(row);
        if main.is_memory_row(idx) {
            mem_rows.push(idx);
        }
    }
    assert_eq!(mem_rows.len(), 2, "expected exactly two memory chiplet rows");

    let mut exp = Expectations::new(&log);
    let mut requested_values = Vec::with_capacity(5 * mem_rows.len());
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
            requested_values.push(value);
        }
    }

    log.assert_contains(&exp);
    for value in requested_values {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced memory range-check value {value}"
        );
    }
}

/// Every Core row carries the range table's response: a `RangeMsg { value: v }` add with runtime
/// multiplicity `m`. A `U32add` with inputs 1 and 255 provides known demand: three checks of 0 and
/// one check of 256.
///
/// This pins the raw per-row table interactions in addition to the aggregate bus-balance checks
/// above, catching a misread multiplicity or value column and a missing always-active gate.
#[test]
fn range_checker_table_emits_per_row_adds() {
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    assert_eq!(range_table_multiplicity(main, ZERO), 3);
    assert_eq!(range_table_multiplicity(main, Felt::from_u16(256)), 1);

    // Include zero-multiplicity rows: the table emitter is structurally active on every Core row.
    let mut exp = Expectations::new(&log);
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        let range = &main.core_row(idx).range;
        let m = range.multiplicity;
        let v = range.value;
        exp.push(row, m, &RangeMsg { value: v });
    }

    log.assert_contains(&exp);
}

// HELPERS
// ================================================================================================

fn find_op_row(main: &MainTrace, opcode: u8) -> RowIndex {
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        if main.get_op_code(idx) == Felt::from_u8(opcode) {
            return idx;
        }
    }
    panic!("no row with opcode 0x{opcode:02x} in trace");
}

fn assert_merkle_depth_range_checks(
    trace: &super::ExecutionTrace,
    opcode: u8,
    expected_depth: u16,
) {
    let log = InteractionLog::new(trace);
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcode);

    let depth = main.stack_element(4, op_row);
    assert_eq!(depth, Felt::from_u16(expected_depth));
    let scaled_depth = (depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE);

    let mut exp = Expectations::new(&log);
    exp.remove(usize::from(op_row), &RangeMsg { value: depth });
    exp.remove(usize::from(op_row), &RangeMsg { value: scaled_depth });
    log.assert_contains(&exp);

    // This program contains no other range-checking operations, so each requested value occurs
    // exactly once in the table.
    for value in [depth, scaled_depth] {
        assert_eq!(
            range_table_multiplicity(main, value),
            1,
            "unexpected range-table multiplicity for {value}"
        );
    }
}

fn range_table_multiplicity(main: &MainTrace, value: Felt) -> u64 {
    (0..main.core_height())
        .map(RowIndex::from)
        .filter_map(|row| {
            let range = &main.core_row(row).range;
            (range.value == value).then(|| range.multiplicity.as_canonical_u64())
        })
        .sum()
}

fn set_stack_element(
    core_matrix: &mut RowMajorMatrix<Felt>,
    row: RowIndex,
    stack_idx: usize,
    value: Felt,
) {
    let width = core_matrix.width();
    let start = usize::from(row) * width;
    let core_row: &mut CoreCols<Felt> = core_matrix.values[start..start + width].borrow_mut();
    core_row.stack.top[stack_idx] = value;
}

fn build_mpverify_trace<const DEPTH: u8>() -> super::ExecutionTrace {
    let value = test_word(7);
    let tree = SimpleSmt::<DEPTH>::with_leaves([(0, value)]).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(value));
    runtime_stack.push(DEPTH.into());
    runtime_stack.push(0);
    runtime_stack.extend(word_to_ints(tree.root()));

    build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(MerkleStore::from(&tree)),
    )
}

fn build_mrupdate_trace<const DEPTH: u8>() -> super::ExecutionTrace {
    let old_value = test_word(7);
    let new_value = test_word(11);
    let tree = SimpleSmt::<DEPTH>::with_leaves([(0, old_value)]).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(old_value));
    runtime_stack.push(DEPTH.into());
    runtime_stack.push(0);
    runtime_stack.extend(word_to_ints(tree.root()));
    runtime_stack.extend(word_to_ints(new_value));

    build_trace_from_ops_with_inputs(
        vec![Operation::MrUpdate],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(MerkleStore::from(&tree)),
    )
}

fn test_word(value: u64) -> Word {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

fn word_to_ints(word: Word) -> [u64; 4] {
    word.map(|value| value.as_canonical_u64())
}
