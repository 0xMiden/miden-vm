use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, chiplets::hasher::HASH_CYCLE_LEN, range::B_RANGE_COL_IDX,
};
use miden_core::{ONE, Operation, ZERO, field::Field};
use miden_utils_testing::rand::rand_array;

use super::{Felt, build_trace_from_ops};

/// This test checks that range check lookups from stack operations are balanced by the range checks
/// processed in the Range Checker.
///
/// The `U32add` operation results in 4 16-bit range checks of 256, 0, 0, 0.
#[test]
fn b_range_trace_stack() {
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let alpha = rand_elements[0];
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();
    let b_range = aux_columns.get_column(B_RANGE_COL_IDX);

    assert_eq!(trace.length(), b_range.len());

    // --- Check the stack processor's range check lookups. ---------------------------------------

    // Before any range checks are executed, the value in b_range should be zero.
    assert_eq!(ZERO, b_range[0]);
    assert_eq!(ZERO, b_range[1]);

    // The first range check lookup from the stack will happen when the add operation is executed,
    // at cycle 1. (The trace begins by executing `span`). It must be subtracted out of `b_range`.
    // The range-checked values are 0, 256, 0, 0, so the values to subtract are 3/(alpha + 0) and
    // 1/(alpha + 256).
    let lookups = alpha.inverse() * Felt::new(3) + (alpha + Felt::new(256)).inverse();
    let mut expected = b_range[1] - lookups;
    assert_eq!(expected, b_range[2]);

    // --- Check the range checker's lookups. -----------------------------------------------------

    // 44 rows are needed for 0, 243, 252, 255, 256, ... 38 additional bridge rows of powers of
    // 3 ..., 65535. (0 and 256 are range-checked. 65535 is the max, and the rest are "bridge"
    // values.) An extra row is added to pad the u16::MAX value.
    let len_16bit = 44 + 1;
    // The start of the values in the range checker table.
    let values_start = trace.length() - len_16bit;

    // After the padded rows, the first value will be unchanged.
    assert_eq!(expected, b_range[values_start]);
    // We include 3 lookups of 0.
    expected += alpha.inverse() * Felt::new(3);
    assert_eq!(expected, b_range[values_start + 1]);
    // Then we have 3 bridge rows between 0 and 255 where the value does not change
    assert_eq!(expected, b_range[values_start + 2]);
    assert_eq!(expected, b_range[values_start + 3]);
    assert_eq!(expected, b_range[values_start + 4]);
    // Then we include 1 lookup of 256, so it should be multiplied by alpha + 256.
    expected += (alpha + Felt::new(256)).inverse();
    assert_eq!(expected, b_range[values_start + 5]);

    // --- Check the last value of the b_range column is zero --------------------------------------

    let last_row = b_range.len() - 1;
    assert_eq!(ZERO, b_range[last_row]);
}

/// This test checks that range check lookups from memory operations are balanced by the
/// range checks processed in the Range Checker.
///
/// The `StoreW` memory operation results in 2 16-bit range checks of 1, 0.
/// The `LoadW` memory operation results in 2 16-bit range checks of 5, 0.
#[test]
#[expect(clippy::needless_range_loop)]
fn b_range_trace_mem() {
    let stack = [0, 1, 2, 3, 4, 0];
    let operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    let trace = build_trace_from_ops(operations, &stack);

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let alpha = rand_elements[0];
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();
    let b_range = aux_columns.get_column(B_RANGE_COL_IDX);

    assert_eq!(trace.length(), b_range.len());

    // The memory section of the chiplets trace starts after the span hash.
    let memory_start = HASH_CYCLE_LEN;

    // 40 rows are needed for 0, 3, 4, ... 36 bridge additional bridge rows of powers of
    // 3  ..., 65535. (0 and 4 are both range-checked. 65535 is the max, and the rest are "bridge"
    // values.) An extra row is added to pad the u16::MAX value.
    let len_16bit = 40 + 1;
    let values_start = trace.length() - len_16bit;

    // The value should start at ZERO and be unchanged until the memory processor section begins.
    let mut expected = ZERO;
    for row in 0..memory_start {
        assert_eq!(expected, b_range[row]);
    }

    // --- Check the memory processor's range check lookups. --------------------------------------

    // There are two memory lookups. For each memory lookup, the context and address are unchanged,
    // so the delta values indicated the clock cycle change clk' - clk.
    // StoreW is executed at cycle 1 (after the initial span), so clk' - clk = 1.
    let (d0_store, d1_store) = (ONE, ZERO);
    // LoadW is executed at cycle 6, so i' - i = 6 - 1 = 5.
    let (d0_load, d1_load) = (Felt::new(5), ZERO);

    // Include the lookups from the `MStoreW` operation at the next row.
    expected -= (alpha + d0_store).inverse() + (alpha + d1_store).inverse();
    assert_eq!(expected, b_range[memory_start + 1]);
    // Include the lookup from the `MLoadW` operation at the next row.
    expected -= (alpha + d0_load).inverse() + (alpha + d1_load).inverse();
    assert_eq!(expected, b_range[memory_start + 2]);

    // The value should be unchanged until the range checker's lookups are included.
    for row in memory_start + 2..=values_start {
        assert_eq!(expected, b_range[row]);
    }

    // --- Check the range checker's lookups. -----------------------------------------------------

    // We include 2 lookups of ZERO in the next row.
    expected += alpha.inverse() * Felt::new(2);
    assert_eq!(expected, b_range[values_start + 1]);

    // We include 1 lookup of ONE in the next row.
    expected += (alpha + d0_store).inverse();
    assert_eq!(expected, b_range[values_start + 2]);

    // We have one bridge row between 1 and 5 where the value does not change.
    assert_eq!(expected, b_range[values_start + 3]);

    // We include 1 lookup of 5 in the next row.
    expected += (alpha + d0_load).inverse();
    assert_eq!(expected, b_range[values_start + 4]);

    // --- The value should now be ZERO for the rest of the trace. ---------------------------------
    assert_eq!(expected, ZERO);
    for i in (values_start + 4)..(b_range.len()) {
        assert_eq!(ZERO, b_range[i]);
    }
}
