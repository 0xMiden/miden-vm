use miden_air::trace::{
    ACE_CHIPLET_WIRING_BUS_OFFSET, AUX_TRACE_RAND_CHALLENGES, chiplets::hasher::HASH_CYCLE_LEN,
    range::B_RANGE_COL_IDX,
};
use miden_core::{ONE, ZERO, field::Field, operations::Operation};
use miden_utils_testing::{rand::rand_array, stack};

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

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
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
    let lookups = alpha.inverse() * Felt::from_u8(3) + (alpha + Felt::from_u16(256)).inverse();
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
    expected += alpha.inverse() * Felt::from_u8(3);
    assert_eq!(expected, b_range[values_start + 1]);
    // Then we have 3 bridge rows between 0 and 255 where the value does not change
    assert_eq!(expected, b_range[values_start + 2]);
    assert_eq!(expected, b_range[values_start + 3]);
    assert_eq!(expected, b_range[values_start + 4]);
    // Then we include 1 lookup of 256, so it should be multiplied by alpha + 256.
    expected += (alpha + Felt::from_u16(256)).inverse();
    assert_eq!(expected, b_range[values_start + 5]);

    // --- Check the last value of the b_range column is zero --------------------------------------

    let last_row = b_range.len() - 1;
    assert_eq!(ZERO, b_range[last_row]);
}

/// Tests that range check lookups from memory operations are balanced across `b_range` and
/// `v_wiring`.
///
/// ## Background
///
/// Each memory access produces two kinds of 16-bit range checks:
///
/// 1. **Delta checks** (`d0`, `d1`): the difference between consecutive memory rows is decomposed
///    into two 16-bit limbs. These are subtracted from `b_range` at the memory row and added back
///    by the range checker table.
///
/// 2. **Address decomposition checks** (`w0`, `w1`, `4*w1`): the word-aligned address is decomposed
///    as `word_index = word_addr / 4`, then `w0 = word_index & 0xFFFF` and `w1 = word_index >> 16`.
///    The three values `w0`, `w1`, `4*w1` are subtracted from the **wiring bus** (`v_wiring`) at
///    the memory row, and added back by the range checker table into `b_range`.
///
/// Because the address range checks are subtracted on `v_wiring` but their multiplicities are
/// added to `b_range`, neither column balances to zero on its own. The verifier checks the
/// combined identity: `b_range[last] + v_wiring[last] = 0`.
///
/// ## Test setup
///
/// We use `addr = 262148 = 4 * 65537` to ensure non-trivial address decomposition:
/// - `word_index = 65537 = 0x10001`
/// - `w0 = 1`, `w1 = 1`, `4*w1 = 4`
///
/// Two memory operations (MStoreW + MLoadW) at the same address produce 2 memory rows,
/// each contributing delta checks to `b_range` and address checks to `v_wiring`.
#[test]
fn b_range_trace_mem() {
    // =====================================================================
    // 1. BUILD THE TRACE
    // =====================================================================

    let addr: u64 = 262148;
    let stack_input = stack![addr, 1, 2, 3, 4, addr];

    let mut operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    // Pad with Noops so that the memory chiplet and range checker table sections don't overlap
    // in the trace, making it easier to reason about which rows contribute to which column.
    operations.resize(operations.len() + 60, Operation::Noop);
    let trace = build_trace_from_ops(operations, &stack_input);

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let alpha = rand_elements[0];
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();
    let b_range = aux_columns.get_column(B_RANGE_COL_IDX);
    let v_wiring = aux_columns.get_column(ACE_CHIPLET_WIRING_BUS_OFFSET);

    assert_eq!(trace.length(), b_range.len());

    // =====================================================================
    // 2. ADDRESS DECOMPOSITION
    // =====================================================================
    //
    // addr = 262148 is word-aligned (262148 % 4 == 0), so word_addr = 262148.
    // word_index = word_addr / 4 = 65537 = 0x10001.
    //
    //   w0    = word_index & 0xFFFF = 0x0001 = 1
    //   w1    = word_index >> 16    = 0x0001 = 1
    //   4*w1  = 4 * 1              = 4
    //
    // These are the three values whose range checks go through v_wiring.
    let w0 = ONE;
    let w1 = ONE;
    let four_w1 = Felt::from_u8(4);

    // =====================================================================
    // 3. DELTA VALUES
    // =====================================================================
    //
    // The memory trace has 2 rows (one per memory op), sorted by (ctx, word_addr, clk).
    // Both operations access the same (ctx=0, word_addr=262148), so the delta between
    // consecutive rows is just the clock cycle difference.
    //
    // Each delta is decomposed into two 16-bit limbs: d0 (low) and d1 (high).
    //
    // Memory row 0 (MStoreW, clk=1):
    //   The memory module initializes the virtual previous row to (same_ctx, same_addr,
    //   clk - 1), so the first row's delta is always 1 regardless of the actual address.
    //   delta = 1, d0 = 1, d1 = 0.
    let d0_store = ONE;
    let d1_store = ZERO;

    // Memory row 1 (MLoadW, clk=6):
    //   Delta from previous row: clk_load - clk_store = 6 - 1 = 5.
    //   d0 = 5, d1 = 0.
    let d0_load = Felt::from_u8(5);
    let d1_load = ZERO;

    // =====================================================================
    // 4. CHECK b_range: DELTA SUBTRACTIONS ON MEMORY ROWS
    // =====================================================================
    //
    // The hasher trace occupies the first 32 rows in total:
    // 16 rows for the padded controller region (2 controller rows + 14 padding) and
    // 16 rows for the packed permutation segment. The memory chiplet starts at row 32.
    let memory_start = 2 * HASH_CYCLE_LEN;

    // b_range starts at zero and stays zero until the first memory row.
    assert_eq!(ZERO, b_range[0]);

    // At memory row 0 (MStoreW): b_range subtracts the two delta LogUp fractions.
    //   b_range[mem+1] = b_range[mem] - 1/(alpha + d0_store) - 1/(alpha + d1_store)
    let store_delta_sub = (alpha + d0_store).inverse() + (alpha + d1_store).inverse();
    let mut expected_b_range = ZERO - store_delta_sub;
    assert_eq!(expected_b_range, b_range[memory_start + 1]);

    // At memory row 1 (MLoadW): b_range subtracts two more delta LogUp fractions.
    //   b_range[mem+2] = b_range[mem+1] - 1/(alpha + d0_load) - 1/(alpha + d1_load)
    let load_delta_sub = (alpha + d0_load).inverse() + (alpha + d1_load).inverse();
    expected_b_range -= load_delta_sub;
    assert_eq!(expected_b_range, b_range[memory_start + 2]);

    // =====================================================================
    // 5. CHECK END-TO-END BALANCE: b_range + v_wiring = 0
    // =====================================================================
    //
    // After the range checker table processes all rows, b_range has added back the
    // multiplicities for ALL range-checked values -- including the address decomposition
    // values (w0, w1, 4*w1) whose subtractions live on v_wiring, not b_range.

    let last_row = b_range.len() - 1;
    let b_range_final = b_range[last_row];
    let v_wiring_final = v_wiring[last_row];

    // Both columns should have non-zero residuals individually, since the address range
    // check contributions are split across them.
    assert_ne!(
        b_range_final, ZERO,
        "b_range should have a non-zero residual: the range table added w0/w1/4*w1 \
         multiplicities that are not cancelled by delta subtractions"
    );
    assert_ne!(
        v_wiring_final, ZERO,
        "v_wiring should have a non-zero residual: it subtracted w0/w1/4*w1 LogUp \
         fractions that are not added back on v_wiring itself"
    );

    // Verify the wiring bus residual matches the expected value.
    //   v_wiring_final = -4/(alpha + w0) - 2/(alpha + 4*w1)
    //                  = -4/(alpha + 1)  - 2/(alpha + 4)
    let num_memory_rows = Felt::from_u8(2);
    let w0_contribution = (alpha + w0).inverse() * num_memory_rows; // 2/(alpha+1) from w0
    let w1_contribution = (alpha + w1).inverse() * num_memory_rows; // 2/(alpha+1) from w1
    let four_w1_contribution = (alpha + four_w1).inverse() * num_memory_rows; // 2/(alpha+4) from 4*w1
    let expected_wiring_residual = -(w0_contribution + w1_contribution + four_w1_contribution);
    assert_eq!(
        v_wiring_final, expected_wiring_residual,
        "v_wiring residual should equal -(2/(alpha+w0) + 2/(alpha+w1) + 2/(alpha+4*w1))"
    );

    // Verify the end-to-end balance: b_range + v_wiring = 0.
    assert_eq!(
        b_range_final + v_wiring_final,
        ZERO,
        "b_range + v_wiring must balance to zero at the last row"
    );
}
