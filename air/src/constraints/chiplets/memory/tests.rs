use alloc::vec::Vec;

use miden_core::{Felt, FieldElement, WORD_SIZE};
use winter_rand_utils::rand_value;

use super::{
    EvaluationFrame, MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX, MEMORY_D_INV_COL_IDX,
    MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX, MEMORY_V_COL_RANGE, MEMORY_WORD_COL_IDX,
};
use crate::{
    ONE, ZERO,
    chiplets::memory,
    trace::{
        TRACE_WIDTH,
        chiplets::{
            MEMORY_FLAG_SAME_CONTEXT_AND_WORD, MEMORY_IDX0_COL_IDX, MEMORY_IDX1_COL_IDX,
            MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX,
            memory::{MEMORY_ACCESS_WORD, MEMORY_READ, MEMORY_WRITE},
        },
    },
};

// UNIT TESTS
// ================================================================================================

#[test]
fn test_memory_write() {
    let expected_constraint_evals = [ZERO; memory::NUM_CONSTRAINTS];

    let old_word = vec![0, 0, 0, 0];
    let new_word = vec![1, 0, 0, 0];

    // Write to a new context.
    let result =
        get_constraint_evaluation(MEMORY_WRITE, MemoryTestDeltaType::Context, &old_word, &new_word);
    assert_eq!(expected_constraint_evals, result);

    // Write to a new address in the same context.
    let result =
        get_constraint_evaluation(MEMORY_WRITE, MemoryTestDeltaType::Word, &old_word, &new_word);
    assert_eq!(expected_constraint_evals, result);

    // Write to the same context and address at a new clock cycle.
    let result =
        get_constraint_evaluation(MEMORY_WRITE, MemoryTestDeltaType::Clock, &old_word, &new_word);
    assert_eq!(expected_constraint_evals, result);
}

#[test]
fn test_memory_read() {
    let expected = [ZERO; memory::NUM_CONSTRAINTS];

    let init_values = vec![0, 0, 0, 0];
    let old_values = vec![1, 0, 0, 0];

    // Read from a new context.
    let result = get_constraint_evaluation(
        MEMORY_READ,
        MemoryTestDeltaType::Context,
        &old_values,
        &init_values,
    );
    assert_eq!(expected, result);

    // Read from a new address in the same context.
    let result = get_constraint_evaluation(
        MEMORY_READ,
        MemoryTestDeltaType::Word,
        &old_values,
        &init_values,
    );
    assert_eq!(expected, result);

    // Read from the same context and address at a new clock cycle.
    let result = get_constraint_evaluation(
        MEMORY_READ,
        MemoryTestDeltaType::Clock,
        &old_values,
        &old_values,
    );
    assert_eq!(expected, result);
}

// TEST HELPERS
// ================================================================================================

/// Specifies the column where the delta should occur in a memory test frame.
/// - Context: when the delta is in context, the address and clock columns can also change.
/// - Address: when the delta occurs in the address, context must stay fixed, but clock can change.
/// - Clock: when the delta occurs in the clock column, context and address must stay fixed.
enum MemoryTestDeltaType {
    Context,
    Word,
    Clock,
}

/// Generates a frame that reads or writes memory with the specified old and new values and a change
/// in the  specified column (context, address, or clock), then returns the evaluation of the memory
/// constraints on this frame.
///
/// - To test a valid write, the MemoryTestDeltaType must be Context or Address and the `old_values`
///   and `new_values` must change.
/// - To test a valid read, the `delta_type` must be Clock and the `old_values` and `new_values`
///   must be equal.
fn get_constraint_evaluation(
    read_write: Felt,
    delta_type: MemoryTestDeltaType,
    old_values: &[u32],
    new_values: &[u32],
) -> [Felt; memory::NUM_CONSTRAINTS] {
    let delta_row = get_test_delta_row(&delta_type);
    let frame = get_test_frame(read_write, &delta_type, &delta_row, old_values, new_values);

    let mut result = [ZERO; memory::NUM_CONSTRAINTS];

    memory::enforce_constraints(&frame, &mut result, ONE, ONE, ZERO);

    result
}

/// Generates an EvaluationFrame with memory trace data as specified by the inputs. The frame treats
/// the current row as the first row of a memory execution trace with context, address, clock, old
/// values, delta (d1, d0), and delta inverse set to zero. The provided inputs determine the values
/// in the next row and therefore the transition from current to next. The generated frame will be
/// valid when valid inputs are provided.
///
/// - `selectors`: specifies the memory operation selectors in the next row which is being tested.
/// - `delta_type`: specifies the column over which the delta value should be calculated.
/// - `delta_row`: specifies the values of the context, address, and clock columns in the next row.
/// - `old_values`: specifies the old values, which are placed in the value columns of the current
///   row.
/// - `new_values`: specifies the new values, which are placed in the value columns of the next row.
fn get_test_frame(
    read_write: Felt,
    delta_type: &MemoryTestDeltaType,
    delta_row: &[u64],
    old_values: &[u32],
    new_values: &[u32],
) -> EvaluationFrame<Felt> {
    let mut current = vec![ZERO; TRACE_WIDTH];
    let mut next = vec![ZERO; TRACE_WIDTH];

    // Set the operation in the next row.
    next[MEMORY_IS_READ_COL_IDX] = read_write;
    next[MEMORY_IS_WORD_ACCESS_COL_IDX] = MEMORY_ACCESS_WORD;

    // Set the context, addr, and clock columns in the next row to the values in the delta row.
    next[MEMORY_CTX_COL_IDX] = Felt::new(delta_row[0]);
    next[MEMORY_WORD_COL_IDX] = Felt::new(delta_row[1]);
    next[MEMORY_CLK_COL_IDX] = Felt::new(delta_row[2]);

    // Set the old and new values.
    for idx in 0..WORD_SIZE {
        let old_value = Felt::new(old_values[idx] as u64);
        // Add a write for the old values to the current row.
        current[MEMORY_V_COL_RANGE.start + idx] = old_value;
        // Change the values from old to new in the next row.
        next[MEMORY_V_COL_RANGE.start + idx] = Felt::new(new_values[idx] as u64);
    }

    // Set the delta and delta inverse values. Treat the current row as if it's the first row.
    current[MEMORY_D0_COL_IDX] = ZERO;
    current[MEMORY_D1_COL_IDX] = ZERO;
    current[MEMORY_D_INV_COL_IDX] = ZERO;

    // Set the delta in the next row according to the specified delta type.
    let delta: u64 = match delta_type {
        MemoryTestDeltaType::Clock => delta_row[MemoryTestDeltaType::Clock as usize],
        MemoryTestDeltaType::Context => delta_row[MemoryTestDeltaType::Context as usize],
        MemoryTestDeltaType::Word => delta_row[MemoryTestDeltaType::Word as usize],
    };
    next[MEMORY_D0_COL_IDX] = Felt::new(delta as u16 as u64);
    next[MEMORY_D1_COL_IDX] = Felt::new(delta >> 16);
    next[MEMORY_D_INV_COL_IDX] = (Felt::new(delta)).inv();

    // since we're always writing a word, the idx0 and idx1 columns should be zero
    next[MEMORY_IDX0_COL_IDX] = ZERO;
    next[MEMORY_IDX1_COL_IDX] = ZERO;

    // If the context or word columns are changed, the "same context and word" flag should be
    // zero.
    if delta_row[MemoryTestDeltaType::Word as usize] > 0
        || delta_row[MemoryTestDeltaType::Context as usize] > 0
    {
        next[MEMORY_FLAG_SAME_CONTEXT_AND_WORD] = ZERO;
    } else {
        next[MEMORY_FLAG_SAME_CONTEXT_AND_WORD] = ONE;
    }

    EvaluationFrame::<Felt>::from_rows(current, next)
}

/// Generates a row of valid test values for the context, word, and clock columns according to
/// the specified delta type, which determines the column over which the delta and delta inverse
/// values of the trace would be calculated.
///
/// - When the delta type is Context, the word and clock columns can be anything.
/// - When the delta type is Word, the context must remain unchanged but the clock can change.
/// - When the delta type is Clock, both the context and word columns must remain unchanged.
fn get_test_delta_row(delta_type: &MemoryTestDeltaType) -> Vec<u64> {
    let delta_value = word_aligned_rand_value() as u64;
    let mut row = vec![0; 3];
    let ctx_idx = MemoryTestDeltaType::Context as usize;
    let word_addr_idx = MemoryTestDeltaType::Word as usize;
    let clk_idx = MemoryTestDeltaType::Clock as usize;

    // Set the context, addr, and clock columns according to the specified delta type.
    match delta_type {
        MemoryTestDeltaType::Context => {
            // Change the row value for the context.
            row[ctx_idx] = delta_value;

            // Set addr and clock in the row column to random values.
            row[word_addr_idx] = word_aligned_rand_value() as u64;
            row[clk_idx] = rand_value::<u32>() as u64;
        },
        MemoryTestDeltaType::Word => {
            // Keep the context value the same in current and row rows (leave it as ZERO).
            // Set the row value for the address.
            row[word_addr_idx] = delta_value;

            // Set clock in the row column to a random value.
            row[clk_idx] = rand_value::<u32>() as u64;
        },
        MemoryTestDeltaType::Clock => {
            // Keep the context and address values the same in the current and row rows.
            // Set the current and row values for the clock.
            row[clk_idx] = delta_value;
        },
    }

    row
}

/// Returns a random value that is divisible by 4 (i.e. "word aligned" when treated as an address).
fn word_aligned_rand_value() -> u32 {
    let value = rand_value::<u32>();
    value - (value % 4)
}
