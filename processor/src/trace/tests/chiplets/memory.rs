use miden_air::{
    RowIndex,
    trace::chiplets::{
        MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX, MEMORY_IDX0_COL_IDX, MEMORY_IDX1_COL_IDX,
        MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX, MEMORY_V_COL_RANGE,
        MEMORY_WORD_COL_IDX,
        memory::{
            MEMORY_ACCESS_ELEMENT, MEMORY_ACCESS_WORD, MEMORY_READ, MEMORY_READ_ELEMENT_LABEL,
            MEMORY_READ_WORD_LABEL, MEMORY_WRITE, MEMORY_WRITE_ELEMENT_LABEL,
            MEMORY_WRITE_WORD_LABEL,
        },
    },
};
use miden_core::WORD_SIZE;

use super::{
    AUX_TRACE_RAND_ELEMENTS, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt, FieldElement,
    NUM_RAND_ROWS, ONE, Operation, Trace, Word, ZERO, build_trace_from_ops, rand_array,
};

/// Tests the generation of the `b_chip` bus column when only memory lookups are included. It
/// ensures that trace generation is correct when all of the following are true.
///
/// - All possible memory operations are called by the stack.
/// - Some requests from the Stack and responses from Memory occur at the same cycle.
/// - Multiple memory addresses are used.
///
/// Note: Communication with the Hash chiplet is also required, due to the span block decoding, but
/// for this test we set those values explicitly, enforcing only that the same initial and final
/// values are requested & provided.
#[test]
#[expect(clippy::needless_range_loop)]
fn b_chip_trace_mem() {
    const FOUR: Felt = Felt::new(4);

    let stack = [1, 2, 3, 4, 0];
    let word = [ONE, Felt::new(2), Felt::new(3), Felt::new(4)];
    let operations = vec![
        Operation::MStoreW, // store [1, 2, 3, 4]
        Operation::Drop,    // clear the stack
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoad,      // read the first value of the word
        Operation::MovDn5,     // put address 0 and space for a full word at top of stack
        Operation::MLoadW,     // load word from address 0 to stack
        Operation::Push(ONE),  // push a new value onto the stack
        Operation::Push(FOUR), // push a new address on to the stack
        Operation::MStore,     // store 1 at address 4
        Operation::Drop,       // ensure the stack overflow table is empty
        Operation::MStream,    // read 2 words starting at address 0
    ];
    let trace = build_trace_from_ops(operations, &stack);

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // At cycle 0 the span hash initialization is requested from the decoder and provided by the
    // hash chiplet, so the trace should still equal one.
    assert_eq!(ONE, b_chip[1]);

    // The first memory request from the stack is sent when the `MStoreW` operation is executed, at
    // cycle 1, so the request is included in the next row. (The trace begins by executing `span`).
    let value = build_expected_bus_word_msg(
        &rand_elements,
        MEMORY_WRITE_WORD_LABEL,
        ZERO,
        ZERO,
        ONE,
        word.into(),
    );
    let mut expected = value.inv();
    assert_eq!(expected, b_chip[2]);

    // Nothing changes after user operations that don't make requests to the Chiplets.
    for row in 3..7 {
        assert_eq!(expected, b_chip[row]);
    }

    // The next memory request from the stack is sent when `MLoad` is executed at cycle 6 and
    // included at row 7
    let value = build_expected_bus_element_msg(
        &rand_elements,
        MEMORY_READ_ELEMENT_LABEL,
        ZERO,
        ZERO,
        Felt::new(6),
        word[0],
    );
    expected *= value.inv();
    assert_eq!(expected, b_chip[7]);

    // At cycle 7 the hasher provides the result of the `SPAN` hash. Since this test is for changes
    // from memory lookups, just set it explicitly and save the multiplied-in value for later.
    assert_ne!(expected, b_chip[8]);
    let span_result = b_chip[8] * b_chip[7].inv();
    expected = b_chip[8];

    // Memory responses will be provided during the memory segment of the Chiplets trace,
    // which starts after the hash for the span block at row 8. There will be 6 rows, corresponding
    // to the 5 memory operations (MStream requires 2 rows).

    // At cycle 8 `MLoadW` is requested by the stack and `MStoreW` is provided by memory
    let value = build_expected_bus_word_msg(
        &rand_elements,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        ZERO,
        Felt::new(8),
        word.into(),
    );
    expected *= value.inv();
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 8.into());
    assert_eq!(expected, b_chip[9]);

    // At cycle 9, `MLoad` is provided by memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 9.into());
    assert_eq!(expected, b_chip[10]);

    // At cycle 10,  `MLoadW` is provided by memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 10.into());
    assert_eq!(expected, b_chip[11]);

    // At cycle 11, `MStore` is requested by the stack and the first read of `MStream` is provided
    // by the memory.
    let value = build_expected_bus_element_msg(
        &rand_elements,
        MEMORY_WRITE_ELEMENT_LABEL,
        ZERO,
        FOUR,
        Felt::new(11),
        ONE,
    );
    expected *= value.inv();
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 11.into());
    assert_eq!(expected, b_chip[12]);

    // At cycle 12, `MStore` is provided by the memory
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 12.into());
    assert_eq!(expected, b_chip[13]);

    // At cycle 13, `MStream` is requested by the stack, and the second read of `MStream` is
    // provided by the memory.
    let value1 = build_expected_bus_word_msg(
        &rand_elements,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        ZERO,
        Felt::new(13),
        word.into(),
    );
    let value2 = build_expected_bus_word_msg(
        &rand_elements,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        Felt::new(4),
        Felt::new(13),
        [ONE, ZERO, ZERO, ZERO].into(),
    );
    expected *= (value1 * value2).inv();
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, 13.into());
    assert_eq!(expected, b_chip[14]);

    // At cycle 14 the decoder requests the span hash. We set this as the inverse of the previously
    // identified `span_result`, since this test is for consistency of the memory lookups.
    assert_ne!(expected, b_chip[15]);
    expected *= span_result.inv();
    assert_eq!(expected, b_chip[15]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in 15..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

// TEST HELPERS
// ================================================================================================

fn build_expected_bus_element_msg(
    alphas: &[Felt],
    op_label: u8,
    ctx: Felt,
    addr: Felt,
    clk: Felt,
    value: Felt,
) -> Felt {
    assert!(op_label == MEMORY_READ_ELEMENT_LABEL || op_label == MEMORY_WRITE_ELEMENT_LABEL);

    alphas[0]
        + alphas[1] * Felt::from(op_label)
        + alphas[2] * ctx
        + alphas[3] * addr
        + alphas[4] * clk
        + alphas[5] * value
}

fn build_expected_bus_word_msg(
    alphas: &[Felt],
    op_label: u8,
    ctx: Felt,
    addr: Felt,
    clk: Felt,
    word: Word,
) -> Felt {
    assert!(op_label == MEMORY_READ_WORD_LABEL || op_label == MEMORY_WRITE_WORD_LABEL);

    alphas[0]
        + alphas[1] * Felt::from(op_label)
        + alphas[2] * ctx
        + alphas[3] * addr
        + alphas[4] * clk
        + alphas[5] * word[0]
        + alphas[6] * word[1]
        + alphas[7] * word[2]
        + alphas[8] * word[3]
}

fn build_expected_bus_msg_from_trace(
    trace: &ExecutionTrace,
    alphas: &[Felt],
    row: RowIndex,
) -> Felt {
    // get the memory access operation
    let read_write = trace.main_trace.get_column(MEMORY_IS_READ_COL_IDX)[row];
    let element_or_word = trace.main_trace.get_column(MEMORY_IS_WORD_ACCESS_COL_IDX)[row];
    let op_label = if read_write == MEMORY_WRITE {
        if element_or_word == MEMORY_ACCESS_ELEMENT {
            MEMORY_WRITE_ELEMENT_LABEL
        } else {
            MEMORY_WRITE_WORD_LABEL
        }
    } else if read_write == MEMORY_READ {
        if element_or_word == MEMORY_ACCESS_ELEMENT {
            MEMORY_READ_ELEMENT_LABEL
        } else {
            MEMORY_READ_WORD_LABEL
        }
    } else {
        panic!("invalid read_write value: {read_write}");
    };

    // get the memory access data
    let ctx = trace.main_trace.get_column(MEMORY_CTX_COL_IDX)[row];
    let addr = {
        let word = trace.main_trace.get_column(MEMORY_WORD_COL_IDX)[row];
        let idx1 = trace.main_trace.get_column(MEMORY_IDX1_COL_IDX)[row];
        let idx0 = trace.main_trace.get_column(MEMORY_IDX0_COL_IDX)[row];

        word + idx1.mul_small(2) + idx0
    };
    let clk = trace.main_trace.get_column(MEMORY_CLK_COL_IDX)[row];

    // get the memory value
    let mut word = [ZERO; WORD_SIZE];
    for (i, element) in word.iter_mut().enumerate() {
        *element = trace.main_trace.get_column(MEMORY_V_COL_RANGE.start + i)[row];
    }

    if element_or_word == MEMORY_ACCESS_ELEMENT {
        let idx1 = trace.main_trace.get_column(MEMORY_IDX1_COL_IDX)[row].as_int();
        let idx0 = trace.main_trace.get_column(MEMORY_IDX0_COL_IDX)[row].as_int();
        let idx = idx1 * 2 + idx0;

        build_expected_bus_element_msg(alphas, op_label, ctx, addr, clk, word[idx as usize])
    } else if element_or_word == MEMORY_ACCESS_WORD {
        build_expected_bus_word_msg(alphas, op_label, ctx, addr, clk, word.into())
    } else {
        panic!("invalid element_or_word value: {element_or_word}");
    }
}
