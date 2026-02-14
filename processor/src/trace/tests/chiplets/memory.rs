use miden_air::trace::{
    RowIndex,
    chiplets::{
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
use miden_core::{
    WORD_SIZE,
    field::{Field, PrimeCharacteristicRing},
};

use super::{
    AUX_TRACE_RAND_ELEMENTS, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt, HASH_CYCLE_LEN,
    LAST_CYCLE_ROW, ONE, Operation, Word, ZERO, build_trace_from_ops, rand_array,
};
use crate::PrimeField64;

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

    let stack = [0, 1, 2, 3, 4];
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
    let mut expected = value.inverse();
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
    expected *= value.inverse();
    assert_eq!(expected, b_chip[7]);

    // Nothing changes until the next memory request from the stack: `MLoadW` executed at cycle 8
    // and included at row 9.
    let value = build_expected_bus_word_msg(
        &rand_elements,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        ZERO,
        Felt::new(8),
        word.into(),
    );
    expected *= value.inverse();
    assert_eq!(expected, b_chip[9]);

    // Nothing changes until the next memory request from the stack.
    assert_eq!(expected, b_chip[10]);

    // At cycle 11, `MStore` is requested by the stack and included at row 12.
    let value = build_expected_bus_element_msg(
        &rand_elements,
        MEMORY_WRITE_ELEMENT_LABEL,
        ZERO,
        FOUR,
        Felt::new(11),
        ONE,
    );
    expected *= value.inverse();
    assert_eq!(expected, b_chip[12]);

    // Nothing changes until the next memory request from the stack.
    assert_eq!(expected, b_chip[13]);

    // At cycle 13, `MStream` is requested by the stack, and the second read of `MStream` is
    // requested for inclusion at row 14.
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
    expected *= (value1 * value2).inverse();
    assert_eq!(expected, b_chip[14]);

    // At cycle 14 the decoder requests the span hash. Capture the multiplicand; the hasher responds
    // at the end of its cycle (row HASH_CYCLE_LEN).
    assert_ne!(expected, b_chip[15]);
    let span_request_mult = b_chip[15] * expected.inverse();
    expected = b_chip[15];

    // Nothing changes until the hasher provides the span hash result at the end of the hash cycle.
    for row in 16..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    let memory_start = HASH_CYCLE_LEN;
    assert_ne!(expected, b_chip[memory_start]);
    let span_response_mult = b_chip[memory_start] * b_chip[LAST_CYCLE_ROW].inverse();
    assert_eq!(span_request_mult * span_response_mult, ONE);
    expected *= span_response_mult;
    assert_eq!(expected, b_chip[memory_start]);

    // Memory responses are provided during the memory segment after the hash cycle. There will be 6
    // rows, corresponding to the 5 memory operations (MStream requires 2 rows).

    // At cycle 8 `MLoadW` was requested by the stack; `MStoreW` is provided by memory here.
    expected *= build_expected_bus_msg_from_trace(&trace, &rand_elements, memory_start.into());
    assert_eq!(expected, b_chip[memory_start + 1]);

    // At cycle 9, `MLoad` is provided by memory.
    expected *=
        build_expected_bus_msg_from_trace(&trace, &rand_elements, (memory_start + 1).into());
    assert_eq!(expected, b_chip[memory_start + 2]);

    // At cycle 10,  `MLoadW` is provided by memory.
    expected *=
        build_expected_bus_msg_from_trace(&trace, &rand_elements, (memory_start + 2).into());
    assert_eq!(expected, b_chip[memory_start + 3]);

    // At cycle 11, `MStore` is provided by the memory.
    expected *=
        build_expected_bus_msg_from_trace(&trace, &rand_elements, (memory_start + 3).into());
    assert_eq!(expected, b_chip[memory_start + 4]);

    // At cycle 12, the first read of `MStream` is provided by the memory.
    expected *=
        build_expected_bus_msg_from_trace(&trace, &rand_elements, (memory_start + 4).into());
    assert_eq!(expected, b_chip[memory_start + 5]);

    // At cycle 13, the second read of `MStream` is provided by the memory.
    expected *=
        build_expected_bus_msg_from_trace(&trace, &rand_elements, (memory_start + 5).into());
    assert_eq!(expected, b_chip[memory_start + 6]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (memory_start + 6)..trace.length() {
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
        + alphas[1] * Felt::from_u8(op_label)
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
        + alphas[1] * Felt::from_u8(op_label)
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

        word + idx1.double() + idx0
    };
    let clk = trace.main_trace.get_column(MEMORY_CLK_COL_IDX)[row];

    // get the memory value
    let mut word = [ZERO; WORD_SIZE];
    for (i, element) in word.iter_mut().enumerate() {
        *element = trace.main_trace.get_column(MEMORY_V_COL_RANGE.start + i)[row];
    }

    if element_or_word == MEMORY_ACCESS_ELEMENT {
        let idx1 = trace.main_trace.get_column(MEMORY_IDX1_COL_IDX)[row].as_canonical_u64();
        let idx0 = trace.main_trace.get_column(MEMORY_IDX0_COL_IDX)[row].as_canonical_u64();
        let idx = idx1 * 2 + idx0;

        build_expected_bus_element_msg(alphas, op_label, ctx, addr, clk, word[idx as usize])
    } else if element_or_word == MEMORY_ACCESS_WORD {
        build_expected_bus_word_msg(alphas, op_label, ctx, addr, clk, word.into())
    } else {
        panic!("invalid element_or_word value: {element_or_word}");
    }
}
