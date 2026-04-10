use miden_air::trace::{
    Challenges, RowIndex,
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
use miden_core::{WORD_SIZE, field::Field};

use super::{
    AUX_TRACE_RAND_CHALLENGES, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt, HASH_CYCLE_LEN,
    ONE, Operation, Word, ZERO, build_trace_from_ops, rand_array,
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

    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // At cycle 0 the span hash initialization is requested from the decoder and provided by the
    // hash chiplet, so the trace should still equal one.
    assert_eq!(ONE, b_chip[1]);

    // At row 1, two things happen simultaneously:
    // - The hasher provides the HOUT response (span hash result) at controller output row 1
    // - The stack sends the MStoreW memory write request (user op at cycle 1)
    // Extract the HOUT response as a black box.
    let mstore_value = build_expected_bus_word_msg(
        &challenges,
        MEMORY_WRITE_WORD_LABEL,
        ZERO,
        ZERO,
        ONE,
        word.into(),
    );
    // b_chip[2] = ONE * hout_response * mstore_value.inverse()
    let hout_response = b_chip[2] * mstore_value;
    let mut expected = hout_response * mstore_value.inverse();
    assert_eq!(expected, b_chip[2]);

    // Nothing changes after user operations that don't make requests to the Chiplets.
    for row in 3..7 {
        assert_eq!(expected, b_chip[row]);
    }

    // The next memory request from the stack is sent when `MLoad` is executed at cycle 6 and
    // included at row 7
    let value = build_expected_bus_element_msg(
        &challenges,
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
        &challenges,
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
        &challenges,
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
        &challenges,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        ZERO,
        Felt::new(13),
        word.into(),
    );
    let value2 = build_expected_bus_word_msg(
        &challenges,
        MEMORY_READ_WORD_LABEL,
        ZERO,
        Felt::new(4),
        Felt::new(13),
        [ONE, ZERO, ZERO, ZERO].into(),
    );
    expected *= (value1 * value2).inverse();
    assert_eq!(expected, b_chip[14]);

    // At cycle 14 the decoder requests the span hash result (END). In the controller/perm split,
    // the hasher already provided the HOUT response at row 1. The END request should cancel with
    // it. We capture the multiplicand as a black box.
    assert_ne!(expected, b_chip[15]);
    let span_end_mult = b_chip[15] * expected.inverse();
    expected = b_chip[15];

    // Verify the HOUT response and END request cancel.
    assert_eq!(hout_response * span_end_mult, ONE);

    // Nothing changes until the memory segment starts. The hasher contributes 32 total rows:
    // 16 rows for the padded controller region (2 controller rows + 14 padding) and 16 rows for
    // the packed permutation segment. No bitwise ops, so memory starts at row 32.
    let memory_start = 2 * HASH_CYCLE_LEN; // controller(16 padded) + perm(16)
    for row in 16..memory_start {
        assert_eq!(expected, b_chip[row]);
    }

    // Memory responses are provided during the memory segment after the hash cycle. There will be 6
    // rows, corresponding to the 5 memory operations (MStream requires 2 rows).

    // At cycle 8 `MLoadW` was requested by the stack; `MStoreW` is provided by memory here.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, memory_start.into());
    assert_eq!(expected, b_chip[memory_start + 1]);

    // At cycle 9, `MLoad` is provided by memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, (memory_start + 1).into());
    assert_eq!(expected, b_chip[memory_start + 2]);

    // At cycle 10,  `MLoadW` is provided by memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, (memory_start + 2).into());
    assert_eq!(expected, b_chip[memory_start + 3]);

    // At cycle 11, `MStore` is provided by the memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, (memory_start + 3).into());
    assert_eq!(expected, b_chip[memory_start + 4]);

    // At cycle 12, the first read of `MStream` is provided by the memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, (memory_start + 4).into());
    assert_eq!(expected, b_chip[memory_start + 5]);

    // At cycle 13, the second read of `MStream` is provided by the memory.
    expected *= build_expected_bus_msg_from_trace(&trace, &challenges, (memory_start + 5).into());
    assert_eq!(expected, b_chip[memory_start + 6]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (memory_start + 6)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

#[test]
fn crypto_stream_missing_chiplets_bus_requests() {
    // `crypto_stream` stack layout: [rate(8), cap(4), src_ptr, dst_ptr, ...]
    let stack = [
        1, 2, 3, 4, 5, 6, 7, 8, // rate(8)
        0, 0, 0, 0, // cap(4)
        0, // src_ptr
        8, // dst_ptr
        0, 0, // unused
    ];

    let trace = build_trace_from_ops(vec![Operation::CryptoStream], &stack);
    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::<Felt>::new(rand_challenges[0], rand_challenges[1]);

    // --- Assert exact bus requests for the four CryptoStream memory operations. ---

    // CryptoStream with src_ptr=0, dst_ptr=8, rate=[1..8], and uninitialized (zero) memory:
    //   - reads  word at addr 0: plaintext = [0, 0, 0, 0]
    //   - reads  word at addr 4: plaintext = [0, 0, 0, 0]
    //   - writes word at addr 8: ciphertext = plaintext + rate = [1, 2, 3, 4]
    //   - writes word at addr 12: ciphertext = [5, 6, 7, 8]
    let ctx = ZERO;
    let clk = ONE; // CryptoStream executes at cycle 1 (cycle 0 is SPAN)

    let read1 = build_expected_bus_word_msg(
        &challenges,
        MEMORY_READ_WORD_LABEL,
        ctx,
        ZERO, // src_ptr = 0
        clk,
        [ZERO, ZERO, ZERO, ZERO].into(),
    );
    let read2 = build_expected_bus_word_msg(
        &challenges,
        MEMORY_READ_WORD_LABEL,
        ctx,
        Felt::new(4), // src_ptr + 4
        clk,
        [ZERO, ZERO, ZERO, ZERO].into(),
    );
    let write1 = build_expected_bus_word_msg(
        &challenges,
        MEMORY_WRITE_WORD_LABEL,
        ctx,
        Felt::new(8), // dst_ptr = 8
        clk,
        [ONE, Felt::new(2), Felt::new(3), Felt::new(4)].into(),
    );
    let write2 = build_expected_bus_word_msg(
        &challenges,
        MEMORY_WRITE_WORD_LABEL,
        ctx,
        Felt::new(12), // dst_ptr + 4
        clk,
        [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into(),
    );

    // All four requests are emitted at the same cycle, so they multiply together.
    let combined_request = (read1 * read2 * write1 * write2).inverse();

    // b_chip[0] should be ONE. At cycle 0, span hash init request and response cancel.
    assert_eq!(ONE, b_chip[0]);
    assert_eq!(ONE, b_chip[1]);

    // At row 1, the hasher's HOUT response and the CryptoStream's 4 memory requests all occur.
    // Extract the HOUT response as a black box.
    let hout_response = b_chip[2] * combined_request.inverse();
    assert_eq!(hout_response * combined_request, b_chip[2]);

    // The chiplets bus should be balanced: final value must be ONE.
    assert_eq!(*b_chip.last().unwrap(), ONE);
}

// TEST HELPERS
// ================================================================================================

fn build_expected_bus_element_msg(
    challenges: &Challenges<Felt>,
    op_label: u8,
    ctx: Felt,
    addr: Felt,
    clk: Felt,
    value: Felt,
) -> Felt {
    assert!(op_label == MEMORY_READ_ELEMENT_LABEL || op_label == MEMORY_WRITE_ELEMENT_LABEL);

    challenges.encode([Felt::from_u8(op_label), ctx, addr, clk, value])
}

fn build_expected_bus_word_msg(
    challenges: &Challenges<Felt>,
    op_label: u8,
    ctx: Felt,
    addr: Felt,
    clk: Felt,
    word: Word,
) -> Felt {
    assert!(op_label == MEMORY_READ_WORD_LABEL || op_label == MEMORY_WRITE_WORD_LABEL);

    challenges.encode([Felt::from_u8(op_label), ctx, addr, clk, word[0], word[1], word[2], word[3]])
}

fn build_expected_bus_msg_from_trace(
    trace: &ExecutionTrace,
    challenges: &Challenges<Felt>,
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

        build_expected_bus_element_msg(challenges, op_label, ctx, addr, clk, word[idx as usize])
    } else if element_or_word == MEMORY_ACCESS_WORD {
        build_expected_bus_word_msg(challenges, op_label, ctx, addr, clk, word.into())
    } else {
        panic!("invalid element_or_word value: {element_or_word}");
    }
}
