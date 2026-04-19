use miden_air::trace::{
    Challenges, RowIndex,
    chiplets::{
        BITWISE_A_COL_IDX, BITWISE_B_COL_IDX, BITWISE_OUTPUT_COL_IDX, BITWISE_TRACE_OFFSET,
        bitwise::{BITWISE_AND, BITWISE_AND_LABEL, BITWISE_XOR, BITWISE_XOR_LABEL, OP_CYCLE_LEN},
    },
};
use miden_core::field::Field;

use super::{
    AUX_TRACE_RAND_CHALLENGES, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt, HASH_CYCLE_LEN,
    ONE, Operation, build_trace_from_ops, rand_array, rand_value,
};

/// Tests the generation of the `b_chip` bus column when only bitwise lookups are included. It
/// ensures that trace generation is correct when all of the following are true.
///
/// - All possible bitwise operations are called by the stack.
/// - Some requests from the Stack and responses from the Bitwise chiplet occur at the same cycle.
///
/// Note: Communication with the Hash chiplet is also required, due to the span block decoding, but
/// for this test we set those values explicitly, enforcing only that the same initial and final
/// values are requested & provided.
#[test]
fn b_chip_trace_bitwise() {
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let stack = [a as u64, b as u64];
    let operations = vec![
        Operation::U32and,
        Operation::Push(Felt::from_u32(a)),
        Operation::Push(Felt::from_u32(b)),
        Operation::U32and,
        // Add 8 padding operations so that U32xor is requested by the stack in the same cycle when
        // U32and is provided by the Bitwise chiplet.
        Operation::Pad,
        Operation::Pad,
        Operation::Pad,
        Operation::Pad,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Push(Felt::from_u32(a)),
        Operation::Push(Felt::from_u32(b)),
        Operation::U32xor,
        // Drop 4 values to empty the stack's overflow table.
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(operations, &stack);

    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // At cycle 0 the span hash initialization is requested from the decoder and provided by the
    // hasher (both at main trace row 0), so they cancel and b_chip stays ONE.
    assert_eq!(ONE, b_chip[1]);

    // At row 1, two things happen simultaneously:
    // - The hasher provides the HOUT response (span hash result) at controller output row 1
    // - The decoder sends the first U32and bitwise request (user op at cycle 1)
    // We treat the HOUT response as a black box and extract it from the bus column.
    let bitwise_1_value = build_expected_bitwise(
        &challenges,
        BITWISE_AND_LABEL,
        Felt::from_u32(a),
        Felt::from_u32(b),
        Felt::from_u32(a & b),
    );
    // b_chip[2] = ONE * hout_response * bitwise_1.inverse()
    // so hout_response = b_chip[2] * bitwise_1
    let hout_response = b_chip[2] * bitwise_1_value;
    let mut expected = hout_response * bitwise_1_value.inverse();
    assert_eq!(expected, b_chip[2]);

    // Nothing changes during user operations with no requests to the Chiplets.
    for row in 3..5 {
        assert_eq!(expected, b_chip[row]);
    }

    // The second bitwise request from the stack is sent when the `U32and` operation is executed at
    // cycle 4, so the request is included in the next row.
    let value = build_expected_bitwise(
        &challenges,
        BITWISE_AND_LABEL,
        Felt::from_u32(b),
        Felt::from_u32(a),
        Felt::from_u32(a & b),
    );
    expected *= value.inverse();
    assert_eq!(expected, b_chip[5]);

    // Nothing changes during user operations with no requests to the Chiplets.
    for row in 6..16 {
        assert_eq!(expected, b_chip[row]);
    }

    // The third bitwise request from the stack is sent when the `U32xor` operation is executed at
    // cycle 15, so the request is included in the next row.
    let value = build_expected_bitwise(
        &challenges,
        BITWISE_XOR_LABEL,
        Felt::from_u32(b),
        Felt::from_u32(a),
        Felt::from_u32(a ^ b),
    );
    expected *= value.inverse();
    assert_eq!(expected, b_chip[16]);

    // Nothing changes until the decoder requests the result of the `SPAN` hash at cycle 21.
    for row in 17..22 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 21 the decoder requests the span hash result (END). This should cancel with the
    // HOUT response that was provided earlier at row 1.
    assert_ne!(expected, b_chip[22]);
    let span_end_request = b_chip[22] * b_chip[21].inverse();
    expected *= span_end_request;
    assert_eq!(expected, b_chip[22]);
    // Verify the HOUT response and END request cancel.
    assert_eq!(hout_response * span_end_request, ONE);

    // The hasher trace in the dispatch/compute split has:
    // - Hasher controller rows 0-1 (already processed above)
    // - Hasher padding rows 2-31 (selectors [0,1,0] = neither input nor output, no bus activity)
    // - Hasher permutation segment rows 32-63 (no bus activity on chiplets bus)
    // So nothing changes until the bitwise segment.
    let hasher_trace_len = 2 * HASH_CYCLE_LEN; // controller(32 padded) + perm(32)
    for row in 23..hasher_trace_len {
        assert_eq!(expected, b_chip[row]);
    }

    // Bitwise responses are provided during the bitwise segment, which starts after the hasher.
    let response_1_row = hasher_trace_len + OP_CYCLE_LEN;
    let response_2_row = response_1_row + OP_CYCLE_LEN;
    let response_3_row = response_2_row + OP_CYCLE_LEN;

    // Nothing changes until the Bitwise chiplet responds.
    for row in hasher_trace_len..response_1_row {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the first bitwise cycle, the response for `U32and` is provided.
    expected *= build_expected_bitwise_from_trace(&trace, &challenges, (response_1_row - 1).into());
    assert_eq!(expected, b_chip[response_1_row]);

    // At the end of the next bitwise cycle, the response for `U32and` is provided.
    for row in (response_1_row + 1)..response_2_row {
        assert_eq!(expected, b_chip[row]);
    }
    expected *= build_expected_bitwise_from_trace(&trace, &challenges, (response_2_row - 1).into());
    assert_eq!(expected, b_chip[response_2_row]);

    // Nothing changes until the next time the Bitwise chiplet responds.
    for row in (response_2_row + 1)..response_3_row {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the next bitwise cycle, the response for `U32xor` is provided.
    expected *= build_expected_bitwise_from_trace(&trace, &challenges, (response_3_row - 1).into());
    assert_eq!(expected, b_chip[response_3_row]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in response_3_row..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

// TEST HELPERS
// ================================================================================================

fn build_expected_bitwise(
    challenges: &Challenges<Felt>,
    label: Felt,
    s0: Felt,
    s1: Felt,
    result: Felt,
) -> Felt {
    challenges.encode(miden_air::trace::bus_types::CHIPLETS_BUS, [label, s0, s1, result])
}

fn build_expected_bitwise_from_trace(
    trace: &ExecutionTrace,
    challenges: &Challenges<Felt>,
    row: RowIndex,
) -> Felt {
    let selector = trace.main_trace.get_column(BITWISE_TRACE_OFFSET)[row];

    let op_id = if selector == BITWISE_AND {
        BITWISE_AND_LABEL
    } else if selector == BITWISE_XOR {
        BITWISE_XOR_LABEL
    } else {
        panic!("Execution trace contains an invalid bitwise operation.")
    };

    let a = trace.main_trace.get_column(BITWISE_A_COL_IDX)[row];
    let b = trace.main_trace.get_column(BITWISE_B_COL_IDX)[row];
    let output = trace.main_trace.get_column(BITWISE_OUTPUT_COL_IDX)[row];

    build_expected_bitwise(challenges, op_id, a, b, output)
}
