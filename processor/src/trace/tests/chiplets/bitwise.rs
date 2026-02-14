use miden_air::trace::{
    RowIndex,
    chiplets::{
        BITWISE_A_COL_IDX, BITWISE_B_COL_IDX, BITWISE_OUTPUT_COL_IDX, BITWISE_TRACE_OFFSET,
        bitwise::{BITWISE_AND, BITWISE_AND_LABEL, BITWISE_XOR, BITWISE_XOR_LABEL, OP_CYCLE_LEN},
    },
};
use miden_core::field::{Field, PrimeCharacteristicRing};

use super::{
    AUX_TRACE_RAND_ELEMENTS, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt, HASH_CYCLE_LEN,
    LAST_CYCLE_ROW, ONE, Operation, build_trace_from_ops, rand_array, rand_value,
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
#[expect(clippy::needless_range_loop)]
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

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // At cycle 0 the span hash initialization is requested from the decoder and provided by the
    // hash chiplet, so the trace should still equal one.
    assert_eq!(ONE, b_chip[1]);

    // The first bitwise request from the stack is sent when the `U32and` operation is executed at
    // cycle 1, so the request is included in the next row. (The trace begins by executing `span`).
    let value = build_expected_bitwise(
        &rand_elements,
        BITWISE_AND_LABEL,
        Felt::from_u32(a),
        Felt::from_u32(b),
        Felt::from_u32(a & b),
    );
    let mut expected = value.inverse();
    assert_eq!(expected, b_chip[2]);

    // Nothing changes during user operations with no requests to the Chiplets.
    for row in 3..5 {
        assert_eq!(expected, b_chip[row]);
    }

    // The second bitwise request from the stack is sent when the `U32and` operation is executed at
    // cycle 4, so the request is included in the next row.
    // After Push(a) then Push(b), stack is [b, a, ...] so operands are (s0=b, s1=a).
    let value = build_expected_bitwise(
        &rand_elements,
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
    // After Push(a) then Push(b), stack is [b, a, ...] so operands are (s0=b, s1=a).
    let value = build_expected_bitwise(
        &rand_elements,
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

    // At cycle 21 the decoder requests the span hash. Since this test focuses on bitwise lookups,
    // we treat the hasher bus messages as a black box and extract their multiplicands directly from
    // the bus column.
    assert_ne!(expected, b_chip[22]);
    let span_request_mult = b_chip[22] * b_chip[21].inverse();
    expected *= span_request_mult;
    assert_eq!(expected, b_chip[22]);

    // Nothing changes until the hasher provides the result of the `SPAN` hash at the end of the
    // hasher cycle.
    for row in 23..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the hasher cycle, the hasher provides the `SPAN` hash. Its multiplicand should
    // cancel out the earlier request.
    assert_ne!(expected, b_chip[HASH_CYCLE_LEN]);
    let span_response_mult = b_chip[HASH_CYCLE_LEN] * b_chip[LAST_CYCLE_ROW].inverse();
    assert_eq!(span_request_mult * span_response_mult, ONE);
    expected *= span_response_mult;
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // Bitwise responses will be provided during the bitwise segment of the Chiplets trace, which
    // starts after the hash for the span block. Responses are provided at the last row of the
    // Bitwise chiplet's operation cycle.
    let response_1_row = HASH_CYCLE_LEN + OP_CYCLE_LEN;
    let response_2_row = response_1_row + OP_CYCLE_LEN;
    let response_3_row = response_2_row + OP_CYCLE_LEN;

    // Nothing changes until the Bitwise chiplet responds.
    for row in (HASH_CYCLE_LEN + 1)..response_1_row {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the first bitwise cycle, the response for `U32and` is provided by the Bitwise
    // chiplet.
    expected *=
        build_expected_bitwise_from_trace(&trace, &rand_elements, (response_1_row - 1).into());
    assert_eq!(expected, b_chip[response_1_row]);

    // At the end of the next bitwise cycle, the response for `U32and` is provided by the Bitwise
    // chiplet.
    for row in (response_1_row + 1)..response_2_row {
        assert_eq!(expected, b_chip[row]);
    }
    expected *=
        build_expected_bitwise_from_trace(&trace, &rand_elements, (response_2_row - 1).into());
    assert_eq!(expected, b_chip[response_2_row]);

    // Nothing changes until the next time the Bitwise chiplet responds.
    for row in (response_2_row + 1)..response_3_row {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the next bitwise cycle, the response for `U32and` is provided by the Bitwise
    // chiplet.
    expected *=
        build_expected_bitwise_from_trace(&trace, &rand_elements, (response_3_row - 1).into());
    assert_eq!(expected, b_chip[response_3_row]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in response_3_row..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

// TEST HELPERS
// ================================================================================================

fn build_expected_bitwise(alphas: &[Felt], label: Felt, s0: Felt, s1: Felt, result: Felt) -> Felt {
    alphas[0] + alphas[1] * label + alphas[2] * s0 + alphas[3] * s1 + alphas[4] * result
}

fn build_expected_bitwise_from_trace(
    trace: &ExecutionTrace,
    alphas: &[Felt],
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

    build_expected_bitwise(alphas, op_id, a, b, output)
}
