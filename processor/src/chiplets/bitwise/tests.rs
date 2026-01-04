use alloc::vec::Vec;

use miden_air::trace::chiplets::bitwise::{
    A_COL_IDX, A_COL_RANGE, B_COL_IDX, B_COL_RANGE, BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN,
    OUTPUT_COL_IDX, PREV_OUTPUT_COL_IDX, TRACE_WIDTH,
};
use miden_core::ZERO;
use miden_utils_testing::rand::rand_value;

use super::{Bitwise, Felt, TraceFragment};
use crate::PrimeField64;

#[test]
fn bitwise_init() {
    let bitwise = Bitwise::new();
    assert_eq!(0, bitwise.trace_len());
}

#[test]
#[expect(clippy::needless_range_loop)]
fn bitwise_and() {
    let mut bitwise = Bitwise::new();

    let a = rand_u32();
    let b = rand_u32();

    let result = bitwise.u32and(a, b, &()).unwrap();
    assert_eq!(a.as_canonical_u64() & b.as_canonical_u64(), result.as_canonical_u64());

    // --- check generated trace ----------------------------------------------
    let trace = build_trace(bitwise, OP_CYCLE_LEN);

    // make sure the selector values specify bitwise AND at each step in the trace
    for row in 0..OP_CYCLE_LEN {
        assert_eq!(trace[0][row], BITWISE_AND);
    }

    // make sure result and result from the trace are the same
    assert_eq!(result, trace[OUTPUT_COL_IDX][OP_CYCLE_LEN - 1]);

    // make sure values a and b were decomposed correctly
    check_decomposition(&trace, 0, a.as_canonical_u64(), b.as_canonical_u64());

    // make sure the result was re-composed correctly
    let mut prev_result = ZERO;

    for i in 0..OP_CYCLE_LEN {
        let c0 = binary_and(trace[A_COL_RANGE.start][i], trace[B_COL_RANGE.start][i]);
        let c1 = binary_and(trace[A_COL_RANGE.start + 1][i], trace[B_COL_RANGE.start + 1][i]);
        let c2 = binary_and(trace[A_COL_RANGE.start + 2][i], trace[B_COL_RANGE.start + 2][i]);
        let c3 = binary_and(trace[A_COL_RANGE.start + 3][i], trace[B_COL_RANGE.start + 3][i]);

        let result_4_bit = c0 + Felt::new(2) * c1 + Felt::new(4) * c2 + Felt::new(8) * c3;
        let result = prev_result * Felt::new(16) + result_4_bit;

        assert_eq!(prev_result, trace[PREV_OUTPUT_COL_IDX][i]);
        assert_eq!(result, trace[OUTPUT_COL_IDX][i]);

        prev_result = result;
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
fn bitwise_xor() {
    let mut bitwise = Bitwise::new();

    let a = rand_u32();
    let b = rand_u32();

    let result = bitwise.u32xor(a, b, &()).unwrap();
    assert_eq!(a.as_canonical_u64() ^ b.as_canonical_u64(), result.as_canonical_u64());

    // --- check generated trace ----------------------------------------------
    let trace = build_trace(bitwise, OP_CYCLE_LEN);

    // make sure the selector values specify bitwise XOR at each step in the trace
    for row in 0..OP_CYCLE_LEN {
        assert_eq!(trace[0][row], BITWISE_XOR);
    }

    // make sure result and result from the trace are the same
    assert_eq!(result, trace[OUTPUT_COL_IDX][OP_CYCLE_LEN - 1]);

    // make sure values a and b were decomposed correctly
    check_decomposition(&trace, 0, a.as_canonical_u64(), b.as_canonical_u64());

    // make sure the result was re-composed correctly
    let mut prev_result = ZERO;

    for i in 0..8 {
        let c0 = binary_xor(trace[A_COL_RANGE.start][i], trace[B_COL_RANGE.start][i]);
        let c1 = binary_xor(trace[A_COL_RANGE.start + 1][i], trace[B_COL_RANGE.start + 1][i]);
        let c2 = binary_xor(trace[A_COL_RANGE.start + 2][i], trace[B_COL_RANGE.start + 2][i]);
        let c3 = binary_xor(trace[A_COL_RANGE.start + 3][i], trace[B_COL_RANGE.start + 3][i]);

        let result_4_bit = c0 + Felt::new(2) * c1 + Felt::new(4) * c2 + Felt::new(8) * c3;
        let result = prev_result * Felt::new(16) + result_4_bit;

        assert_eq!(prev_result, trace[PREV_OUTPUT_COL_IDX][i]);
        assert_eq!(result, trace[OUTPUT_COL_IDX][i]);

        prev_result = result;
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
fn bitwise_multiple() {
    let mut bitwise = Bitwise::new();

    let a = [rand_u32(), rand_u32(), rand_u32()];
    let b = [rand_u32(), rand_u32(), rand_u32()];

    // first operation: AND
    let result0 = bitwise.u32and(a[0], b[0], &()).unwrap();
    assert_eq!(a[0].as_canonical_u64() & b[0].as_canonical_u64(), result0.as_canonical_u64());

    // second operation: XOR
    let result1 = bitwise.u32xor(a[1], b[1], &()).unwrap();
    assert_eq!(a[1].as_canonical_u64() ^ b[1].as_canonical_u64(), result1.as_canonical_u64());

    // third operation: AND
    let result2 = bitwise.u32and(a[2], b[2], &()).unwrap();
    assert_eq!(a[2].as_canonical_u64() & b[2].as_canonical_u64(), result2.as_canonical_u64());

    // --- check generated trace ----------------------------------------------
    let trace = build_trace(bitwise, 3 * OP_CYCLE_LEN);

    // make sure results and results from the trace are the same
    assert_eq!(result0, trace[OUTPUT_COL_IDX][OP_CYCLE_LEN - 1]);
    assert_eq!(result1, trace[OUTPUT_COL_IDX][2 * OP_CYCLE_LEN - 1]);
    assert_eq!(result2, trace[OUTPUT_COL_IDX][3 * OP_CYCLE_LEN - 1]);
    // make sure input values were decomposed correctly
    check_decomposition(&trace, 0, a[0].as_canonical_u64(), b[0].as_canonical_u64());
    check_decomposition(&trace, OP_CYCLE_LEN, a[1].as_canonical_u64(), b[1].as_canonical_u64());
    check_decomposition(&trace, 2 * OP_CYCLE_LEN, a[2].as_canonical_u64(), b[2].as_canonical_u64());

    // make sure the results was re-composed correctly

    let mut prev_result = ZERO;
    for i in 0..OP_CYCLE_LEN {
        let c0 = binary_and(trace[A_COL_RANGE.start][i], trace[B_COL_RANGE.start][i]);
        let c1 = binary_and(trace[A_COL_RANGE.start + 1][i], trace[B_COL_RANGE.start + 1][i]);
        let c2 = binary_and(trace[A_COL_RANGE.start + 2][i], trace[B_COL_RANGE.start + 2][i]);
        let c3 = binary_and(trace[A_COL_RANGE.start + 3][i], trace[B_COL_RANGE.start + 3][i]);

        let result_4_bit = c0 + Felt::new(2) * c1 + Felt::new(4) * c2 + Felt::new(8) * c3;
        let result = prev_result * Felt::new(16) + result_4_bit;

        assert_eq!(prev_result, trace[PREV_OUTPUT_COL_IDX][i]);
        assert_eq!(result, trace[OUTPUT_COL_IDX][i]);

        prev_result = result;
    }

    let mut prev_result = ZERO;
    for i in OP_CYCLE_LEN..(2 * OP_CYCLE_LEN) {
        let c0 = binary_xor(trace[A_COL_RANGE.start][i], trace[B_COL_RANGE.start][i]);
        let c1 = binary_xor(trace[A_COL_RANGE.start + 1][i], trace[B_COL_RANGE.start + 1][i]);
        let c2 = binary_xor(trace[A_COL_RANGE.start + 2][i], trace[B_COL_RANGE.start + 2][i]);
        let c3 = binary_xor(trace[A_COL_RANGE.start + 3][i], trace[B_COL_RANGE.start + 3][i]);

        let result_4_bit = c0 + Felt::new(2) * c1 + Felt::new(4) * c2 + Felt::new(8) * c3;
        let result = prev_result * Felt::new(16) + result_4_bit;

        assert_eq!(prev_result, trace[PREV_OUTPUT_COL_IDX][i]);
        assert_eq!(result, trace[OUTPUT_COL_IDX][i]);

        prev_result = result;
    }

    let mut prev_result = ZERO;
    for i in (2 * OP_CYCLE_LEN)..(3 * OP_CYCLE_LEN) {
        let c0 = binary_and(trace[A_COL_RANGE.start][i], trace[B_COL_RANGE.start][i]);
        let c1 = binary_and(trace[A_COL_RANGE.start + 1][i], trace[B_COL_RANGE.start + 1][i]);
        let c2 = binary_and(trace[A_COL_RANGE.start + 2][i], trace[B_COL_RANGE.start + 2][i]);
        let c3 = binary_and(trace[A_COL_RANGE.start + 3][i], trace[B_COL_RANGE.start + 3][i]);

        let result_4_bit = c0 + Felt::new(2) * c1 + Felt::new(4) * c2 + Felt::new(8) * c3;
        let result = prev_result * Felt::new(16) + result_4_bit;

        assert_eq!(prev_result, trace[PREV_OUTPUT_COL_IDX][i]);
        assert_eq!(result, trace[OUTPUT_COL_IDX][i]);

        prev_result = result;
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a trace of the specified length and fills it with data from the provided Bitwise
/// instance.
fn build_trace(bitwise: Bitwise, num_rows: usize) -> Vec<Vec<Felt>> {
    let mut trace = (0..TRACE_WIDTH).map(|_| vec![ZERO; num_rows]).collect::<Vec<_>>();
    let mut fragment = TraceFragment::trace_to_fragment(&mut trace);
    bitwise.fill_trace(&mut fragment);

    trace
}

fn check_decomposition(trace: &[Vec<Felt>], start: usize, a: u64, b: u64) {
    let mut bit_offset = 28;

    #[expect(clippy::needless_range_loop)]
    for i in start..start + 8 {
        let a = a >> bit_offset;
        let b = b >> bit_offset;

        assert_eq!(Felt::new(a), trace[A_COL_IDX][i]);
        assert_eq!(Felt::new(b), trace[B_COL_IDX][i]);

        assert_eq!(Felt::new(a & 1), trace[A_COL_RANGE.start][i]);
        assert_eq!(Felt::new((a >> 1) & 1), trace[A_COL_RANGE.start + 1][i]);
        assert_eq!(Felt::new((a >> 2) & 1), trace[A_COL_RANGE.start + 2][i]);
        assert_eq!(Felt::new((a >> 3) & 1), trace[A_COL_RANGE.start + 3][i]);

        assert_eq!(Felt::new(b & 1), trace[B_COL_RANGE.start][i]);
        assert_eq!(Felt::new((b >> 1) & 1), trace[B_COL_RANGE.start + 1][i]);
        assert_eq!(Felt::new((b >> 2) & 1), trace[B_COL_RANGE.start + 2][i]);
        assert_eq!(Felt::new((b >> 3) & 1), trace[B_COL_RANGE.start + 3][i]);

        bit_offset -= 4;
    }
}

fn binary_and(a: Felt, b: Felt) -> Felt {
    a * b
}

fn binary_xor(a: Felt, b: Felt) -> Felt {
    a + b - Felt::new(2) * a * b
}

fn rand_u32() -> Felt {
    let value = rand_value::<u64>() as u32 as u64;
    Felt::new(value)
}
