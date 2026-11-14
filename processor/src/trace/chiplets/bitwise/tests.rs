use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use miden_air_definitions::vm::{
    BitwiseOpCols,
    trace::{
        and8_lookup::BYTE_LOOKUP_COUNT_LEN,
        chiplets::bitwise::{BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN, TRACE_WIDTH},
    },
};
use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::{Bitwise, ChipletTraceFragment};

#[test]
fn bitwise_init() {
    let bitwise = Bitwise::new();
    assert_eq!(0, bitwise.trace_len());
}

#[test]
fn bitwise_and() {
    let mut bitwise = Bitwise::new();

    let a = rand_u32();
    let b = rand_u32();

    let result = bitwise.u32and(a, b).unwrap();
    assert_eq!(a.as_canonical_u64() & b.as_canonical_u64(), result.as_canonical_u64());
    assert_eq!(bitwise.trace_len(), OP_CYCLE_LEN);

    let (trace, and8_counts) = build_trace_with_counts(bitwise);
    assert_eq!(and8_counts.iter().sum::<u64>(), 4);
    check_bitwise_row(&trace, 0, BITWISE_AND, a, b, result);
}

#[test]
fn bitwise_xor() {
    let mut bitwise = Bitwise::new();

    let a = rand_u32();
    let b = rand_u32();

    let result = bitwise.u32xor(a, b).unwrap();
    assert_eq!(a.as_canonical_u64() ^ b.as_canonical_u64(), result.as_canonical_u64());

    let (trace, and8_counts) = build_trace_with_counts(bitwise);
    assert_eq!(and8_counts.iter().sum::<u64>(), 4);
    check_bitwise_row(&trace, 0, BITWISE_XOR, a, b, result);
}

#[test]
fn bitwise_multiple() {
    let mut bitwise = Bitwise::new();

    let a = [rand_u32(), rand_u32(), rand_u32()];
    let b = [rand_u32(), rand_u32(), rand_u32()];

    // first operation: AND
    let result0 = bitwise.u32and(a[0], b[0]).unwrap();
    assert_eq!(a[0].as_canonical_u64() & b[0].as_canonical_u64(), result0.as_canonical_u64());

    // second operation: XOR
    let result1 = bitwise.u32xor(a[1], b[1]).unwrap();
    assert_eq!(a[1].as_canonical_u64() ^ b[1].as_canonical_u64(), result1.as_canonical_u64());

    // third operation: AND
    let result2 = bitwise.u32and(a[2], b[2]).unwrap();
    assert_eq!(a[2].as_canonical_u64() & b[2].as_canonical_u64(), result2.as_canonical_u64());

    let (trace, and8_counts) = build_trace_with_counts(bitwise);
    assert_eq!(and8_counts.iter().sum::<u64>(), 12);

    check_bitwise_row(&trace, 0, BITWISE_AND, a[0], b[0], result0);
    check_bitwise_row(&trace, OP_CYCLE_LEN, BITWISE_XOR, a[1], b[1], result1);
    check_bitwise_row(&trace, 2 * OP_CYCLE_LEN, BITWISE_AND, a[2], b[2], result2);
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_trace_with_counts(bitwise: Bitwise) -> (Vec<Felt>, Vec<u64>) {
    let width = TRACE_WIDTH;
    let mut band = Felt::zero_vec(width * bitwise.trace_len());
    let mut fragment = ChipletTraceFragment::row_major(&mut band, width);
    let mut and8_counts = vec![0; BYTE_LOOKUP_COUNT_LEN];
    bitwise.fill_trace(&mut fragment, &mut and8_counts);

    (band, and8_counts)
}

fn check_bitwise_row(trace: &[Felt], row: usize, op: Felt, a: Felt, b: Felt, result: Felt) {
    let start = row * TRACE_WIDTH;
    let cols: &BitwiseOpCols<Felt> = trace[start..start + TRACE_WIDTH].borrow();
    assert_eq!(cols.op_flag, op);

    let a_bytes = felt_u32(a).to_le_bytes();
    let b_bytes = felt_u32(b).to_le_bytes();
    assert_eq!(cols.a_bytes, a_bytes.map(Felt::from_u8));
    assert_eq!(cols.b_bytes, b_bytes.map(Felt::from_u8));
    assert_eq!(
        cols.and_bytes,
        core::array::from_fn(|idx| Felt::from_u8(a_bytes[idx] & b_bytes[idx]))
    );

    let and = u32_from_bytes(cols.and_bytes);
    let xor = a + b - and.double();
    let recomposed = and + op * (xor - and);
    assert_eq!(result, recomposed);
}

fn rand_u32() -> Felt {
    let value = rand::random::<u64>() as u32 as u64;
    Felt::new_unchecked(value)
}

fn felt_u32(value: Felt) -> u32 {
    u32::try_from(value.as_canonical_u64()).expect("test value should fit in u32")
}

fn u32_from_bytes(bytes: [Felt; 4]) -> Felt {
    let bytes = bytes
        .map(|byte| u8::try_from(byte.as_canonical_u64()).expect("test byte should fit in u8"));
    Felt::from_u32(u32::from_le_bytes(bytes))
}
