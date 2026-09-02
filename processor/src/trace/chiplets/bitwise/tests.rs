use alloc::vec::Vec;
use core::{mem::size_of, ops::Range};

use miden_air::trace::chiplets::bitwise::{BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN, TRACE_WIDTH};
use miden_core::{ONE, chiplets::eidos_compression, field::PrimeCharacteristicRing};
use miden_utils_testing::rand::rand_value;

use super::{Bitwise, ChipletTraceFragment, Felt};

// Chiplet-local column indices for assertions in the bitwise trace tests.
const OP_COL_IDX: usize = 0;
const A_BYTE_RANGE: Range<usize> = 1..5;
const B_BYTE_RANGE: Range<usize> = 5..9;
const AND_BYTE_RANGE: Range<usize> = 9..13;

#[test]
fn bitwise_init() {
    let bitwise = Bitwise::new();
    assert_eq!(0, bitwise.trace_len());
}

#[test]
fn entry_does_not_inline_the_aead_stream_payload() {
    assert!(
        size_of::<super::Entry>() < size_of::<super::AeadStreamOp>(),
        "ordinary bitwise entries must not pay for the inline AEAD stream payload",
    );
}

#[test]
fn bitwise_and() {
    let mut bitwise = Bitwise::new();

    let a = rand_u32();
    let b = rand_u32();

    let result = bitwise.u32and(a, b).unwrap();
    assert_eq!(a.as_canonical_u64() & b.as_canonical_u64(), result.as_canonical_u64());
    assert_eq!(bitwise.trace_len(), OP_CYCLE_LEN);

    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, OP_CYCLE_LEN, TRACE_WIDTH);
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

    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, OP_CYCLE_LEN, TRACE_WIDTH);
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

    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, 3 * OP_CYCLE_LEN, TRACE_WIDTH);
    assert_eq!(and8_counts.iter().sum::<u64>(), 12);

    check_bitwise_row(&trace, 0, BITWISE_AND, a[0], b[0], result0);
    check_bitwise_row(&trace, OP_CYCLE_LEN, BITWISE_XOR, a[1], b[1], result1);
    check_bitwise_row(&trace, 2 * OP_CYCLE_LEN, BITWISE_AND, a[2], b[2], result2);
}

#[test]
fn aead_stream_trace() {
    let mut bitwise = Bitwise::new();

    let plaintext_limbs = [1_u32, 2, 3, 4, 5, 6, 7, 8];
    let plaintext = [
        eidos_compression::pack(plaintext_limbs[0], plaintext_limbs[1]),
        eidos_compression::pack(plaintext_limbs[2], plaintext_limbs[3]),
        eidos_compression::pack(plaintext_limbs[4], plaintext_limbs[5]),
        eidos_compression::pack(plaintext_limbs[6], plaintext_limbs[7]),
    ];
    let keystream = core::array::from_fn(|idx| Felt::from_u32(20 + idx as u32));
    let ciphertext = core::array::from_fn(|idx| {
        Felt::from_u32(plaintext_limbs[idx] ^ keystream[idx].as_canonical_u64() as u32)
    });

    let ctx = Felt::from_u32(3);
    let clk = Felt::from_u32(11);
    let src_ptr = Felt::from_u32(100);
    let dst_ptr = Felt::from_u32(200);
    let lane_base = Felt::from_u32(40);
    bitwise.aead_stream(ctx, clk, src_ptr, dst_ptr, lane_base, plaintext, keystream, ciphertext);
    assert_eq!(bitwise.trace_len(), super::AEAD_STREAM_CYCLE_LEN);

    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, 8, super::AEAD_STREAM_FRAGMENT_WIDTH);
    assert_eq!(and8_counts.iter().sum::<u64>(), 32);

    for row in 0..8 {
        assert_eq!(trace[super::STREAM_MODE_OFFSET][row], ONE);
    }

    // r0: read + low limb for plaintext[0].
    assert_eq!(trace[0][0], ctx);
    assert_eq!(trace[1][0], clk);
    assert_eq!(trace[2][0], src_ptr);
    assert_eq!(trace[3][0], lane_base);
    assert_eq!(trace[4][0], plaintext[0]);
    assert_eq!(trace[8][0], Felt::from_u8(plaintext_limbs[0] as u8));
    assert_eq!(trace[12][0], keystream[0]);
    assert_eq!(
        trace[16][0],
        Felt::from_u8((plaintext_limbs[0] as u8) & (keystream[0].as_canonical_u64() as u8)),
    );

    // r1 carries ciphertext limb 0 and plaintext[1].
    assert_eq!(trace[4][1], plaintext[1]);
    assert_eq!(trace[5][1], ciphertext[0]);

    // r4 starts the second word pair at lane_base + 4.
    assert_eq!(trace[3][4], lane_base + Felt::from_u32(4));
    assert_eq!(trace[4][4], plaintext[0]);
}

#[test]
fn aead_stream_is_phase_aligned_after_bitwise_op() {
    let mut bitwise = Bitwise::new();
    let a = Felt::from_u32(0x1234_5678);
    let b = Felt::from_u32(0xff00_ff00);
    let result = bitwise.u32and(a, b).unwrap();
    record_test_aead_stream(&mut bitwise);

    let num_rows = super::AEAD_STREAM_CYCLE_LEN + OP_CYCLE_LEN;
    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, num_rows, super::AEAD_STREAM_FRAGMENT_WIDTH);

    assert_eq!(and8_counts.iter().sum::<u64>(), 36);
    for row in 0..super::AEAD_STREAM_CYCLE_LEN {
        assert_eq!(trace[super::STREAM_MODE_OFFSET][row], ONE);
    }
    assert_eq!(trace[super::STREAM_MODE_OFFSET][super::AEAD_STREAM_CYCLE_LEN], Felt::ZERO);
    check_bitwise_row(&trace, super::AEAD_STREAM_CYCLE_LEN, BITWISE_AND, a, b, result);
}

#[test]
fn aead_stream_is_phase_aligned_after_seven_bitwise_ops() {
    let mut bitwise = Bitwise::new();
    let mut expected = Vec::new();
    for value in 0..7_u32 {
        let a = Felt::from_u32(value + 1);
        let b = Felt::from_u32(0xa5a5_0000 | value);
        let result = bitwise.u32xor(a, b).unwrap();
        expected.push((a, b, result));
    }
    record_test_aead_stream(&mut bitwise);

    let num_rows = super::AEAD_STREAM_CYCLE_LEN + 7 * OP_CYCLE_LEN;
    let (trace, and8_counts) =
        build_trace_with_width_and_counts(bitwise, num_rows, super::AEAD_STREAM_FRAGMENT_WIDTH);

    assert_eq!(and8_counts.iter().sum::<u64>(), 60);
    for row in 0..super::AEAD_STREAM_CYCLE_LEN {
        assert_eq!(trace[super::STREAM_MODE_OFFSET][row], ONE);
    }
    for (idx, (a, b, result)) in expected.into_iter().enumerate() {
        let row = super::AEAD_STREAM_CYCLE_LEN + idx;
        assert_eq!(trace[super::STREAM_MODE_OFFSET][row], Felt::ZERO);
        check_bitwise_row(&trace, row, BITWISE_XOR, a, b, result);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_trace_with_width_and_counts(
    bitwise: Bitwise,
    num_rows: usize,
    width: usize,
) -> (Vec<Vec<Felt>>, Vec<u64>) {
    let mut band = Felt::zero_vec(width * num_rows);
    let mut fragment = ChipletTraceFragment::row_major(&mut band, width, 0, width);
    let and8_counts = bitwise.fill_trace(&mut fragment);

    let trace = (0..width)
        .map(|c| (0..num_rows).map(|r| band[r * width + c]).collect())
        .collect();
    (trace, and8_counts)
}

fn record_test_aead_stream(bitwise: &mut Bitwise) {
    let plaintext_limbs = [1_u32, 2, 3, 4, 5, 6, 7, 8];
    let plaintext = [
        eidos_compression::pack(plaintext_limbs[0], plaintext_limbs[1]),
        eidos_compression::pack(plaintext_limbs[2], plaintext_limbs[3]),
        eidos_compression::pack(plaintext_limbs[4], plaintext_limbs[5]),
        eidos_compression::pack(plaintext_limbs[6], plaintext_limbs[7]),
    ];
    let keystream = core::array::from_fn(|idx| Felt::from_u32(20 + idx as u32));
    let ciphertext = core::array::from_fn(|idx| {
        Felt::from_u32(plaintext_limbs[idx] ^ keystream[idx].as_canonical_u64() as u32)
    });

    bitwise.aead_stream(
        Felt::from_u32(3),
        Felt::from_u32(11),
        Felt::from_u32(100),
        Felt::from_u32(200),
        Felt::from_u32(40),
        plaintext,
        keystream,
        ciphertext,
    );
}

fn check_bitwise_row(trace: &[Vec<Felt>], row: usize, op: Felt, a: Felt, b: Felt, result: Felt) {
    assert_eq!(trace[OP_COL_IDX][row], op);

    let a_bytes = felt_u32(a).to_le_bytes();
    let b_bytes = felt_u32(b).to_le_bytes();
    for idx in 0..4 {
        assert_eq!(Felt::from_u8(a_bytes[idx]), trace[A_BYTE_RANGE.start + idx][row]);
        assert_eq!(Felt::from_u8(b_bytes[idx]), trace[B_BYTE_RANGE.start + idx][row]);
        assert_eq!(
            Felt::from_u8(a_bytes[idx] & b_bytes[idx]),
            trace[AND_BYTE_RANGE.start + idx][row],
        );
    }

    let and = u32_from_bytes([
        trace[AND_BYTE_RANGE.start][row],
        trace[AND_BYTE_RANGE.start + 1][row],
        trace[AND_BYTE_RANGE.start + 2][row],
        trace[AND_BYTE_RANGE.start + 3][row],
    ]);
    let xor = a + b - and.double();
    let recomposed = and + op * (xor - and);
    assert_eq!(result, recomposed);
}

fn rand_u32() -> Felt {
    let value = rand_value::<u64>() as u32 as u64;
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
