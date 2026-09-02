use miden_core::{Felt, Word};
use miden_crypto::hash::eidos::Eidos;

use super::model::{execute_fused_rounds, execute_unfused_rounds, low_output, xof_lanes};

const BLOCK_WIDTH: usize = 8;

fn test_block() -> [Felt; BLOCK_WIDTH] {
    [
        Felt::new_unchecked(0x0000_0002_0000_0001),
        Felt::new_unchecked(0x0000_0004_0000_0003),
        Felt::new_unchecked(0x0000_0006_0000_0005),
        Felt::new_unchecked(0x0000_0008_0000_0007),
        Felt::new_unchecked(0x8000_000a_0000_0009),
        Felt::new_unchecked(0x0000_000c_8000_000b),
        Felt::new_unchecked(0x0000_000e_0000_000d),
        Felt::new_unchecked(0x0000_0010_0000_000f),
    ]
}

fn test_cv_word() -> Word {
    Word::new([
        Felt::new_unchecked(0x8000_0001_0000_0021),
        Felt::new_unchecked(0x0000_0043_8000_0022),
        Felt::new_unchecked(0x0000_0065_0000_0023),
        Felt::new_unchecked(0x0000_0087_0000_0024),
    ])
}

fn unpack(felt: Felt) -> (u32, u32) {
    let value = felt.as_canonical_u64();
    (value as u32, (value >> 32) as u32)
}

fn unpack_word(word: Word) -> [u32; 8] {
    core::array::from_fn(|i| {
        let (lo, hi) = unpack(word[i / 2]);
        if i % 2 == 0 { lo } else { hi }
    })
}

fn unpack_block(block: [Felt; BLOCK_WIDTH]) -> [u32; 16] {
    core::array::from_fn(|i| {
        let (lo, hi) = unpack(block[i / 2]);
        if i % 2 == 0 { lo } else { hi }
    })
}

fn pack_word(cv: [u32; 8]) -> Word {
    Word::new(core::array::from_fn(|i| {
        let high = cv[2 * i + 1] & 0x7fff_ffff;
        Felt::new_unchecked(((high as u64) << 32) | cv[2 * i] as u64)
    }))
}

#[test]
fn fused_schedule_matches_unfused_schedule() {
    let block = unpack_block(test_block());
    let h = unpack_word(test_cv_word());

    assert_eq!(execute_fused_rounds(block, h), execute_unfused_rounds(block, h));
}

#[test]
fn fused_schedule_matches_vm_compression_output() {
    let block = unpack_block(test_block());
    let h = unpack_word(test_cv_word());
    let fused_v = execute_fused_rounds(block, h);

    let actual_word = pack_word(low_output(fused_v));
    let expected_word = Eidos::compress(test_cv_word(), test_block());

    assert_eq!(actual_word, expected_word);
}

#[test]
fn fused_schedule_matches_vm_xof_lanes() {
    let block = unpack_block(test_block());
    let h = unpack_word(test_cv_word());
    let fused_v = execute_fused_rounds(block, h);

    let expected = Eidos::compress_xof(test_cv_word(), test_block())
        .map(|felt| felt.as_canonical_u64() as u32);
    assert_eq!(xof_lanes(fused_v, h), expected);
}
