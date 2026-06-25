use miden_core::{
    Felt, Word,
    chiplets::blakeg::{self, RATE_WIDTH, STATE_WIDTH},
};

use super::air32_model::{execute_fused_rounds, execute_unfused_rounds, low_output, xof_lanes};

fn test_block() -> [Felt; RATE_WIDTH] {
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

fn test_state() -> [Felt; STATE_WIDTH] {
    let block = test_block();
    let cv = test_cv_word();
    [
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7], cv[0],
        cv[1], cv[2], cv[3],
    ]
}

#[test]
fn fused_schedule_matches_unfused_schedule() {
    let block = blakeg::unpack_block(test_block());
    let h = blakeg::unpack_word(test_cv_word());

    assert_eq!(execute_fused_rounds(block, h), execute_unfused_rounds(block, h));
}

#[test]
fn fused_schedule_matches_vm_compression_output() {
    let block = blakeg::unpack_block(test_block());
    let h = blakeg::unpack_word(test_cv_word());
    let fused_v = execute_fused_rounds(block, h);

    let actual_word = blakeg::pack_word(low_output(fused_v));

    let mut expected_state = test_state();
    blakeg::compress_state(&mut expected_state);
    let expected_word =
        Word::new([expected_state[8], expected_state[9], expected_state[10], expected_state[11]]);

    assert_eq!(actual_word, expected_word);
}

#[test]
fn fused_schedule_matches_vm_xof_lanes() {
    let block = blakeg::unpack_block(test_block());
    let h = blakeg::unpack_word(test_cv_word());
    let fused_v = execute_fused_rounds(block, h);

    assert_eq!(xof_lanes(fused_v, h), blakeg::compress_raw_xof_lanes(&test_state()));
}
