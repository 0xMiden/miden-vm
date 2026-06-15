//! BlakeG compression helpers for VM 12-lane stack windows.
//!
//! The VM stores one BlakeG input as eight block Felts followed by a 4-Felt
//! packed chaining value. This module owns the VM stack contract and delegates
//! compression to the public Eidos interface in `miden-crypto`.

use miden_crypto::{Felt, Word, hash::eidos::Eidos};

/// Number of Felts in one BlakeG stack window.
pub const STATE_WIDTH: usize = 12;

/// Number of block Felts in the stack window.
pub const RATE_WIDTH: usize = 8;

/// Number of Felts in the packed chaining value.
pub const DIGEST_WIDTH: usize = 4;

const ODD_LANE_MASK: u32 = 0x7fff_ffff;
const STATE_WORDS: usize = 8;
const BLOCK_WORDS: usize = 16;

#[inline]
pub fn unpack(felt: Felt) -> (u32, u32) {
    let value = felt.as_canonical_u64();
    (value as u32, (value >> 32) as u32)
}

#[inline]
pub fn unpack_word(word: Word) -> [u32; STATE_WORDS] {
    let (a, b) = unpack(word[0]);
    let (c, d) = unpack(word[1]);
    let (e, f) = unpack(word[2]);
    let (g, h) = unpack(word[3]);
    [a, b, c, d, e, f, g, h]
}

#[inline]
pub fn unpack_block(block: [Felt; RATE_WIDTH]) -> [u32; BLOCK_WORDS] {
    core::array::from_fn(|i| {
        let (lo, hi) = unpack(block[i / 2]);
        if i % 2 == 0 { lo } else { hi }
    })
}

#[inline]
pub fn pack(lo: u32, hi: u32) -> Felt {
    Felt::new_unchecked((((hi & ODD_LANE_MASK) as u64) << 32) | lo as u64)
}

#[inline]
pub fn pack_word(cv: [u32; STATE_WORDS]) -> Word {
    Word::new([pack(cv[0], cv[1]), pack(cv[2], cv[3]), pack(cv[4], cv[5]), pack(cv[6], cv[7])])
}

/// Construct the Eidos felt-mode initial chaining word.
#[inline]
pub fn init_chaining_word(domain: u32, n: u32) -> Word {
    Eidos::init_chaining_word(domain, n)
}

/// Construct the chaining word for a two-word BlakeG hash.
///
/// This is the switch point for the VM's 2-to-1/control-block framing.
#[inline]
pub fn two_to_one_chaining_word(domain: u32) -> Word {
    init_chaining_word(domain, RATE_WIDTH as u32)
}

#[inline]
pub fn merge(values: &[Word; 2]) -> Word {
    Eidos::merge(values)
}

#[inline]
pub fn merge_many(values: &[Word]) -> Word {
    Eidos::merge_many(values)
}

#[inline]
pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
    Eidos::merge_in_domain(values, domain)
}

#[inline]
pub fn hash(bytes: &[u8]) -> Word {
    Eidos::hash(bytes)
}

#[inline]
pub fn hash_elements(elements: &[Felt]) -> Word {
    Eidos::hash_elements(elements)
}

/// Applies packed BlakeG compression to a VM stack window.
///
/// The input window is interpreted as:
///
/// ```text
/// state[0..8]   = block
/// state[8..12]  = cv
/// ```
///
/// The output window is:
///
/// ```text
/// state[0..8]   = block
/// state[8..12]  = BlakeG(cv, block)
/// ```
pub fn compress_state(state: &mut [Felt; STATE_WIDTH]) -> [u32; STATE_WORDS] {
    let block = core::array::from_fn(|i| state[i]);
    let cv_word = Word::new(core::array::from_fn(|i| state[RATE_WIDTH + i]));
    let cv_new_word = Eidos::compress_block(cv_word, block);
    let cv_new = unpack_word(cv_new_word);

    state[RATE_WIDTH..STATE_WIDTH].copy_from_slice(cv_new_word.as_slice());

    cv_new
}

/// Computes the full 16-lane BlakeG XOF keystream (`low || high`) for a stack window.
///
/// The input window has the same shape as [`compress_state`]:
///
/// ```text
/// state[0..8]   = block
/// state[8..12]  = cv
/// ```
///
/// Returns all 16 u32 keystream lanes as `low[0..8] || high[0..8]`, where
/// `low[i] = v[i] ^ v[i+8]` (identical to `BlakeG::compress_raw`) and
/// `high[i] = v[i+8] ^ cv[i]` (the BLAKE3 XOF feed-forward against the input CV).
///
/// The 16 lanes exceed the 12-Felt window, so they are returned for direct bus
/// emission rather than written back to `state`.
pub fn compress_raw_xof_lanes(state: &[Felt; STATE_WIDTH]) -> [u32; 16] {
    let block = core::array::from_fn(|i| state[i]);
    let cv_word = Word::new(core::array::from_fn(|i| state[RATE_WIDTH + i]));
    Eidos::compress_xof_block(cv_word, block).map(|felt| felt.as_canonical_u64() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_state_preserves_block_and_writes_new_cv() {
        let block = [
            Felt::new_unchecked(0x0000_0002_0000_0001),
            Felt::new_unchecked(0x0000_0004_0000_0003),
            Felt::new_unchecked(0x0000_0006_0000_0005),
            Felt::new_unchecked(0x0000_0008_0000_0007),
            Felt::new_unchecked(0x8000_000a_0000_0009),
            Felt::new_unchecked(0x0000_000c_8000_000b),
            Felt::new_unchecked(0x0000_000e_0000_000d),
            Felt::new_unchecked(0x0000_0010_0000_000f),
        ];
        let cv_word = Word::new([
            Felt::new_unchecked(0x8000_0001_0000_0021),
            Felt::new_unchecked(0x0000_0043_8000_0022),
            Felt::new_unchecked(0x0000_0065_0000_0023),
            Felt::new_unchecked(0x0000_0087_0000_0024),
        ]);
        let mut state = [
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
            cv_word[0], cv_word[1], cv_word[2], cv_word[3],
        ];

        let expected_cv_word = Eidos::compress_block(cv_word, block);
        let expected_cv = unpack_word(expected_cv_word);
        let actual_cv = compress_state(&mut state);

        assert_eq!(actual_cv, expected_cv);
        assert_eq!(&state[..RATE_WIDTH], &block);
        assert_eq!(&state[RATE_WIDTH..STATE_WIDTH], expected_cv_word.as_slice());
    }

    #[test]
    fn pack_word_masks_odd_lanes() {
        let word = pack_word([
            0xffff_ffff,
            0xffff_ffff,
            0x0123_4567,
            0x89ab_cdef,
            0xdead_beef,
            0xffff_ffff,
            0xa5a5_a5a5,
            0xffff_ffff,
        ]);

        for felt in word.as_slice() {
            let (_, hi) = unpack(*felt);
            assert_eq!(hi & !ODD_LANE_MASK, 0);
        }
    }

    #[test]
    fn compress_raw_xof_lanes_returns_low_fold_then_high_feed_forward() {
        let block = [
            Felt::new_unchecked(0x0000_0002_0000_0001),
            Felt::new_unchecked(0x0000_0004_0000_0003),
            Felt::new_unchecked(0x0000_0006_0000_0005),
            Felt::new_unchecked(0x0000_0008_0000_0007),
            Felt::new_unchecked(0x8000_000a_0000_0009),
            Felt::new_unchecked(0x0000_000c_8000_000b),
            Felt::new_unchecked(0x0000_000e_0000_000d),
            Felt::new_unchecked(0x0000_0010_0000_000f),
        ];
        let cv_word = Word::new([
            Felt::new_unchecked(0x8000_0001_0000_0021),
            Felt::new_unchecked(0x0000_0043_8000_0022),
            Felt::new_unchecked(0x0000_0065_0000_0023),
            Felt::new_unchecked(0x0000_0087_0000_0024),
        ]);
        let state = [
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
            cv_word[0], cv_word[1], cv_word[2], cv_word[3],
        ];

        let lanes = compress_raw_xof_lanes(&state);

        let expected =
            Eidos::compress_xof_block(cv_word, block).map(|felt| felt.as_canonical_u64() as u32);
        assert_eq!(lanes, expected);
    }
}
