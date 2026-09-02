//! Canonical encoding between Eidos compression lanes and Goldilocks field elements.
//!
//! Raw compression inputs are decoded losslessly from canonical field elements. Eidos output CVs
//! use a different, intentionally lossy operation: bit 31 of every odd output lane is
//! cleared before each lane pair is packed into a field element. Keeping those operations
//! distinct prevents callers from accidentally treating an arbitrary input CV as an Eidos output.

use core::array;

use super::{BLOCK_LEN, DIGEST_WIDTH};
use crate::{Felt, Word};

/// Mask applied to odd output lanes before packing an Eidos output CV.
pub const ODD_LANE_MASK: u32 = 0x7fff_ffff;

/// Decode a canonical field element into its low and high `u32` lanes.
///
/// This is lossless for every canonical Goldilocks field element. It does not require the element
/// to have been produced by [`pack_output_felt`].
#[inline]
pub fn unpack_felt(felt: Felt) -> (u32, u32) {
    let value = felt.as_canonical_u64();
    (value as u32, (value >> 32) as u32)
}

/// Decode a four-Felt word into an arbitrary eight-lane Eidos chaining value.
///
/// No output-subspace mask is applied to the input.
#[inline]
pub fn word_to_cv(word: Word) -> [u32; 8] {
    let (a, b) = unpack_felt(word[0]);
    let (c, d) = unpack_felt(word[1]);
    let (e, f) = unpack_felt(word[2]);
    let (g, h) = unpack_felt(word[3]);
    [a, b, c, d, e, f, g, h]
}

/// Decode an eight-Felt compression block into sixteen `u32` lanes.
#[inline]
pub fn felts_to_block(block: [Felt; BLOCK_LEN]) -> [u32; 16] {
    encode_felt_block(&block)
}

/// Pack two lanes from an Eidos output CV into one canonical field element.
///
/// Bit 31 of `hi` is cleared. This operation is for compression outputs and completed digests,
/// not for round-tripping arbitrary compression inputs.
#[inline]
pub fn pack_output_felt(lo: u32, hi: u32) -> Felt {
    Felt::new_unchecked(pack_output_pair_u64(lo, hi))
}

/// Pack an eight-lane Eidos output CV into a four-Felt word.
///
/// Bit 31 of each odd lane is cleared.
#[inline]
pub fn output_cv_to_word(cv: [u32; 8]) -> Word {
    Word::new([
        pack_output_felt(cv[0], cv[1]),
        pack_output_felt(cv[2], cv[3]),
        pack_output_felt(cv[4], cv[5]),
        pack_output_felt(cv[6], cv[7]),
    ])
}

#[inline]
pub(super) const fn pack_output_pair_u64(lo: u32, hi: u32) -> u64 {
    (((hi & ODD_LANE_MASK) as u64) << 32) | lo as u64
}

#[inline]
pub(super) fn pack_cv_to_felts<const LANES: usize>(
    cv: [[u32; LANES]; 8],
) -> [[Felt; LANES]; DIGEST_WIDTH] {
    array::from_fn(|word| {
        array::from_fn(|lane| pack_output_felt(cv[2 * word][lane], cv[2 * word + 1][lane]))
    })
}

#[inline]
pub(super) fn pack_cv_to_u64s(cv: [u32; 8]) -> [u64; DIGEST_WIDTH] {
    array::from_fn(|word| pack_output_pair_u64(cv[2 * word], cv[2 * word + 1]))
}

#[inline]
pub(super) fn unpack_u64_cv(cv: [u64; DIGEST_WIDTH]) -> [u32; 8] {
    array::from_fn(|lane_word| {
        let value = cv[lane_word / 2];
        if lane_word % 2 == 0 {
            value as u32
        } else {
            (value >> 32) as u32
        }
    })
}

#[inline]
pub(super) fn pack_cv_to_packed_u64s<const LANES: usize>(
    cv: [[u32; LANES]; 8],
) -> [[u64; LANES]; DIGEST_WIDTH] {
    array::from_fn(|word| {
        array::from_fn(|lane| pack_output_pair_u64(cv[2 * word][lane], cv[2 * word + 1][lane]))
    })
}

#[inline]
pub(super) fn encode_byte_block(chunk: &[u8]) -> [u32; 16] {
    debug_assert!(chunk.len() <= 64);

    let mut block = [0u32; 16];
    for (i, four) in chunk.chunks(4).enumerate() {
        let mut buf = [0u8; 4];
        buf[..four.len()].copy_from_slice(four);
        block[i] = u32::from_le_bytes(buf);
    }
    block
}

#[inline]
pub(super) fn encode_felt_block(chunk: &[Felt]) -> [u32; 16] {
    debug_assert!(chunk.len() <= BLOCK_LEN);

    let mut block = [0u32; 16];
    for (i, &felt) in chunk.iter().enumerate() {
        let (lo, hi) = unpack_felt(felt);
        block[2 * i] = lo;
        block[2 * i + 1] = hi;
    }
    block
}

#[inline]
pub(super) fn encode_u64_block(chunk: &[u64]) -> [u32; 16] {
    debug_assert!(chunk.len() <= BLOCK_LEN);

    let mut block = [0u32; 16];
    for (i, &value) in chunk.iter().enumerate() {
        block[2 * i] = value as u32;
        block[2 * i + 1] = (value >> 32) as u32;
    }
    block
}

#[inline]
pub(super) fn unpack_packed_cv<const LANES: usize>(
    cv: [[Felt; LANES]; DIGEST_WIDTH],
) -> [[u32; LANES]; 8] {
    let pairs = cv.map(|word| word.map(unpack_felt));
    array::from_fn(|lane_word| {
        array::from_fn(|lane| {
            let (lo, hi) = pairs[lane_word / 2][lane];
            if lane_word % 2 == 0 { lo } else { hi }
        })
    })
}

#[inline]
pub(super) fn unpack_packed_u64_cv<const LANES: usize>(
    cv: [[u64; LANES]; DIGEST_WIDTH],
) -> [[u32; LANES]; 8] {
    array::from_fn(|lane_word| {
        array::from_fn(|lane| {
            let value = cv[lane_word / 2][lane];
            if lane_word % 2 == 0 {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

#[inline]
pub(super) fn encode_packed_felt_block<const LANES: usize>(
    block: [[Felt; LANES]; BLOCK_LEN],
) -> [[u32; LANES]; 16] {
    let pairs = block.map(|values| values.map(unpack_felt));
    array::from_fn(|lane_word| {
        array::from_fn(|lane| {
            let (lo, hi) = pairs[lane_word / 2][lane];
            if lane_word % 2 == 0 { lo } else { hi }
        })
    })
}

#[inline]
#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx512f"))))]
pub(super) fn encode_packed_u64_block<const LANES: usize>(
    block: [[u64; LANES]; BLOCK_LEN],
) -> [[u32; LANES]; 16] {
    array::from_fn(|lane_word| {
        array::from_fn(|lane| {
            let value = block[lane_word / 2][lane];
            if lane_word % 2 == 0 {
                value as u32
            } else {
                (value >> 32) as u32
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_felt_preserves_canonical_boundary_bits() {
        for value in [0, 1, u32::MAX as u64, 1u64 << 32, 0x8000_0000_0000_0000, Felt::ORDER - 1] {
            let felt = Felt::new_unchecked(value);
            let (lo, hi) = unpack_felt(felt);
            assert_eq!(((hi as u64) << 32) | lo as u64, value);
        }
    }

    #[test]
    fn output_packing_masks_only_odd_lane_top_bits() {
        let cv = [
            0x1234_5678,
            0xffff_ffff,
            0x2345_6789,
            0x8000_0000,
            0x3456_789a,
            0x7fff_ffff,
            0x4567_89ab,
            0,
        ];
        let packed = output_cv_to_word(cv);
        let decoded = word_to_cv(packed);

        assert_eq!(decoded[0], cv[0]);
        assert_eq!(decoded[2], cv[2]);
        assert_eq!(decoded[4], cv[4]);
        assert_eq!(decoded[6], cv[6]);
        for odd in [1, 3, 5, 7] {
            assert_eq!(decoded[odd], cv[odd] & ODD_LANE_MASK);
        }
    }

    #[test]
    fn raw_word_and_block_decoding_is_lossless() {
        let block: [Felt; BLOCK_LEN] = array::from_fn(|i| {
            Felt::new_unchecked(((0x8000_0000u64 | (2 * i + 1) as u64) << 32) | (2 * i) as u64)
        });
        let word = Word::new(block[..DIGEST_WIDTH].try_into().unwrap());

        let decoded_word = word_to_cv(word);
        let decoded_block = felts_to_block(block);

        for (i, actual) in decoded_word.into_iter().enumerate() {
            assert_eq!(actual, i as u32 | if i % 2 == 1 { 0x8000_0000 } else { 0 });
        }
        for (i, actual) in decoded_block.into_iter().enumerate() {
            assert_eq!(actual, i as u32 | if i % 2 == 1 { 0x8000_0000 } else { 0 });
        }
    }
}
