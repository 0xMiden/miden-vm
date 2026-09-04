//! Raw Eidos compression over Goldilocks-encoded inputs.
//!
//! This module does not add Eidos framing, domain separation, length binding, or padding. The
//! caller supplies both the chaining value and one complete block. Arbitrary canonical field
//! elements are accepted in the input CV; only the output CV is placed in Eidos's 252-bit packed
//! subspace.

use super::{
    BLOCK_LEN, DIGEST_WIDTH, PACKED_LANES, PackedBlock, PackedChainingValue, encoding,
    primitive::CompressionCore,
};
use crate::{Felt, Word};

#[inline]
pub(super) fn compress_cv(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
    CompressionCore::compress(cv, block)
}

#[inline]
pub(super) fn compress_cv_packed(
    cv: &[[u32; PACKED_LANES]; 8],
    block: &[[u32; PACKED_LANES]; 16],
) -> [[u32; PACKED_LANES]; 8] {
    CompressionCore::compress_packed_native(cv, block)
}

#[inline]
pub(super) fn compress_xof_cv(cv: [u32; 8], block: [u32; 16]) -> [u32; 16] {
    CompressionCore::compress_raw_xof(cv, block)
}

#[inline]
pub(super) fn compress_felt_block(cv: Word, block: [Felt; BLOCK_LEN]) -> Word {
    let cv = encoding::word_to_cv(cv);
    let block = encoding::encode_felt_block(&block);
    encoding::output_cv_to_word(compress_cv(cv, block))
}

#[cfg(test)]
#[inline]
pub(super) fn compress_felt_block_for_test(
    cv: [Felt; DIGEST_WIDTH],
    block: [Felt; BLOCK_LEN],
) -> [Felt; DIGEST_WIDTH] {
    compress_felt_block(Word::new(cv), block).into()
}

#[inline]
pub(super) fn compress_packed_felt_cv(
    cv: &PackedChainingValue,
    block: &PackedBlock,
) -> PackedChainingValue {
    let cv = encoding::unpack_packed_cv(*cv);
    let block = encoding::encode_packed_felt_block(*block);
    encoding::pack_cv_to_felts(CompressionCore::compress_packed_native(&cv, &block))
}

#[inline]
pub(super) fn compress_u64_cv(cv: [u32; 8], block: [u64; BLOCK_LEN]) -> [u32; 8] {
    compress_cv(cv, encoding::encode_u64_block(&block))
}

#[inline]
pub(super) fn compress_packed_u64_cv(
    cv: &[[u64; PACKED_LANES]; DIGEST_WIDTH],
    block: &[[u64; PACKED_LANES]; BLOCK_LEN],
) -> [[u64; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = encoding::unpack_packed_u64_cv(*cv);

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    let block = avx512_u64_adapter::unpack_block(*block);

    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
    let block = encoding::encode_packed_u64_block(*block);

    let output = CompressionCore::compress_packed_native(&cv, &block);

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    {
        avx512_u64_adapter::pack_cv(output)
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512f")))]
    {
        encoding::pack_cv_to_packed_u64s(output)
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
mod avx512_u64_adapter {
    use core::arch::x86_64::*;

    use super::{BLOCK_LEN, DIGEST_WIDTH, PACKED_LANES};

    const LANES: usize = PACKED_LANES;
    const HALF_LANES: usize = LANES / 2;
    const _: () = assert!(LANES == 16, "the AVX-512 adapter requires sixteen packed lanes");

    #[inline]
    pub(super) fn unpack_block(block: [[u64; LANES]; BLOCK_LEN]) -> [[u32; LANES]; 16] {
        let mut output = [[0u32; LANES]; 16];

        for (element, values) in block.iter().enumerate() {
            for half in 0..2 {
                let lane_offset = half * HALF_LANES;
                // SAFETY: this module is compiled only with AVX-512F enabled. `lane_offset` is
                // either 0 or 8, so the unaligned eight-u64 load remains within `values`.
                let packed = unsafe {
                    _mm512_loadu_si512(values.as_ptr().add(lane_offset).cast::<__m512i>())
                };
                // SAFETY: these AVX-512F operations only transform the loaded register. Signed
                // narrowing is intentional: both conversions retain the low 32 bits.
                let (lo, hi) = unsafe {
                    (
                        _mm512_cvtepi64_epi32(packed),
                        _mm512_cvtepi64_epi32(_mm512_srli_epi64::<32>(packed)),
                    )
                };

                // SAFETY: `lane_offset` is either 0 or 8, so each unaligned eight-u32 store
                // remains within its sixteen-element output row.
                unsafe {
                    _mm256_storeu_si256(
                        output[2 * element].as_mut_ptr().add(lane_offset).cast::<__m256i>(),
                        lo,
                    );
                    _mm256_storeu_si256(
                        output[2 * element + 1].as_mut_ptr().add(lane_offset).cast::<__m256i>(),
                        hi,
                    );
                }
            }
        }

        output
    }

    #[inline]
    pub(super) fn pack_cv(cv: [[u32; LANES]; 8]) -> [[u64; LANES]; DIGEST_WIDTH] {
        let mut output = [[0u64; LANES]; DIGEST_WIDTH];
        // SAFETY: this module is compiled only with AVX-512F enabled.
        let high_mask = unsafe { _mm512_set1_epi64(super::encoding::ODD_LANE_MASK as i64) };

        for word in 0..DIGEST_WIDTH {
            for half in 0..2 {
                let lane_offset = half * HALF_LANES;
                // SAFETY: `lane_offset` is either 0 or 8, so both unaligned eight-u32 loads
                // remain within their sixteen-element CV rows.
                let lo32 = unsafe {
                    _mm256_loadu_si256(cv[2 * word].as_ptr().add(lane_offset).cast::<__m256i>())
                };
                let hi32 = unsafe {
                    _mm256_loadu_si256(cv[2 * word + 1].as_ptr().add(lane_offset).cast::<__m256i>())
                };
                // SAFETY: these AVX-512F operations only transform registers. The high word is
                // masked to preserve the canonical 63-bit field-element encoding.
                let packed = unsafe {
                    let lo64 = _mm512_cvtepu32_epi64(lo32);
                    let hi64 = _mm512_and_si512(_mm512_cvtepu32_epi64(hi32), high_mask);
                    _mm512_or_si512(lo64, _mm512_slli_epi64::<32>(hi64))
                };

                // SAFETY: `lane_offset` is either 0 or 8, so the unaligned eight-u64 store
                // remains within its sixteen-element output row.
                unsafe {
                    _mm512_storeu_si512(
                        output[word].as_mut_ptr().add(lane_offset).cast::<__m512i>(),
                        packed,
                    );
                }
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use core::array;

    use super::*;
    #[test]
    fn raw_compression_accepts_unmasked_input_cv() {
        let cv = Word::new([
            Felt::new_unchecked(0x8000_0001_0000_0021),
            Felt::new_unchecked(0x0000_0043_8000_0022),
            Felt::new_unchecked(0x0000_0065_0000_0023),
            Felt::new_unchecked(0x0000_0087_0000_0024),
        ]);
        let block = array::from_fn(|i| {
            Felt::new_unchecked(((0x8000_0000u64 | (i as u64 + 1)) << 32) | i as u64)
        });

        let expected = encoding::output_cv_to_word(CompressionCore::compress(
            encoding::word_to_cv(cv),
            encoding::encode_felt_block(&block),
        ));
        assert_eq!(super::super::Eidos::compress(cv, block), expected);
    }

    #[test]
    fn compress_xof_returns_raw_u32_lanes_as_felts() {
        let cv = Word::new(array::from_fn(|i| Felt::new_unchecked((i as u64 + 1) << 32)));
        let block = array::from_fn(|i| Felt::new_unchecked((i as u64 + 1) * 17));

        let expected = CompressionCore::compress_raw_xof(
            encoding::word_to_cv(cv),
            encoding::encode_felt_block(&block),
        )
        .map(Felt::from_u32);

        assert_eq!(super::super::Eidos::compress_xof(cv, block), expected);
        assert!(expected.iter().all(|value| u32::try_from(value.as_canonical_u64()).is_ok()));
    }

    #[test]
    fn packed_compression_matches_scalar_lanes() {
        let packed_cv: PackedChainingValue = array::from_fn(|word| {
            array::from_fn(|lane| Felt::new_unchecked((word * 101 + lane * 17 + 3) as u64))
        });
        let packed_block: PackedBlock = array::from_fn(|element| {
            array::from_fn(|lane| Felt::new_unchecked((element * 97 + lane * 13 + 5) as u64))
        });
        let packed = super::super::Eidos::compress_packed(packed_cv, packed_block);

        for lane in 0..PACKED_LANES {
            let cv = Word::new(array::from_fn(|word| packed_cv[word][lane]));
            let block = array::from_fn(|element| packed_block[element][lane]);
            let scalar = super::super::Eidos::compress(cv, block);
            let actual = Word::new(array::from_fn(|word| packed[word][lane]));
            assert_eq!(actual, scalar, "packed lane {lane} diverged");
        }
    }

    #[test]
    fn packed_u64_adapter_matches_scalar_lanes_for_mixed_bits() {
        let cv = super::super::framing::init_packed_u64_cv(0, [0; 3]);
        for batch in 0..32 {
            let block = mixed_packed_u64_block(batch);
            let packed = compress_packed_u64_cv(&cv, &block);

            for lane in 0..PACKED_LANES {
                let scalar_cv = array::from_fn(|word| cv[word][lane]);
                let scalar_block = array::from_fn(|element| block[element][lane]);
                let scalar = encoding::pack_cv_to_u64s(compress_u64_cv(
                    encoding::unpack_u64_cv(scalar_cv),
                    scalar_block,
                ));
                let packed_lane = array::from_fn(|word| packed[word][lane]);
                assert_eq!(packed_lane, scalar, "packed lane {lane} diverged in batch {batch}");
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn avx512_u64_adapter_matches_generic_layout() {
        for batch in 0..32 {
            let block = mixed_packed_u64_block(batch);
            assert_eq!(
                avx512_u64_adapter::unpack_block(block),
                encoding::encode_packed_u64_block(block),
                "AVX-512 input adapter diverged in batch {batch}",
            );

            let cv =
                array::from_fn(|word| array::from_fn(|lane| mixed_u64(batch, word, lane) as u32));
            assert_eq!(
                avx512_u64_adapter::pack_cv(cv),
                encoding::pack_cv_to_packed_u64s(cv),
                "AVX-512 output adapter diverged in batch {batch}",
            );
        }
    }

    fn mixed_packed_u64_block(batch: usize) -> [[u64; PACKED_LANES]; BLOCK_LEN] {
        const BOUNDARIES: [u64; 8] = [
            0,
            1,
            u32::MAX as u64,
            1u64 << 32,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0xffff_ffff_0000_0001,
            u64::MAX,
        ];

        array::from_fn(|element| {
            array::from_fn(|lane| {
                if batch == 0 {
                    BOUNDARIES[(element * PACKED_LANES + lane) % BOUNDARIES.len()]
                } else {
                    mixed_u64(batch, element, lane)
                }
            })
        })
    }

    fn mixed_u64(batch: usize, element: usize, lane: usize) -> u64 {
        let mut value = (batch as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add((element as u64) << 32)
            .wrapping_add(lane as u64);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}
