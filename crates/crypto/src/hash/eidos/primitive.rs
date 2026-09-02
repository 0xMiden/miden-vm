//! Goldilocks-tailored BLAKE3 compression.
//!
//! Eidos uses BLAKE3's seven-round compression schedule with fixed parameter words.
//! `compress` clears the top bit of odd output lanes so the 8-word chaining
//! value packs losslessly into four Goldilocks field elements:
//! `pack(lo, hi) = ((hi & 0x7fff_ffff) << 32) | lo`.

mod blake3_schedule;

pub(super) const IV: [u32; 8] = blake3_schedule::IV;
pub(super) const PACKED_LANES: usize = blake3_schedule::PACKED_LANES;

use super::encoding::ODD_LANE_MASK;

#[inline(always)]
fn apply_output_mask(cv: &mut [u32; 8]) {
    cv[1] &= ODD_LANE_MASK;
    cv[3] &= ODD_LANE_MASK;
    cv[5] &= ODD_LANE_MASK;
    cv[7] &= ODD_LANE_MASK;
}

#[inline(always)]
fn apply_packed_output_mask<const LANES: usize>(cv: &mut [[u32; LANES]; 8]) {
    for word in [1, 3, 5, 7] {
        for lane in cv[word].iter_mut() {
            *lane &= ODD_LANE_MASK;
        }
    }
}

/// Goldilocks-tailored BLAKE3 compression.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct CompressionCore;

impl CompressionCore {
    /// Apply the Eidos compression core and mask the odd output lanes.
    ///
    /// The input chaining value may contain arbitrary `u32` lanes. The
    /// Goldilocks subspace mask is an output-finalization rule, not an input
    /// invariant.
    pub(super) fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        let mut cv_new = Self::compress_raw(cv, block);
        apply_output_mask(&mut cv_new);
        cv_new
    }

    /// Apply the compression function without the Goldilocks output mask.
    ///
    /// Returns the eight folded BLAKE3-derived output words:
    ///
    /// ```text
    /// out[i] = v[i] ^ v[i + 8]
    /// ```
    ///
    /// These are the words consumed by [`Self::compress`] before odd-lane masking.
    /// This is a raw compression output, not an Eidos digest. Callers that build a construction
    /// from it must bind the construction's complete context into the input CV.
    pub fn compress_raw(cv: [u32; 8], block: [u32; 16]) -> [u32; 8] {
        blake3_schedule::compress_raw(cv, block)
    }

    /// Return the full 16-word XOF output (low half || high half), without the Goldilocks output
    /// mask.
    ///
    /// ```text
    /// out[i]     = v[i] ^ v[i + 8]    (i in 0..8)   // standard CV fold (low half)
    /// out[i + 8] = v[i + 8] ^ cv[i]   (i in 0..8)   // BLAKE3 XOF feed-forward (high half)
    /// ```
    ///
    /// The low half is [`Self::compress_raw`]. The high half is BLAKE3's XOF feed-forward. This is
    /// raw XOF material, not a canonical field digest. Callers that expose it as XOF output must
    /// bind the construction's complete context into the input CV.
    pub fn compress_raw_xof(cv: [u32; 8], block: [u32; 16]) -> [u32; 16] {
        blake3_schedule::compress_raw_xof(cv, block)
    }

    /// Apply compression to several independent lanes with the same instruction stream.
    ///
    /// Lane `i` of the result is identical to `compress(cv_i, block_i)`, where
    /// `cv_i[j] = cv[j][i]` and `block_i[j] = block[j][i]`.
    #[cfg(test)]
    fn compress_packed<const LANES: usize>(
        cv: [[u32; LANES]; 8],
        block: [[u32; LANES]; 16],
    ) -> [[u32; LANES]; 8] {
        let mut cv_new = blake3_schedule::compress_packed(cv, block);
        apply_packed_output_mask(&mut cv_new);
        cv_new
    }

    /// Apply compression to the build's selected native packed lane width.
    #[inline]
    pub(super) fn compress_packed_native(
        cv: [[u32; PACKED_LANES]; 8],
        block: [[u32; PACKED_LANES]; 16],
    ) -> [[u32; PACKED_LANES]; 8] {
        let mut cv_new = blake3_schedule::compress_packed_native(cv, block);
        apply_packed_output_mask(&mut cv_new);
        cv_new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chaining value whose odd lanes already fit the field-packing mask.
    const TEST_CV: [u32; 8] = [
        0x6a09_e667,
        0x3b67_ae85, // IV[1] with top bit cleared
        0x3c6e_f372,
        0x254f_f53a, // IV[3] with top bit cleared
        0x0000_0000,
        0x1b05_688c, // IV[5] with top bit cleared
        0x0000_0000,
        0x5be0_cd19, // IV[7] (top bit already 0)
    ];

    fn test_block() -> [u32; 16] {
        core::array::from_fn(|i| 0x1020_3040u32.wrapping_add((i as u32).wrapping_mul(0x0102_0304)))
    }

    fn block_words_to_bytes(block: [u32; 16]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for (word, out) in block.iter().zip(bytes.chunks_exact_mut(4)) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn words_to_bytes(words: [u32; 8]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (word, out) in words.iter().zip(bytes.chunks_exact_mut(4)) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn reference_core_with_p(cv: [u32; 8], block: [u32; 16], p: [u32; 4]) -> [u32; 8] {
        blake3_schedule::compress_raw_with_parameter_words(cv, block, p)
    }

    fn reference_core_xof_with_p(cv: [u32; 8], block: [u32; 16], p: [u32; 4]) -> [u32; 16] {
        blake3_schedule::compress_raw_xof_with_parameter_words(cv, block, p)
    }

    fn standard_blake3_compress(
        cv: [u32; 8],
        block: [u32; 16],
        counter: u64,
        block_len: u8,
        flags: u8,
    ) -> [u32; 8] {
        let mut out = cv;
        blake3::platform::Platform::Portable.compress_in_place(
            &mut out,
            &block_words_to_bytes(block),
            block_len,
            counter,
            flags,
        );
        out
    }

    fn mask_odd_lanes(cv: &mut [u32; 8]) {
        cv[1] &= ODD_LANE_MASK;
        cv[3] &= ODD_LANE_MASK;
        cv[5] &= ODD_LANE_MASK;
        cv[7] &= ODD_LANE_MASK;
    }

    #[test]
    fn reference_core_matches_standard_blake3_compression() {
        let cv = TEST_CV;
        let block = test_block();
        let counter = 0x0123_4567_89ab_cdefu64;
        let block_len = 64u8;
        let flags = 0x0bu8;

        let official = standard_blake3_compress(cv, block, counter, block_len, flags);
        let reference = reference_core_with_p(
            cv,
            block,
            [counter as u32, (counter >> 32) as u32, block_len as u32, flags as u32],
        );

        assert_eq!(reference, official);
    }

    #[test]
    fn standard_compression_oracle_matches_public_blake3_hash_for_one_block() {
        const CHUNK_START: u8 = 1 << 0;
        const CHUNK_END: u8 = 1 << 1;
        const ROOT: u8 = 1 << 3;

        let block = test_block();
        let bytes = block_words_to_bytes(block);
        let compressed = standard_blake3_compress(IV, block, 0, 64, CHUNK_START | CHUNK_END | ROOT);

        assert_eq!(words_to_bytes(compressed), *blake3::hash(&bytes).as_bytes());
    }

    #[test]
    fn eidos_compression_is_blake3_core_with_fixed_iv_tail_and_mask() {
        let cv = TEST_CV;
        let block = test_block();
        let mut expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        mask_odd_lanes(&mut expected);

        assert_eq!(CompressionCore::compress(cv, block), expected);
    }

    #[test]
    fn compress_raw_is_blake3_fold_with_fixed_iv_tail() {
        let cv = TEST_CV;
        let block = test_block();
        let expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        assert_eq!(CompressionCore::compress_raw(cv, block), expected);
    }

    #[test]
    fn xof_reference_matches_official_blake3_compress_xof() {
        let cv = TEST_CV;
        let block = test_block();
        let counter = 0x0123_4567_89ab_cdefu64;
        let block_len = 64u8;
        let flags = 0x0bu8;

        let xof_bytes = blake3::platform::Platform::Portable.compress_xof(
            &cv,
            &block_words_to_bytes(block),
            block_len,
            counter,
            flags,
        );
        let official: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(xof_bytes[4 * i..4 * i + 4].try_into().unwrap())
        });
        let reference = reference_core_xof_with_p(
            cv,
            block,
            [counter as u32, (counter >> 32) as u32, block_len as u32, flags as u32],
        );

        assert_eq!(reference, official);
    }

    #[test]
    fn compress_raw_xof_is_blake3_xof_with_fixed_iv_tail() {
        let cv = TEST_CV;
        let block = test_block();
        let xof = CompressionCore::compress_raw_xof(cv, block);

        // Low half is identical to the folded raw output.
        assert_eq!(&xof[..8], &CompressionCore::compress_raw(cv, block));

        // Full 16 words match the BLAKE3 XOF reference with Eidos's fixed IV tail.
        let expected = reference_core_xof_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);
        assert_eq!(xof, expected);
    }

    #[test]
    fn compress_raw_then_mask_matches_compress() {
        let cv = TEST_CV;
        let block = test_block();
        let mut raw = CompressionCore::compress_raw(cv, block);

        apply_output_mask(&mut raw);

        assert_eq!(raw, CompressionCore::compress(cv, block));
    }

    #[test]
    fn compress_accepts_unmasked_input_cv_lanes() {
        let mut cv = TEST_CV;
        cv[1] |= 0x8000_0000;
        cv[3] |= 0x8000_0000;
        cv[5] |= 0x8000_0000;
        cv[7] |= 0x8000_0000;
        let block = test_block();
        let mut expected = reference_core_with_p(cv, block, [IV[4], IV[5], IV[6], IV[7]]);

        mask_odd_lanes(&mut expected);

        assert_eq!(CompressionCore::compress(cv, block), expected);
    }

    #[test]
    fn standard_blake3_compression_is_not_eidos_compression() {
        let cv = TEST_CV;
        let block = test_block();
        let mut standard = standard_blake3_compress(cv, block, 0, 64, 0);

        mask_odd_lanes(&mut standard);

        assert_ne!(CompressionCore::compress(cv, block), standard);
    }

    #[test]
    fn compress_output_lives_in_252_bit_subspace() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32 + 1);
        let cv_new = CompressionCore::compress(TEST_CV, block);

        assert_eq!(cv_new[1] & !ODD_LANE_MASK, 0, "cv_new[1] top bit must be 0");
        assert_eq!(cv_new[3] & !ODD_LANE_MASK, 0, "cv_new[3] top bit must be 0");
        assert_eq!(cv_new[5] & !ODD_LANE_MASK, 0, "cv_new[5] top bit must be 0");
        assert_eq!(cv_new[7] & !ODD_LANE_MASK, 0, "cv_new[7] top bit must be 0");
    }

    #[test]
    fn compress_is_deterministic() {
        let block: [u32; 16] = core::array::from_fn(|i| i as u32);
        assert_eq!(
            CompressionCore::compress(TEST_CV, block),
            CompressionCore::compress(TEST_CV, block)
        );
    }

    #[test]
    fn different_blocks_produce_different_outputs() {
        let block_a = [0u32; 16];
        let mut block_b = [0u32; 16];
        block_b[0] = 1;
        assert_ne!(
            CompressionCore::compress(TEST_CV, block_a),
            CompressionCore::compress(TEST_CV, block_b)
        );
    }

    #[test]
    fn different_cvs_produce_different_outputs() {
        let mut cv_b = TEST_CV;
        cv_b[0] = 0;
        let block = [0u32; 16];
        assert_ne!(
            CompressionCore::compress(TEST_CV, block),
            CompressionCore::compress(cv_b, block)
        );
    }

    #[test]
    fn compress_packed_4_matches_scalar_lanes() {
        const LANES: usize = 4;

        let cvs: [[u32; 8]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| TEST_CV[i].wrapping_add((lane as u32) << (i % 7)))
        });
        let blocks: [[u32; 16]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| {
                0x1020_3040u32
                    .wrapping_add((lane as u32).wrapping_mul(0x1111_1111))
                    .wrapping_add((i as u32).wrapping_mul(0x0102_0304))
            })
        });

        let packed_cv: [[u32; LANES]; 8] =
            core::array::from_fn(|word| core::array::from_fn(|lane| cvs[lane][word]));
        let packed_block: [[u32; LANES]; 16] =
            core::array::from_fn(|word| core::array::from_fn(|lane| blocks[lane][word]));
        let packed_out = CompressionCore::compress_packed(packed_cv, packed_block);

        for lane in 0..LANES {
            let scalar = CompressionCore::compress(cvs[lane], blocks[lane]);
            let packed_lane: [u32; 8] = core::array::from_fn(|word| packed_out[word][lane]);
            assert_eq!(packed_lane, scalar);
        }
    }

    #[test]
    fn compress_packed_native_matches_scalar_lanes() {
        const LANES: usize = PACKED_LANES;

        let cvs: [[u32; 8]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| TEST_CV[i].wrapping_add((lane as u32) << (i % 7)))
        });
        let blocks: [[u32; 16]; LANES] = core::array::from_fn(|lane| {
            core::array::from_fn(|i| {
                0x1020_3040u32
                    .wrapping_add((lane as u32).wrapping_mul(0x1111_1111))
                    .wrapping_add((i as u32).wrapping_mul(0x0102_0304))
            })
        });

        let packed_cv: [[u32; LANES]; 8] =
            core::array::from_fn(|word| core::array::from_fn(|lane| cvs[lane][word]));
        let packed_block: [[u32; LANES]; 16] =
            core::array::from_fn(|word| core::array::from_fn(|lane| blocks[lane][word]));
        let portable = CompressionCore::compress_packed(packed_cv, packed_block);
        let native = CompressionCore::compress_packed_native(packed_cv, packed_block);

        for lane in 0..LANES {
            let scalar = CompressionCore::compress(cvs[lane], blocks[lane]);
            let portable_lane: [u32; 8] = core::array::from_fn(|word| portable[word][lane]);
            let native_lane: [u32; 8] = core::array::from_fn(|word| native[word][lane]);
            assert_eq!(portable_lane, scalar);
            assert_eq!(native_lane, scalar);
        }
    }
}
