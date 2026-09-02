//! Eidos message framing and block scheduling.
//!
//! Eidos binds a registered construction selector and three selector-defined parameters into the
//! initial chaining value. The scheduler then compresses full blocks, zero-pads only a final
//! partial block, and represents an empty input by one all-zero block compression.

use super::{BLOCK_LEN, DIGEST_WIDTH, PACKED_LANES, encoding, primitive::IV};
use crate::Felt;

/// Registered selector for the Eidos byte-string construction.
///
/// This uses domain id `0x000003`, version 1, from the miden-crypto registry range. Felt-sequence
/// hashing uses selector zero or an explicitly supplied registered selector.
const BYTE_STRING_DOMAIN_ID: u32 = 0x000003;
pub(super) const BYTE_STRING_SELECTOR: u32 = (BYTE_STRING_DOMAIN_ID << 8) | 1;

pub(super) const FELT_BLOCK_INIT_CV: [u32; 8] = init_cv_unchecked(0, [BLOCK_LEN as u32, 0, 0]);

const FELT_INIT_CV: [u32; 8] = init_cv_unchecked(0, [0; 3]);

/// Felt-sequence initial chaining word before compressing the required zero block for empty input.
pub(super) const FELT_INIT_CV_U64: [u64; DIGEST_WIDTH] = [
    encoding::pack_output_pair_u64(FELT_INIT_CV[0], FELT_INIT_CV[1]),
    encoding::pack_output_pair_u64(FELT_INIT_CV[2], FELT_INIT_CV[3]),
    encoding::pack_output_pair_u64(FELT_INIT_CV[4], FELT_INIT_CV[5]),
    encoding::pack_output_pair_u64(FELT_INIT_CV[6], FELT_INIT_CV[7]),
];

#[inline]
pub(super) fn selector_to_u32(selector: Felt) -> u32 {
    let selector = selector.as_canonical_u64();
    assert!(u32::try_from(selector).is_ok(), "selector must fit in a u32");
    selector as u32
}

/// Construct an Eidos initial chaining value from the BLAKE3 IV layout.
///
/// The selector and three selector-defined parameters occupy the four even u32 lanes. The four
/// odd lanes are fixed and masked, so the initial CV is already in the same 252-bit subspace as
/// every Eidos compression output. Each parameter may use its complete u32 lane.
#[inline]
pub(super) fn init_cv(selector: u32, params: [u32; 3]) -> [u32; 8] {
    init_cv_unchecked(selector, params)
}

const fn init_cv_unchecked(selector: u32, params: [u32; 3]) -> [u32; 8] {
    [
        selector,
        IV[1] & encoding::ODD_LANE_MASK,
        params[0],
        IV[3] & encoding::ODD_LANE_MASK,
        params[1],
        IV[5] & encoding::ODD_LANE_MASK,
        params[2],
        IV[7] & encoding::ODD_LANE_MASK,
    ]
}

#[inline]
pub(super) fn init_packed_cv(
    selector: u32,
    params: [u32; 3],
) -> [[Felt; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = init_cv(selector, params);
    encoding::pack_cv_to_felts(core::array::from_fn(|word| [cv[word]; PACKED_LANES]))
}

#[inline]
pub(super) fn init_packed_u64_cv(
    selector: u32,
    params: [u32; 3],
) -> [[u64; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = init_cv(selector, params);
    encoding::pack_cv_to_packed_u64s(core::array::from_fn(|word| [cv[word]; PACKED_LANES]))
}

/// Fold an exact logical input into fixed-size, zero-padded physical blocks.
///
/// Empty inputs emit exactly one all-zero block. A non-empty exact multiple emits no extra block.
/// The item count is checked against `expected_len`, preserving the `CryptographicHasher`
/// contract for iterators with dishonest exact size hints.
#[inline]
pub(super) fn fold_blocks<const BLOCK_LEN: usize, I, State>(
    iter: I,
    expected_len: usize,
    mut state: State,
    zero: I::Item,
    mut compress: impl FnMut(State, [I::Item; BLOCK_LEN]) -> State,
) -> State
where
    I: Iterator,
    I::Item: Copy,
{
    let mut block = [zero; BLOCK_LEN];
    let mut pos = 0usize;
    let mut count = 0usize;

    for value in iter {
        block[pos] = value;
        pos += 1;
        count += 1;

        if pos == BLOCK_LEN {
            state = compress(state, block);
            pos = 0;
        }
    }

    assert_eq!(count, expected_len, "iterator yielded a different length than its size_hint");

    if pos != 0 {
        block[pos..].fill(zero);
    }

    if count == 0 || pos != 0 {
        state = compress(state, block);
    }

    state
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn initial_cv_is_derived_from_blake3_iv() {
        for (selector, params) in [(0, [0, 0, 0]), (u32::MAX, [u32::MAX; 3]), (7, [42, 11, 9])] {
            let cv = init_cv(selector, params);
            assert_eq!(cv[0], selector);
            assert_eq!(cv[1], IV[1] & encoding::ODD_LANE_MASK);
            assert_eq!(cv[2], params[0]);
            assert_eq!(cv[3], IV[3] & encoding::ODD_LANE_MASK);
            assert_eq!(cv[4], params[1]);
            assert_eq!(cv[5], IV[5] & encoding::ODD_LANE_MASK);
            assert_eq!(cv[6], params[2]);
            assert_eq!(cv[7], IV[7] & encoding::ODD_LANE_MASK);
        }
    }

    #[test]
    fn byte_and_felt_constructions_use_distinct_selectors() {
        assert_ne!(init_cv(0, [0; 3]), init_cv(BYTE_STRING_SELECTOR, [0; 3]));
    }

    #[test]
    fn felt_init_cv_u64_matches_initial_cv() {
        assert_eq!(FELT_INIT_CV_U64, encoding::pack_cv_to_u64s(FELT_INIT_CV));
    }

    #[test]
    fn block_schedule_handles_boundaries_canonically() {
        for len in [0, 1, 7, 8, 9, 15, 16, 17] {
            let input: Vec<u32> = (1..=len as u32).collect();
            let blocks = fold_blocks::<8, _, _>(
                input.iter().copied(),
                len,
                Vec::new(),
                0,
                |mut blocks, block| {
                    blocks.push(block);
                    blocks
                },
            );

            let expected_blocks = if len == 0 { 1 } else { len.div_ceil(8) };
            assert_eq!(blocks.len(), expected_blocks);
            assert_eq!(blocks.concat()[..len], input);
            assert!(blocks.concat()[len..].iter().all(|value| *value == 0));
        }
    }

    #[test]
    #[should_panic(expected = "iterator yielded a different length than its size_hint")]
    fn block_schedule_rejects_too_few_items() {
        fold_blocks::<8, _, _>([1, 2].into_iter(), 3, (), 0, |(), _| ());
    }

    #[test]
    #[should_panic(expected = "iterator yielded a different length than its size_hint")]
    fn block_schedule_rejects_too_many_items() {
        fold_blocks::<8, _, _>([1, 2, 3].into_iter(), 2, (), 0, |(), _| ());
    }
}
