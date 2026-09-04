//! Eidos message framing and block scheduling.
//!
//! Eidos binds a registered domain tag and three domain-defined parameters into the
//! initial chaining value. The scheduler then compresses full blocks, zero-pads only a final
//! partial block, and represents an empty input by one all-zero block compression.

use super::{
    DIGEST_WIDTH, PACKED_LANES, domain::EidosDomain, domains::GenericFeltSequenceDomain, encoding,
    primitive::IV,
};
use crate::Felt;

pub(super) const GENERIC_FELT_TAG: u32 = GenericFeltSequenceDomain::TAG.as_u32();

/// Initial CV for the reserved fixed, one-block Merkle inner-node compression.
///
/// All four injected u32 lanes are zero. This construction is intentionally outside the domain
/// registry and must not be reused for ordinary Felt-sequence hashing.
pub(super) const MERKLE_NODE_INIT_CV: [u32; 8] = init_cv(0, [0; 3]);

/// Construct an Eidos initial chaining value from the BLAKE3 IV layout.
///
/// The tag and three domain-defined parameters occupy the four even u32 lanes. The four
/// odd lanes are fixed and masked, so the initial CV is already in the same 252-bit subspace as
/// every Eidos compression output. Each parameter may use its complete u32 lane.
pub(super) const fn init_cv(tag: u32, params: [u32; 3]) -> [u32; 8] {
    [
        tag,
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
pub(super) fn init_packed_cv(tag: u32, params: [u32; 3]) -> [[Felt; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = init_cv(tag, params);
    encoding::pack_cv_to_felts(core::array::from_fn(|word| [cv[word]; PACKED_LANES]))
}

#[inline]
pub(super) fn init_packed_u64_cv(
    tag: u32,
    params: [u32; 3],
) -> [[u64; PACKED_LANES]; DIGEST_WIDTH] {
    let cv = init_cv(tag, params);
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
    use crate::hash::eidos::domains::GenericByteStringDomain;

    #[test]
    fn initial_cv_is_derived_from_blake3_iv() {
        for (tag, params) in [(0, [0, 0, 0]), (u32::MAX, [u32::MAX; 3]), (7, [42, 11, 9])] {
            let cv = init_cv(tag, params);
            assert_eq!(cv[0], tag);
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
    fn registered_byte_and_felt_constructions_are_distinct_from_each_other_and_merkle() {
        let felt = init_cv(GENERIC_FELT_TAG, [0; 3]);
        let bytes = init_cv(GenericByteStringDomain::TAG.as_u32(), [0; 3]);
        assert_ne!(felt, bytes);
        assert_ne!(felt, MERKLE_NODE_INIT_CV);
        assert_ne!(bytes, MERKLE_NODE_INIT_CV);
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
