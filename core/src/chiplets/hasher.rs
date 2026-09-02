//! Low-level VM hasher helpers.

use core::ops::Range;

use miden_crypto::Word as Digest;

use super::{Felt, eidos_compression};

pub struct Hasher;

impl Hasher {
    pub const STATE_WIDTH: usize = eidos_compression::STATE_WIDTH;
    pub const BLOCK_LEN: usize = eidos_compression::BLOCK_LEN;
    pub const DIGEST_LEN: usize = eidos_compression::DIGEST_WIDTH;

    pub const BLOCK_LO_RANGE: Range<usize> = 0..4;
    pub const BLOCK_HI_RANGE: Range<usize> = 4..8;
    pub const CV_RANGE: Range<usize> = 8..12;
    pub const DIGEST_RANGE: Range<usize> = Self::CV_RANGE;

    #[inline(always)]
    pub fn merge(values: &[Digest; 2]) -> Digest {
        merge(values)
    }

    #[inline(always)]
    pub fn merge_many(values: &[Digest]) -> Digest {
        merge_many(values)
    }

    #[inline(always)]
    pub fn merge_in_domain(values: &[Digest; 2], domain: Felt) -> Digest {
        merge_in_domain(values, domain)
    }

    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Digest {
        hash(bytes)
    }

    #[inline(always)]
    pub fn hash_elements(elements: &[Felt]) -> Digest {
        hash_elements(elements)
    }

    #[inline(always)]
    pub fn hash_elements_in_domain(elements: &[Felt], domain: Felt) -> Digest {
        hash_elements_in_domain(elements, domain)
    }

    #[inline(always)]
    pub fn compress_state(state: &mut [Felt; STATE_WIDTH]) {
        compress_state(state)
    }
}

/// Number of Felts in the hasher state window.
pub const STATE_WIDTH: usize = eidos_compression::STATE_WIDTH;

/// Number of block Felts in one Eidos compression.
pub const BLOCK_LEN: usize = eidos_compression::BLOCK_LEN;

/// Number of trace transitions in one 32-row Eidos compression block.
pub const NUM_ROUNDS: usize = 31;

#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    eidos_compression::merge(values)
}

#[inline(always)]
pub fn merge_many(values: &[Digest]) -> Digest {
    eidos_compression::merge_many(values)
}

#[inline(always)]
pub fn merge_in_domain(values: &[Digest; 2], domain: Felt) -> Digest {
    eidos_compression::merge_in_domain(values, domain)
}

#[inline(always)]
pub fn hash(bytes: &[u8]) -> Digest {
    eidos_compression::hash(bytes)
}

#[inline(always)]
pub fn hash_elements(elements: &[Felt]) -> Digest {
    eidos_compression::hash_elements(elements)
}

#[inline(always)]
pub fn hash_elements_in_domain(elements: &[Felt], domain: Felt) -> Digest {
    eidos_compression::hash_elements_in_domain(elements, domain)
}

/// Apply one Eidos compression to the VM 12-Felt state window.
#[inline(always)]
pub fn compress_state(state: &mut [Felt; STATE_WIDTH]) {
    eidos_compression::compress_state(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_state_uses_eidos_compression_state_contract() {
        let left = Digest::new([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);
        let right = Digest::new([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]);
        let cv = eidos_compression::two_to_one_chaining_word(0);
        let mut state = [
            left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3], cv[0],
            cv[1], cv[2], cv[3],
        ];

        compress_state(&mut state);

        assert_eq!(&state[..4], left.as_slice());
        assert_eq!(&state[4..8], right.as_slice());
        assert_eq!(Digest::new(state[8..12].try_into().unwrap()), merge(&[left, right]));
    }
}
