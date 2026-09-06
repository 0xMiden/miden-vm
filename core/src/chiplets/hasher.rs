//! Low-level VM hasher helpers.

use core::ops::Range;

use miden_crypto::{
    Word as Digest,
    hash::eidos::{Eidos, EidosDomain, FeltSequence},
};

use super::{Felt, eidos_compression};

/// Number of Felts in the hasher state window.
pub const STATE_WIDTH: usize = eidos_compression::STATE_WIDTH;

/// Number of block Felts in one Eidos compression.
pub const BLOCK_LEN: usize = eidos_compression::BLOCK_LEN;

/// Number of Felts in an Eidos digest.
pub const DIGEST_LEN: usize = eidos_compression::DIGEST_WIDTH;

/// Number of trace transitions in one 32-row Eidos compression block.
pub const NUM_ROUNDS: usize = 31;

/// Range containing the low half of the compression block.
pub const BLOCK_LO_RANGE: Range<usize> = 0..4;
/// Range containing the high half of the compression block.
pub const BLOCK_HI_RANGE: Range<usize> = 4..8;
/// Range containing the chaining value.
pub const CV_RANGE: Range<usize> = 8..12;
/// Range containing the digest returned by the state window.
pub const DIGEST_RANGE: Range<usize> = CV_RANGE;

/// Compresses two words as a reserved Merkle inner node.
#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    Eidos::merge(values)
}

/// Hashes two words as an eight-Felt sequence under the generic Felt-sequence domain.
#[inline(always)]
pub fn hash_two_words(values: &[Digest; 2]) -> Digest {
    Eidos::hash_two_words(values)
}

/// Hashes an ordered list of words under the generic Felt-sequence domain.
#[inline(always)]
pub fn merge_many(values: &[Digest]) -> Digest {
    Eidos::merge_many(values)
}

/// Hashes a pair with the opcode-domain framing used by MAST control nodes.
///
/// This is separate from the registered Eidos domain-tag API.
#[inline(always)]
pub fn merge_in_mast_domain(values: &[Digest; 2], domain: Felt) -> Digest {
    let tag = u32::try_from(domain.as_canonical_u64()).expect("Eidos tag must fit in a u32");
    Eidos::compress(
        eidos_compression::two_to_one_chaining_word(tag),
        [
            values[0][0],
            values[0][1],
            values[0][2],
            values[0][3],
            values[1][0],
            values[1][1],
            values[1][2],
            values[1][3],
        ],
    )
}

/// Hashes a byte string under the generic byte-string domain.
#[inline(always)]
pub fn hash(bytes: &[u8]) -> Digest {
    Eidos::hash(bytes)
}

/// Hashes a Felt sequence under the generic Felt-sequence domain.
#[inline(always)]
pub fn hash_elements(elements: &[Felt]) -> Digest {
    Eidos::hash_elements(elements)
}

/// Hashes a Felt sequence under a registered Felt-sequence domain.
#[inline(always)]
pub fn hash_elements_in_domain<D>(elements: &[Felt], domain: D) -> Digest
where
    D: EidosDomain<Encoding = FeltSequence>,
{
    Eidos::hash_elements_in_domain(elements, domain)
}

/// Applies one Eidos compression to the VM's 12-Felt state window.
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
        let cv = eidos_compression::merkle_node_chaining_word();
        let mut state = [
            left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3], cv[0],
            cv[1], cv[2], cv[3],
        ];

        compress_state(&mut state);

        assert_eq!(&state[..4], left.as_slice());
        assert_eq!(&state[4..8], right.as_slice());
        assert_eq!(Digest::new(state[8..12].try_into().unwrap()), merge(&[left, right]));
    }

    #[test]
    fn two_word_hash_uses_generic_felt_framing() {
        let values = [
            Digest::new([
                Felt::new_unchecked(1),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
            ]),
            Digest::new([
                Felt::new_unchecked(0),
                Felt::new_unchecked(1),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
            ]),
        ];

        let expected = hash_elements(Digest::words_as_elements(&values));
        assert_eq!(hash_two_words(&values), expected);
        assert_ne!(hash_two_words(&values), merge(&values));
    }
}
