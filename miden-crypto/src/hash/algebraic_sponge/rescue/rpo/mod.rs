use super::{
    ARK1, ARK2, AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, Felt, MDS, NUM_ROUNDS, RATE_RANGE,
    RATE0_RANGE, RATE1_RANGE, Range, STATE_WIDTH, Word, add_constants,
    add_constants_and_apply_inv_sbox, add_constants_and_apply_sbox, apply_inv_sbox, apply_mds,
    apply_sbox,
};

#[cfg(test)]
mod tests;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Rescue Prime Optimized hash function with 256-bit output.
///
/// The hash function is implemented according to the Rescue Prime Optimized
/// [specifications](https://eprint.iacr.org/2022/1577) while the padding rule follows the one
/// described [here](https://eprint.iacr.org/2023/1045).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus p = 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Rate size: r = 8 field elements.
/// * Capacity size: c = 4 field elements.
/// * Number of founds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rpo256::hash_elements), and [merge()](Rpo256::merge), are internally
/// consistent. That is, computing a hash for the same set of elements using these functions will
/// always produce the same result. For example, merging two digests using [merge()](Rpo256::merge)
/// will produce the same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rpo256::hash_elements) function.
///
/// However, [hash()](Rpo256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rpo256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rpo256::hash_elements) function. The reason for
/// this difference is that [hash()](Rpo256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rpo256::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Rpo256::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Rpo256::merge_in_domain) hashes two digests into one digest with some domain
/// identifier and the current implementation sets the second capacity element to the value of
/// this domain identifier. Using a similar argument to the one formulated for domain separation of
/// the RPX hash function in Appendix C of its [specification](https://eprint.iacr.org/2023/1045),
/// one sees that doing so degrades only pre-image resistance, from its initial bound of c.log_2(p),
/// by as much as the log_2 of the size of the domain identifier space. Since pre-image resistance
/// becomes the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the RPO permutation when hashing empty input.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpo256();

impl AlgebraicSponge for Rpo256 {
    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    #[inline(always)]
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }
}

impl Rpo256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Target collision resistance level in bits.
    pub const COLLISION_RESISTANCE: u32 = 128;

    /// The number of rounds is set to 7 to target 128-bit security level.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for the
    /// rate and the remaining 4 elements are reserved for the capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The first 4-element word of the rate portion.
    pub const RATE0_RANGE: Range<usize> = RATE0_RANGE;

    /// The second 4-element word of the rate portion.
    pub const RATE1_RANGE: Range<usize> = RATE1_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 0, 1, 2, and 3 (the first
    /// word of the state).
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a RPO round.
    pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Round constants added to the hasher state in the first half of the RPO round.
    pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the RPO round.
    pub const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK2;

    // HASH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Word {
        <Self as AlgebraicSponge>::hash(bytes)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: crate::field::BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        <Self as AlgebraicSponge>::hash_elements(elements)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Word; 2]) -> Word {
        <Self as AlgebraicSponge>::merge(values)
    }

    /// Returns a hash of multiple digests.
    #[inline(always)]
    pub fn merge_many(values: &[Word]) -> Word {
        <Self as AlgebraicSponge>::merge_many(values)
    }

    /// Returns a hash of two digests and a domain identifier.
    #[inline(always)]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        <Self as AlgebraicSponge>::merge_in_domain(values, domain)
    }

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }

    /// RPO round function.
    #[inline(always)]
    pub fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        // apply first half of RPO round
        apply_mds(state);
        if !add_constants_and_apply_sbox(state, &ARK1[round]) {
            add_constants(state, &ARK1[round]);
            apply_sbox(state);
        }

        // apply second half of RPO round
        apply_mds(state);
        if !add_constants_and_apply_inv_sbox(state, &ARK2[round]) {
            add_constants(state, &ARK2[round]);
            apply_inv_sbox(state);
        }
    }
}

// PLONKY3 INTEGRATION
// ================================================================================================

/// Plonky3-compatible RPO permutation implementation.
///
/// This module provides a Plonky3-compatible interface to the RPO256 hash function,
/// implementing the `Permutation` and `CryptographicPermutation` traits from Plonky3.
///
/// This allows RPO to be used with Plonky3's cryptographic infrastructure, including:
/// - PaddingFreeSponge for hashing
/// - TruncatedPermutation for compression
/// - DuplexChallenger for Fiat-Shamir transforms
use p3_challenger::DuplexChallenger;
use p3_symmetric::{
    CryptographicPermutation, PaddingFreeSponge, Permutation, TruncatedPermutation,
};

// RPO PERMUTATION FOR PLONKY3
// ================================================================================================

/// Plonky3-compatible RPO permutation.
///
/// This struct wraps the RPO256 permutation and implements Plonky3's `Permutation` and
/// `CryptographicPermutation` traits, allowing RPO to be used within the Plonky3 ecosystem.
///
/// The permutation operates on a state of 12 field elements (STATE_WIDTH = 12), with:
/// - Rate: 8 elements (positions 0-7)
/// - Capacity: 4 elements (positions 8-11)
/// - Digest output: 4 elements (positions 0-3)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RpoPermutation256;

impl RpoPermutation256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level.
    pub const NUM_ROUNDS: usize = Rpo256::NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = Rpo256::RATE_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = Rpo256::CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 0, 1, 2, and 3.
    pub const DIGEST_RANGE: Range<usize> = Rpo256::DIGEST_RANGE;

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    ///
    /// This delegates to the RPO256 implementation which applies 7 rounds of the
    /// Rescue Prime Optimized permutation.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Rpo256::apply_permutation(state);
    }
}

// PLONKY3 TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Permutation<[Felt; STATE_WIDTH]> for RpoPermutation256 {
    fn permute_mut(&self, state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_permutation(state);
    }
}

impl CryptographicPermutation<[Felt; STATE_WIDTH]> for RpoPermutation256 {}

// TYPE ALIASES FOR PLONKY3 INTEGRATION
// ================================================================================================

/// RPO-based hasher using Plonky3's PaddingFreeSponge.
///
/// This provides a sponge-based hash function with:
/// - WIDTH: 12 field elements (total state size)
/// - RATE: 8 field elements (input/output rate)
/// - OUT: 4 field elements (digest size)
pub type RpoHasher = PaddingFreeSponge<RpoPermutation256, 12, 8, 4>;

/// RPO-based compression function using Plonky3's TruncatedPermutation.
///
/// This provides a 2-to-1 compression function for Merkle tree construction with:
/// - CHUNK: 2 (number of input chunks - i.e., 2 digests of 4 elements each = 8 elements)
/// - N: 4 (output size in field elements)
/// - WIDTH: 12 (total state size)
///
/// The compression function takes 8 field elements (2 digests) as input and produces
/// 4 field elements (1 digest) as output.
pub type RpoCompression = TruncatedPermutation<RpoPermutation256, 2, 4, 12>;

/// RPO-based challenger using Plonky3's DuplexChallenger.
///
/// This provides a Fiat-Shamir transform implementation for interactive proof protocols,
/// with:
/// - F: Generic field type (typically the same as Felt)
/// - WIDTH: 12 field elements (sponge state size)
/// - RATE: 8 field elements (rate of absorption/squeezing)
pub type RpoChallenger<F> = DuplexChallenger<F, RpoPermutation256, 12, 8>;
