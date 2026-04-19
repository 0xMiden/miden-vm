use super::{
    ARK1, ARK2, AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, Felt, MDS, NUM_ROUNDS, RATE_RANGE,
    RATE0_RANGE, RATE1_RANGE, Range, STATE_WIDTH, Word, add_constants,
    add_constants_and_apply_ext_round, add_constants_and_apply_inv_sbox,
    add_constants_and_apply_sbox, apply_inv_sbox, apply_mds, apply_sbox,
};

#[cfg(test)]
mod tests;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Rescue Prime eXtension hash function with 256-bit output.
///
/// The hash function is based on the XHash12 construction in [specifications](https://eprint.iacr.org/2023/1045)
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * S-Box degree: 7.
/// * Rounds: There are 3 different types of rounds:
/// - (FB): `apply_mds` → `add_constants` → `apply_sbox` → `apply_mds` → `add_constants` →
///   `apply_inv_sbox`.
/// - (E): `add_constants` → `ext_sbox` (which is raising to power 7 in the degree 3 extension
///   field).
/// - (M): `apply_mds` → `add_constants`.
/// * Permutation: (FB) (E) (FB) (E) (FB) (E) (M).
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rpx256::hash_elements), and [merge()](Rpx256::merge), are internally
/// consistent. That is, computing a hash for the same set of elements using these functions will
/// always produce the same result. For example, merging two digests using [merge()](Rpx256::merge)
/// will produce the same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rpx256::hash_elements) function.
///
/// However, [hash()](Rpx256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rpx256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rpx256::hash_elements) function. The reason for
/// this difference is that [hash()](Rpx256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rpx256::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Rpx256::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Rpx256::merge_in_domain) hashes two digests into one digest with some domain
/// identifier and the current implementation sets the second capacity element to the value of
/// this domain identifier. Using a similar argument to the one formulated for domain separation
/// in Appendix C of the [specifications](https://eprint.iacr.org/2023/1045), one sees that doing
/// so degrades only pre-image resistance, from its initial bound of c.log_2(p), by as much as
/// the log_2 of the size of the domain identifier space. Since pre-image resistance becomes
/// the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the RPX permutation when hashing empty input.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpx256();

impl AlgebraicSponge for Rpx256 {
    /// Applies RPX permutation to the provided state.
    #[inline(always)]
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_fb_round(state, 0);
        Self::apply_ext_round(state, 1);
        Self::apply_fb_round(state, 2);
        Self::apply_ext_round(state, 3);
        Self::apply_fb_round(state, 4);
        Self::apply_ext_round(state, 5);
        Self::apply_final_round(state, 6);
    }
}

impl Rpx256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Target collision resistance level in bits.
    pub const COLLISION_RESISTANCE: u32 = 128;

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

    /// MDS matrix used for computing the linear layer in the (FB) and (E) rounds.
    pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Round constants added to the hasher state in the first half of the round.
    pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the round.
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

    // RPX PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPX permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_fb_round(state, 0);
        Self::apply_ext_round(state, 1);
        Self::apply_fb_round(state, 2);
        Self::apply_ext_round(state, 3);
        Self::apply_fb_round(state, 4);
        Self::apply_ext_round(state, 5);
        Self::apply_final_round(state, 6);
    }

    // RPX PERMUTATION ROUND FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// (FB) round function.
    #[inline(always)]
    pub fn apply_fb_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        apply_mds(state);
        if !add_constants_and_apply_sbox(state, &ARK1[round]) {
            add_constants(state, &ARK1[round]);
            apply_sbox(state);
        }

        apply_mds(state);
        if !add_constants_and_apply_inv_sbox(state, &ARK2[round]) {
            add_constants(state, &ARK2[round]);
            apply_inv_sbox(state);
        }
    }

    /// (E) round function.
    ///
    /// It first attempts to run the optimized (SIMD-accelerated) implementation.
    /// If SIMD acceleration is not available for the current target it falls
    /// back to the scalar reference implementation (`apply_ext_round_ref`).
    #[inline(always)]
    pub fn apply_ext_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        if !add_constants_and_apply_ext_round(state, &ARK1[round]) {
            Self::apply_ext_round_ref(state, round);
        }
    }

    /// Scalar (reference) implementation of the (E) round function.
    ///
    /// This version performs the round without SIMD acceleration and is used
    /// as a fallback when optimized implementations are not available.
    #[inline(always)]
    fn apply_ext_round_ref(state: &mut [Felt; STATE_WIDTH], round: usize) {
        // add constants
        add_constants(state, &ARK1[round]);

        // decompose the state into 4 elements in the cubic extension field and apply the power 7
        // map to each of the elements using our custom cubic extension implementation
        let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = *state;

        let ext0 = cubic_ext::power7([s0, s1, s2]);
        let ext1 = cubic_ext::power7([s3, s4, s5]);
        let ext2 = cubic_ext::power7([s6, s7, s8]);
        let ext3 = cubic_ext::power7([s9, s10, s11]);

        // write the results back into the state
        state[0] = ext0[0];
        state[1] = ext0[1];
        state[2] = ext0[2];
        state[3] = ext1[0];
        state[4] = ext1[1];
        state[5] = ext1[2];
        state[6] = ext2[0];
        state[7] = ext2[1];
        state[8] = ext2[2];
        state[9] = ext3[0];
        state[10] = ext3[1];
        state[11] = ext3[2];
    }

    /// (M) round function.
    #[inline(always)]
    pub fn apply_final_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        apply_mds(state);
        add_constants(state, &ARK1[round]);
    }
}

// CUBIC EXTENSION FIELD OPERATIONS
// ================================================================================================

/// Helper functions for cubic extension field operations over the irreducible polynomial
/// x³ - x - 1. These are used for Plonky3 integration where we need explicit control
/// over the field arithmetic.
mod cubic_ext {
    use super::Felt;

    /// Multiplies two cubic extension field elements.
    ///
    /// Element representation: [a0, a1, a2] = a0 + a1*φ + a2*φ²
    /// where φ is a root of x³ - x - 1.
    #[inline(always)]
    pub fn mul(a: [Felt; 3], b: [Felt; 3]) -> [Felt; 3] {
        let a0b0 = a[0] * b[0];
        let a1b1 = a[1] * b[1];
        let a2b2 = a[2] * b[2];

        let a0b0_a0b1_a1b0_a1b1 = (a[0] + a[1]) * (b[0] + b[1]);
        let a0b0_a0b2_a2b0_a2b2 = (a[0] + a[2]) * (b[0] + b[2]);
        let a1b1_a1b2_a2b1_a2b2 = (a[1] + a[2]) * (b[1] + b[2]);

        let a0b0_minus_a1b1 = a0b0 - a1b1;

        let a0b0_a1b2_a2b1 = a1b1_a1b2_a2b1_a2b2 + a0b0_minus_a1b1 - a2b2;
        let a0b1_a1b0_a1b2_a2b1_a2b2 =
            a0b0_a0b1_a1b0_a1b1 + a1b1_a1b2_a2b1_a2b2 - a1b1.double() - a0b0;
        let a0b2_a1b1_a2b0_a2b2 = a0b0_a0b2_a2b0_a2b2 - a0b0_minus_a1b1;

        [a0b0_a1b2_a2b1, a0b1_a1b0_a1b2_a2b1_a2b2, a0b2_a1b1_a2b0_a2b2]
    }

    /// Squares a cubic extension field element.
    #[inline(always)]
    pub fn square(a: [Felt; 3]) -> [Felt; 3] {
        let a0 = a[0];
        let a1 = a[1];
        let a2 = a[2];

        let a2_sq = a2.square();
        let a1_a2 = a1 * a2;

        let out0 = a0.square() + a1_a2.double();
        let out1 = (a0 * a1 + a1_a2).double() + a2_sq;
        let out2 = (a0 * a2).double() + a1.square() + a2_sq;

        [out0, out1, out2]
    }

    /// Computes the 7th power of a cubic extension field element.
    ///
    /// Uses the addition chain: x → x² → x³ → x⁶ → x⁷
    /// - x² (1 squaring)
    /// - x³ = x² * x (1 multiplication)
    /// - x⁶ = (x³)² (1 squaring)
    /// - x⁷ = x⁶ * x (1 multiplication)
    ///
    /// Total: 2 squarings + 2 multiplications
    #[inline(always)]
    pub fn power7(a: [Felt; 3]) -> [Felt; 3] {
        let a2 = square(a);
        let a3 = mul(a2, a);
        let a6 = square(a3);
        mul(a6, a)
    }
}

// PLONKY3 INTEGRATION
// ================================================================================================

/// Plonky3-compatible RPX permutation implementation.
///
/// This module provides a Plonky3-compatible interface to the RPX256 hash function,
/// implementing the `Permutation` and `CryptographicPermutation` traits from Plonky3.
///
/// This allows RPX to be used with Plonky3's cryptographic infrastructure, including:
/// - PaddingFreeSponge for hashing
/// - TruncatedPermutation for compression
/// - DuplexChallenger for Fiat-Shamir transforms
use p3_challenger::DuplexChallenger;
use p3_symmetric::{
    CryptographicPermutation, PaddingFreeSponge, Permutation, TruncatedPermutation,
};

// RPX PERMUTATION FOR PLONKY3
// ================================================================================================

/// Plonky3-compatible RPX permutation.
///
/// This struct wraps the RPX256 permutation and implements Plonky3's `Permutation` and
/// `CryptographicPermutation` traits, allowing RPX to be used within the Plonky3 ecosystem.
///
/// The permutation operates on a state of 12 field elements (STATE_WIDTH = 12), with:
/// - Rate: 8 elements (positions 0-7)
/// - Capacity: 4 elements (positions 8-11)
/// - Digest output: 4 elements (positions 0-3)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RpxPermutation256;

impl RpxPermutation256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = Rpx256::RATE_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = Rpx256::CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 0, 1, 2, and 3 (the first
    /// word of the state).
    pub const DIGEST_RANGE: Range<usize> = Rpx256::DIGEST_RANGE;

    // RPX PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPX permutation to the provided state.
    ///
    /// This delegates to the RPX256 implementation.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Rpx256::apply_permutation(state);
    }
}

// PLONKY3 TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Permutation<[Felt; STATE_WIDTH]> for RpxPermutation256 {
    fn permute_mut(&self, state: &mut [Felt; STATE_WIDTH]) {
        Self::apply_permutation(state);
    }
}

impl CryptographicPermutation<[Felt; STATE_WIDTH]> for RpxPermutation256 {}

// TYPE ALIASES FOR PLONKY3 INTEGRATION
// ================================================================================================

/// RPX-based hasher using Plonky3's PaddingFreeSponge.
///
/// This provides a sponge-based hash function with:
/// - WIDTH: 12 field elements (total state size)
/// - RATE: 8 field elements (input/output rate)
/// - OUT: 4 field elements (digest size)
pub type RpxHasher = PaddingFreeSponge<RpxPermutation256, 12, 8, 4>;

/// RPX-based compression function using Plonky3's TruncatedPermutation.
///
/// This provides a 2-to-1 compression function for Merkle tree construction with:
/// - CHUNK: 2 (number of input chunks - i.e., 2 digests of 4 elements each = 8 elements)
/// - N: 4 (output size in field elements)
/// - WIDTH: 12 (total state size)
///
/// The compression function takes 8 field elements (2 digests) as input and produces
/// 4 field elements (1 digest) as output.
pub type RpxCompression = TruncatedPermutation<RpxPermutation256, 2, 4, 12>;

/// RPX-based challenger using Plonky3's DuplexChallenger.
///
/// This provides a Fiat-Shamir transform implementation for interactive proof protocols,
/// with:
/// - F: Generic field type (typically the same as Felt)
/// - WIDTH: 12 field elements (sponge state size)
/// - RATE: 8 field elements (rate of absorption/squeezing)
pub type RpxChallenger<F> = DuplexChallenger<F, RpxPermutation256, 12, 8>;
