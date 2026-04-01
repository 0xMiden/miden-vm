use once_cell::sync::Lazy;
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;

use super::{
    AlgebraicSponge, CAPACITY_RANGE, DIGEST_RANGE, Felt, RATE_RANGE, RATE0_RANGE, RATE1_RANGE,
    Range, STATE_WIDTH, Word,
};
use crate::{
    ZERO,
    hash::algebraic_sponge::poseidon2::constants::{
        ARK_EXT_INITIAL, ARK_EXT_TERMINAL, ARK_INT, MAT_DIAG,
    },
};

mod constants;
use constants::{NUM_EXTERNAL_ROUNDS_HALF, NUM_INTERNAL_ROUNDS};

#[cfg(test)]
mod test;

static P3_POSEIDON2: Lazy<p3_goldilocks::Poseidon2Goldilocks<12>> =
    Lazy::new(p3_goldilocks::default_goldilocks_poseidon2_12);

/// Applies Plonky3's optimized Poseidon2 permutation to a `[Felt; 12]` state.
///
/// `Felt` is `#[repr(transparent)]` over `Goldilocks`, so the transmute is safe.
/// A process-global lazy static holds the permutation so round constants are not reallocated on
/// every call (including `no_std`, via `once_cell` and the `critical-section` crate).
#[inline(always)]
fn p3_permute(state: &mut [Felt; STATE_WIDTH]) {
    // SAFETY: Felt is #[repr(transparent)] over Goldilocks.
    let gl_state =
        unsafe { &mut *(state as *mut [Felt; STATE_WIDTH] as *mut [Goldilocks; STATE_WIDTH]) };

    P3_POSEIDON2.permute_mut(gl_state);
}

/// Implementation of the Poseidon2 hash function with 256-bit output.
///
/// The permutation is delegated to Plonky3's optimized `Poseidon2Goldilocks<12>`, which provides
/// hardware-accelerated implementations on aarch64 (NEON inline assembly) and an optimized generic
/// implementation on other architectures. The internal MDS diagonal uses small special values
/// (-2, 1, 2, 1/2, 3, 4, ...) that enable multiplication via shifts and halves rather than full
/// field multiplications.
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * S-Box degree: 7.
/// * Rounds: There are 2 different types of rounds, called internal and external, and are
///   structured as follows:
/// - Initial External rounds (IE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
/// - Internal rounds: `add_constants` → `apply_sbox` → `apply_matmul_internal`, where the constant
///   addition and sbox application apply only to the first entry of the state.
/// - Terminal External rounds (TE): `add_constants` → `apply_sbox` → `apply_matmul_external`.
/// - An additional `apply_matmul_external` is inserted at the beginning in order to protect against
///   some recent attacks.
///
/// The above parameters target a 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Poseidon2::hash_elements), and [merge()](Poseidon2::merge), are
/// internally consistent. That is, computing a hash for the same set of elements using these
/// functions will always produce the same result. For example, merging two digests using
/// [merge()](Poseidon2::merge) will produce the same result as hashing 8 elements which make up
/// these digests using [hash_elements()](Poseidon2::hash_elements) function.
///
/// However, [hash()](Poseidon2::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Poseidon2::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Poseidon2::hash_elements) function. The reason for
/// this difference is that [hash()](Poseidon2::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Poseidon2::hash_elements) function rather than hashing the serialized bytes
/// using [hash()](Poseidon2::hash) function.
///
/// ## Domain separation
/// [merge_in_domain()](Poseidon2::merge_in_domain) hashes two digests into one digest with some
/// domain identifier and the current implementation sets the second capacity element to the value
/// of this domain identifier. Using a similar argument to the one formulated for domain separation
/// in Appendix C of the [specifications](https://eprint.iacr.org/2023/1045), one sees that doing
/// so degrades only pre-image resistance, from its initial bound of c.log_2(p), by as much as
/// the log_2 of the size of the domain identifier space. Since pre-image resistance becomes
/// the bottleneck for the security bound of the sponge in overwrite-mode only when it is
/// lower than 2^128, we see that the target 128-bit security level is maintained as long as
/// the size of the domain identifier space, including for padding, is less than 2^128.
///
/// ## Hashing of empty input
/// The current implementation hashes empty input to the zero digest [0, 0, 0, 0]. This has
/// the benefit of requiring no calls to the Poseidon2 permutation when hashing empty input.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2();

impl AlgebraicSponge for Poseidon2 {
    fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        p3_permute(state);
    }
}

impl Poseidon2 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Target collision resistance level in bits.
    pub const COLLISION_RESISTANCE: u32 = 128;

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = NUM_EXTERNAL_ROUNDS_HALF;
    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = NUM_INTERNAL_ROUNDS;

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

    /// Matrix used for computing the linear layers of internal rounds.
    pub const MAT_DIAG: [Felt; STATE_WIDTH] = MAT_DIAG;

    /// Round constants added to the hasher state.
    pub const ARK_EXT_INITIAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_INITIAL;
    pub const ARK_EXT_TERMINAL: [[Felt; STATE_WIDTH]; NUM_EXTERNAL_ROUNDS_HALF] = ARK_EXT_TERMINAL;
    pub const ARK_INT: [Felt; NUM_INTERNAL_ROUNDS] = ARK_INT;

    // HASH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Word {
        <Self as AlgebraicSponge>::hash(bytes)
    }

    /// Applies the Poseidon2 permutation to the provided state in-place.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        <Self as AlgebraicSponge>::apply_permutation(state);
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

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies the M_E (external) linear layer to the state in-place.
    ///
    /// This basically takes any 4 x 4 MDS matrix M and computes the matrix-vector product with
    /// the matrix defined by `[[2M, M, ..., M], [M, 2M, ..., M], ..., [M, M, ..., 2M]]`.
    ///
    /// Given the structure of the above matrix, we can compute the product of the state with
    /// matrix `[M, M, ..., M]` and compute the final result using a few addition.
    #[inline(always)]
    pub fn apply_matmul_external(state: &mut [Felt; STATE_WIDTH]) {
        // multiply the state by `[M, M, ..., M]` block-wise
        Self::matmul_m4(state);

        // accumulate column-wise sums
        let number_blocks = STATE_WIDTH / 4;
        let mut stored = [ZERO; 4];
        for j in 0..number_blocks {
            let base = j * 4;
            for l in 0..4 {
                stored[l] += state[base + l];
            }
        }

        // add stored column-sums to each element
        for (i, val) in state.iter_mut().enumerate() {
            *val += stored[i % 4];
        }
    }

    /// Multiply a 4-element vector x by:
    /// [ 2 3 1 1 ]
    /// [ 1 2 3 1 ]
    /// [ 1 1 2 3 ]
    /// [ 3 1 1 2 ].
    #[inline(always)]
    fn matmul_m4(state: &mut [Felt; STATE_WIDTH]) {
        const N_CHUNKS: usize = STATE_WIDTH / 4;

        for i in 0..N_CHUNKS {
            let base = i * 4;
            let x = &mut state[base..base + 4];

            let t01 = x[0] + x[1];
            let t23 = x[2] + x[3];
            let t0123 = t01 + t23;
            let t01123 = t0123 + x[1];
            let t01233 = t0123 + x[3];

            // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
            x[3] = t01233 + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
            x[1] = t01123 + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
            x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
            x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
        }
    }

    /// Applies the M_I (internal) linear layer to the state in-place.
    ///
    /// The matrix is given by its diagonal entries with the remaining entries set equal to 1.
    /// Hence, given the sum of the state entries, the matrix-vector product is computed using
    /// a multiply-and-add per state entry.
    #[inline(always)]
    pub fn matmul_internal(state: &mut [Felt; STATE_WIDTH], mat_diag: [Felt; 12]) {
        let mut sum = ZERO;
        for s in state.iter().take(STATE_WIDTH) {
            sum += *s
        }

        for i in 0..state.len() {
            state[i] = state[i] * mat_diag[i] + sum;
        }
    }

    /// Adds the round constants to the state in-place.
    #[inline(always)]
    pub fn add_rc(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; 12]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    /// Applies the S-box (x^7) to each element of the state in-place.
    #[inline(always)]
    pub fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
        state[0] = state[0].exp_const_u64::<7>();
        state[1] = state[1].exp_const_u64::<7>();
        state[2] = state[2].exp_const_u64::<7>();
        state[3] = state[3].exp_const_u64::<7>();
        state[4] = state[4].exp_const_u64::<7>();
        state[5] = state[5].exp_const_u64::<7>();
        state[6] = state[6].exp_const_u64::<7>();
        state[7] = state[7].exp_const_u64::<7>();
        state[8] = state[8].exp_const_u64::<7>();
        state[9] = state[9].exp_const_u64::<7>();
        state[10] = state[10].exp_const_u64::<7>();
        state[11] = state[11].exp_const_u64::<7>();
    }
}

// PLONKY3 INTEGRATION
// ================================================================================================

use p3_challenger::DuplexChallenger;
use p3_symmetric::{CryptographicPermutation, PaddingFreeSponge, TruncatedPermutation};

/// Plonky3-compatible Poseidon2 permutation.
///
/// This zero-sized wrapper delegates to Plonky3's optimized `Poseidon2Goldilocks<12>` and
/// implements the `Permutation` and `CryptographicPermutation` traits.
///
/// The permutation operates on a state of 12 field elements (STATE_WIDTH = 12), with:
/// - Rate: 8 elements (positions 0-7)
/// - Capacity: 4 elements (positions 8-11)
/// - Digest output: 4 elements (positions 0-3)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Poseidon2Permutation256;

impl Poseidon2Permutation256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of initial or terminal external rounds.
    pub const NUM_EXTERNAL_ROUNDS_HALF: usize = Poseidon2::NUM_EXTERNAL_ROUNDS_HALF;

    /// Number of internal rounds.
    pub const NUM_INTERNAL_ROUNDS: usize = Poseidon2::NUM_INTERNAL_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 0 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = Poseidon2::RATE_RANGE;

    /// The capacity portion of the state is located in elements 8, 9, 10, and 11.
    pub const CAPACITY_RANGE: Range<usize> = Poseidon2::CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 0, 1, 2, and 3.
    pub const DIGEST_RANGE: Range<usize> = Poseidon2::DIGEST_RANGE;

    // POSEIDON2 PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Poseidon2 permutation to the provided state.
    ///
    /// This delegates to the Poseidon2 implementation.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        Poseidon2::apply_permutation(state);
    }
}

// PLONKY3 TRAIT IMPLEMENTATIONS
// ================================================================================================

impl Permutation<[Felt; STATE_WIDTH]> for Poseidon2Permutation256 {
    fn permute_mut(&self, state: &mut [Felt; STATE_WIDTH]) {
        p3_permute(state);
    }
}

impl CryptographicPermutation<[Felt; STATE_WIDTH]> for Poseidon2Permutation256 {}

// TYPE ALIASES FOR PLONKY3 INTEGRATION
// ================================================================================================

/// Poseidon2-based hasher using Plonky3's PaddingFreeSponge.
///
/// This provides a sponge-based hash function with:
/// - WIDTH: 12 field elements (total state size)
/// - RATE: 8 field elements (input/output rate)
/// - OUT: 4 field elements (digest size)
pub type Poseidon2Hasher = PaddingFreeSponge<Poseidon2Permutation256, 12, 8, 4>;

/// Poseidon2-based compression function using Plonky3's TruncatedPermutation.
///
/// This provides a 2-to-1 compression function for Merkle tree construction with:
/// - CHUNK: 2 (number of input chunks - i.e., 2 digests of 4 elements each = 8 elements)
/// - N: 4 (output size in field elements)
/// - WIDTH: 12 (total state size)
///
/// The compression function takes 8 field elements (2 digests) as input and produces
/// 4 field elements (1 digest) as output.
pub type Poseidon2Compression = TruncatedPermutation<Poseidon2Permutation256, 2, 4, 12>;

/// Poseidon2-based challenger using Plonky3's DuplexChallenger.
///
/// This provides a Fiat-Shamir transform implementation for interactive proof protocols,
/// with:
/// - F: Generic field type (typically the same as Felt)
/// - WIDTH: 12 field elements (sponge state size)
/// - RATE: 8 field elements (rate of absorption/squeezing)
pub type Poseidon2Challenger<F> = DuplexChallenger<F, Poseidon2Permutation256, 12, 8>;
