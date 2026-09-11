use alloc::vec::Vec;

use super::{MODULUS, N, Nonce, Polynomial, falcon512_common::FalconFelt};
use crate::{
    Felt, Word, ZERO,
    hash::eidos::{Eidos, domains::FALCON_HASH_TO_POINT},
};

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in `Z_q[x]/(phi)` representing the hash of the provided message and
/// nonce using Eidos.
///
/// This construction reduces wide samples directly instead of using rejection sampling. Falcon
/// Section 3.7 [1] describes the analogous check-free reduction for 64-bit samples. The calculation
/// below applies Prest's distribution-replacement argument [2, Section 3.3] to Eidos's 63-bit
/// outputs.
///
/// Let `M = 2^63` and `q = 12289`. Since `M = 750538858886384 * q + 2832`, 2832 residues have one
/// additional preimage. If `B_1` is this distribution and `U_1` is uniform modulo `q`, their Rényi
/// divergence of order `alpha` is:
///
/// ```text
/// h = 1 + (q - 2832) / M
/// l = 1 - 2832 / M
/// R_alpha(B_1 || U_1)
///     = ((2832 / q) * h^alpha + ((q - 2832) / q) * l^alpha)^(1 / (alpha - 1))
/// ```
///
/// Modeling the 512 emitted Felts as independent uniform 63-bit samples gives the per-hash-to-point
/// divergence `R_alpha(B_1 || U_1)^512`. Taking the target security parameter `lambda = 128` in
/// Prest's one-bit-loss bound, which sets `alpha = 2 * lambda + 1`, gives `alpha = 257`. At this
/// order, `R_257(B_1 || U_1)^512 - 1 = 2.0712869695272872e-26 < 2^-85.31`.
/// For Prest's signing-query budget `q_s <= 2^64`, the accumulated logarithmic divergence satisfies
/// `q_s * log2(R_257(B_1 || U_1)^512) < 5.6e-7`.
/// At the maximum budget, the bound permits a per-hash-to-point divergence excess of
/// `1 / (4 * 2^64) = 2^-66`, more than `2^19` times the modeled excess. This calculation
/// establishes only the distribution-replacement step and assumes that the Eidos output schedule is
/// pseudorandom.
///
/// [1]: <https://falcon-sign.info/falcon.pdf>
/// [2]: <https://tprest.github.io/pdf/pub/renyi.pdf>
pub fn hash_to_point_eidos(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
    let nonce_elements = nonce.to_elements();

    let mut cv = Eidos::init_chaining_word(FALCON_HASH_TO_POINT, 0);
    cv = Eidos::compress(cv, nonce_elements);

    let mut block = [ZERO; 8];
    block[..Word::NUM_ELEMENTS].copy_from_slice(message.as_slice());
    cv = Eidos::compress(cv, block);

    // Derive the coefficients of the polynomial.
    let block = [ZERO; 8];
    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    for _ in 0..128 {
        cv = Eidos::compress(cv, block);
        cv.iter().for_each(|value| coefficients.push(felt_to_falcon_felt(*value)));
    }

    Polynomial::new(coefficients)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a Miden field element to a field element in the prime field with characteristic
/// the Falcon prime.
///
/// The final cast is safe because the Falcon prime is less than `i16::MAX`.
fn felt_to_falcon_felt(value: Felt) -> FalconFelt {
    FalconFelt::new((value.as_canonical_u64() % MODULUS as u64) as i16)
}
