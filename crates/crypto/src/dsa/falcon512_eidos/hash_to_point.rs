use alloc::vec::Vec;

use super::{MODULUS, N, Nonce, Polynomial, falcon512_common::FalconFelt};
use crate::{
    Felt, Word, ZERO,
    hash::eidos::{Eidos, domains::FALCON_HASH_TO_POINT},
};

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in `Z_p[x]/(phi)` representing the hash of the provided message and
/// nonce using Eidos.
///
/// Unlike the SHAKE256-based reference implementation, this implementation reduces wide samples
/// directly instead of using rejection sampling. The Falcon specification [1] describes this
/// branch-free alternative for sufficiently wide samples. Each Eidos output element supplies 63
/// pseudorandom bits, so reduction modulo the Falcon prime introduces a small bias.
///
/// [1]: <https://falcon-sign.info/falcon.pdf>
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
