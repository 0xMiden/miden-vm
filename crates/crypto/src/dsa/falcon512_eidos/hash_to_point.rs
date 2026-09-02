use alloc::vec::Vec;

use super::{FALCON_HASH_TO_POINT_SELECTOR, MODULUS, N, Nonce, Polynomial, ZERO, math::FalconFelt};
use crate::{Felt, Word, hash::eidos::Eidos};

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

    let mut cv = Eidos::init_chaining_word(FALCON_HASH_TO_POINT_SELECTOR, 0);
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

/// Returns a polynomial in `Z_p[x]/(phi)` representing the hash of the provided message and
/// nonce using SHAKE256. This is the hash-to-point algorithm used in the reference implementation.
#[cfg(test)]
pub(super) fn hash_to_point_shake256(message: &[u8], nonce: &Nonce) -> Polynomial<FalconFelt> {
    use shake::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    let mut data = vec![];
    data.extend_from_slice(&nonce.as_bytes());
    data.extend_from_slice(message);
    const K: u32 = (1u32 << 16) / MODULUS as u32;

    let mut hasher = Shake256::default();
    hasher.update(&data);
    let mut reader = hasher.finalize_xof();

    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    while coefficients.len() != N {
        let mut randomness = [0u8; 2];
        reader.read(&mut randomness);
        let t = ((randomness[0] as u32) << 8) | (randomness[1] as u32);
        if t < K * MODULUS as u32 {
            coefficients.push(u32_to_falcon_felt(t));
        }
    }

    Polynomial { coefficients }
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

/// Converts a `u32` to a field element in the prime field with characteristic the Falcon prime.
///
/// The final cast is safe because the Falcon prime is less than `i16::MAX`.
#[cfg(test)]
fn u32_to_falcon_felt(value: u32) -> FalconFelt {
    FalconFelt::new((value % MODULUS as u32) as i16)
}
