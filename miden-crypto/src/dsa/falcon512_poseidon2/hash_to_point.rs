use alloc::vec::Vec;

use super::{MODULUS, N, Nonce, Polynomial, Poseidon2, ZERO, math::FalconFelt};
use crate::{Felt, Word};

// HASH-TO-POINT FUNCTIONS
// ================================================================================================

/// Returns a polynomial in `Z_p[x]/(phi)` representing the hash of the provided message and
/// nonce using Poseidon2.
///
/// Note that, in contrast to the SHAKE256-based reference implementation, this implementation
/// does not use rejection sampling but instead uses one of the variants listed in the specification
/// [1]. This variant omits the conditional check in the rejection sampling step at the cost of
/// having to extract 64 bits, instead of 16 bits, of pseudo-randomness. This makes
/// the implementation simpler and constant-time at the cost of a higher number of extracted
/// pseudo-random bits per call to the hash-to-point algorithm.
///
/// [1]: <https://falcon-sign.info/falcon.pdf>
pub fn hash_to_point_poseidon2(message: Word, nonce: &Nonce) -> Polynomial<FalconFelt> {
    let mut state = [ZERO; Poseidon2::STATE_WIDTH];

    // absorb the nonce into the state
    let nonce_elements = nonce.to_elements();
    for (&n, s) in nonce_elements.iter().zip(state[Poseidon2::RATE_RANGE].iter_mut()) {
        *s = n;
    }
    Poseidon2::apply_permutation(&mut state);

    // absorb message into the state
    for (&m, s) in message.iter().zip(state[Poseidon2::RATE_RANGE].iter_mut()) {
        *s = m;
    }

    // squeeze the coefficients of the polynomial
    let mut coefficients: Vec<FalconFelt> = Vec::with_capacity(N);
    for _ in 0..64 {
        //
        // Note that `FalconFelt::new((a.as_canonical_u64() % MODULUS as u64) as i16)` will
        // create a bias as we are mapping $2^64 - 2^31 + 1$ elements to $12289$ elements
        // and it must not be uniform. A statistical analysis can be applied here to show
        // that this is still fine: the output distribution is computational IND from
        // uniform.
        Poseidon2::apply_permutation(&mut state);
        state[Poseidon2::RATE_RANGE]
            .iter()
            .for_each(|value| coefficients.push(felt_to_falcon_felt(*value)));
    }

    Polynomial::new(coefficients)
}

/// Returns a polynomial in `Z_p[x]/(phi)` representing the hash of the provided message and
/// nonce using SHAKE256. This is the hash-to-point algorithm used in the reference implementation.
#[cfg(test)]
pub fn hash_to_point_shake256(message: &[u8], nonce: &Nonce) -> Polynomial<FalconFelt> {
    use sha3::{
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
/// Note that since `FalconFelt::new` accepts `i16`, we first reduce the canonical value of
/// the Miden field element modulo the Falcon prime and then cast the resulting value to an `i16`.
/// Note that this final cast is safe as the Falcon prime is less than `i16::MAX`.
fn felt_to_falcon_felt(value: Felt) -> FalconFelt {
    FalconFelt::new((value.as_canonical_u64() % MODULUS as u64) as i16)
}

/// Converts a `u32` to a field element in the prime field with characteristic the Falcon prime.
///
/// Note that since `FalconFelt::new` accepts `i16`, we first reduce the `u32` value modulo
/// the Falcon prime and then cast the resulting value to an `i16`.
/// Note that this final cast is safe as the Falcon prime is less than `i16::MAX`.
#[cfg(test)]
fn u32_to_falcon_felt(value: u32) -> FalconFelt {
    FalconFelt::new((value % MODULUS as u32) as i16)
}
