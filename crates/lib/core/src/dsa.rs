//! Digital Signature Algorithm (DSA) helper functions.
//!
//! This module provides helpers for signature schemes whose MASM verification procedures are in the
//! core library.

// FALCON 512 POSEIDON2
// ================================================================================================

/// Falcon-512 with Poseidon2 hashing signature helpers.
///
/// Functions in this module generate data for the
/// `miden::core::crypto::dsa::falcon512_poseidon2::verify` MASM procedure.
pub mod falcon512_poseidon2 {
    extern crate alloc;

    use alloc::vec::Vec;

    // Re-export signature type for users
    pub use miden_core::crypto::dsa::falcon512_poseidon2::{PublicKey, SecretKey, Signature};
    use miden_core::{
        Felt, Word,
        crypto::{dsa::falcon512_poseidon2::Polynomial, hash::Poseidon2},
    };

    /// Signs the provided message with the provided secret key and returns the resulting signature
    /// encoded in the format required by the `falcon512_poseidon2::verify` procedure, or `None` if
    /// the secret key is malformed due to either incorrect length or failed decoding.
    ///
    /// This is equivalent to calling [`encode_signature`] on the result of signing the message.
    ///
    /// See [`encode_signature`] for the encoding format.
    pub fn sign(sk: &SecretKey, msg: Word) -> Option<Vec<Felt>> {
        let sig = sk.sign(msg);
        Some(encode_signature(sig.public_key(), &sig))
    }

    /// Encodes the provided Falcon public key and signature into a vector of field elements in the
    /// format expected by `miden::core::crypto::dsa::falcon512_poseidon2::verify` procedure.
    ///
    /// The encoding format is (in reverse order on the advice stack):
    ///
    /// 1. The challenge point, a tuple of elements representing an element in the quadratic
    ///    extension field, at which we evaluate the polynomials in the subsequent three points to
    ///    check the product relationship.
    /// 2. The expanded public key represented as the coefficients of a polynomial of degree < 512.
    /// 3. The signature represented as the coefficients of a polynomial of degree < 512.
    /// 4. The product of the above two polynomials in the ring of polynomials with coefficients in
    ///    the Miden field.
    /// 5. The nonce represented as 8 field elements.
    ///
    /// The result can be streamed straight to the advice provider before invoking
    /// `falcon512_poseidon2::verify`.
    pub fn encode_signature(pk: &PublicKey, sig: &Signature) -> Vec<Felt> {
        use alloc::vec;

        // The signature is composed of a nonce and a polynomial s2

        // The nonce is represented as 8 field elements.
        let nonce = sig.nonce();

        // We convert the signature to a polynomial
        let s2 = sig.sig_poly();

        // Lastly, for the probabilistic product routine that is part of the verification
        // procedure, we need to compute the product of the expanded key and the signature
        // polynomial in the ring of polynomials with coefficients in the Miden field.
        let pi = Polynomial::mul_modulo_p(pk, s2);

        // We now push the expanded key, the signature polynomial, and the product of the
        // expanded key and the signature polynomial to the advice stack. We also push
        // the challenge point at which the previous polynomials will be evaluated.
        // Finally, we push the nonce needed for the hash-to-point algorithm.

        let mut polynomials = pk.to_elements();
        polynomials.extend(s2.to_elements());
        polynomials.extend(pi.iter().map(|a| Felt::new_unchecked(*a)));

        let digest_polynomials = Poseidon2::hash_elements(&polynomials);
        let challenge = (digest_polynomials[0], digest_polynomials[1]);

        // Push [tau1, tau0] so that after extend_stack reversal + two `adv_push` ops,
        // operand stack is [tau0, tau1, ...]
        let mut result: Vec<Felt> = vec![challenge.1, challenge.0];
        result.extend_from_slice(&polynomials);
        result.extend_from_slice(&nonce.to_elements());

        result
    }
}
