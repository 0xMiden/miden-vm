//! Digital Signature Algorithm (DSA) helper functions.
//!
//! This module provides functions for signing messages and encoding signatures in the format
//! expected by the corresponding MASM verification procedures.
//!
//! Each submodule corresponds to a specific signature scheme:
//! - [`ecdsa_k256_keccak`]: ECDSA over secp256k1 with Keccak256 hashing
//! - [`eddsa_ed25519`]: EdDSA over Ed25519 with SHA-512 hashing
//! - [`falcon512_rpo`]: Falcon-512 with RPO hashing

// ECDSA K256 KECCAK
// ================================================================================================

/// ECDSA secp256k1 with Keccak256 signature helpers.
///
/// Functions in this module generate data for the
/// `miden::core::crypto::dsa::ecdsa_k256_keccak::verify` MASM procedure.
pub mod ecdsa_k256_keccak {
    extern crate alloc;

    use alloc::vec::Vec;

    use miden_core::{Felt, Word, utils::Serializable};
    use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, SecretKey, Signature};

    use crate::handlers::bytes_to_packed_u32_felts;

    /// Signs the provided message with the supplied secret key and encodes this signature and the
    /// associated public key into a vector of field elements in the format expected by
    /// `miden::core::crypto::dsa::ecdsa_k256_keccak::verify` procedure.
    ///
    /// See [`encode_signature()`] for more info.
    pub fn sign(sk: &SecretKey, msg: Word) -> Vec<Felt> {
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        encode_signature(&pk, &sig)
    }

    /// Encodes the provided public key and signature into a vector of field elements in the format
    /// expected by `miden::core::crypto::dsa::ecdsa_k256_keccak::verify` procedure.
    ///
    /// 1. The compressed secp256k1 public key encoded as 9 packed-u32 felts (33 bytes total).
    /// 2. The ECDSA signature encoded as 17 packed-u32 felts (66 bytes total).
    ///
    /// The two chunks are concatenated as `[PK[9] || SIG[17]]` so they can be streamed straight to
    /// the advice provider before invoking `ecdsa_k256_keccak::verify`.
    pub fn encode_signature(pk: &PublicKey, sig: &Signature) -> Vec<Felt> {
        let mut out = Vec::new();
        let pk_bytes = pk.to_bytes();
        out.extend(bytes_to_packed_u32_felts(&pk_bytes));
        let sig_bytes = sig.to_bytes();
        out.extend(bytes_to_packed_u32_felts(&sig_bytes));
        out
    }
}

// EDDSA ED25519
// ================================================================================================

/// EdDSA Ed25519 with SHA-512 signature helpers.
///
/// Functions in this module generate data for the
/// `miden::core::crypto::dsa::eddsa_ed25519::verify` MASM procedure.
pub mod eddsa_ed25519 {
    extern crate alloc;

    use alloc::vec::Vec;

    use miden_core::{Felt, Word, utils::Serializable};
    use miden_crypto::dsa::eddsa_25519_sha512::{PublicKey, SecretKey, Signature};

    use crate::handlers::bytes_to_packed_u32_felts;

    /// Signs the provided message with the supplied secret key and encodes this signature and the
    /// associated public key into a vector of field elements in the format expected by
    /// `miden::core::crypto::dsa::eddsa_ed25519::verify` procedure.
    ///
    /// See [`encode_signature()`] for more info.
    pub fn sign(sk: &SecretKey, msg: Word) -> Vec<Felt> {
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        encode_signature(&pk, &sig)
    }

    /// Encodes the provided public key and signature into a vector of field elements in the format
    /// expected by `miden::core::crypto::dsa::eddsa_ed25519::verify` procedure.
    ///
    /// The encoding format is:
    /// 1. The Ed25519 public key encoded as 8 packed-u32 felts (32 bytes total).
    /// 2. The EdDSA signature encoded as 16 packed-u32 felts (64 bytes total).
    ///
    /// The two chunks are concatenated as `[PK[8] || SIG[16]]` so they can be streamed straight to
    /// the advice provider before invoking `eddsa_ed25519::verify`.
    pub fn encode_signature(pk: &PublicKey, sig: &Signature) -> Vec<Felt> {
        let mut out = Vec::new();
        let pk_bytes = pk.to_bytes();
        out.extend(bytes_to_packed_u32_felts(&pk_bytes));
        let sig_bytes = sig.to_bytes();
        out.extend(bytes_to_packed_u32_felts(&sig_bytes));
        out
    }
}

// FALCON 512 RPO
// ================================================================================================

/// Falcon-512 with RPO hashing signature helpers.
///
/// Functions in this module generate data for the
/// `miden::core::crypto::dsa::falcon512rpo::verify` MASM procedure.
pub mod falcon512_rpo {
    extern crate alloc;

    use alloc::vec::Vec;

    // Re-export signature type for users
    pub use miden_core::crypto::dsa::falcon512_rpo::{PublicKey, SecretKey, Signature};
    use miden_core::{
        Felt, Word,
        crypto::{dsa::falcon512_rpo::Polynomial, hash::Rpo256},
    };

    /// Signs the provided message with the provided secret key and returns the resulting signature
    /// encoded in the format required by the `falcon512rpo::verify` procedure, or `None` if the
    /// secret key is malformed due to either incorrect length or failed decoding.
    ///
    /// This is equivalent to calling [`encode_signature`] on the result of signing the message.
    ///
    /// See [`encode_signature`] for the encoding format.
    pub fn sign(sk: &SecretKey, msg: Word) -> Option<Vec<Felt>> {
        let sig = sk.sign(msg);
        Some(encode_signature(sig.public_key(), &sig))
    }

    /// Encodes the provided Falcon public key and signature into a vector of field elements in the
    /// format expected by `miden::core::crypto::dsa::falcon512rpo::verify` procedure.
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
    /// `falcon512rpo::verify`.
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
        polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

        let digest_polynomials = Rpo256::hash_elements(&polynomials);
        let challenge = (digest_polynomials[0], digest_polynomials[1]);

        let mut result: Vec<Felt> = vec![challenge.0, challenge.1];
        result.extend_from_slice(&polynomials);
        result.extend_from_slice(&nonce.to_elements());

        result.reverse();
        result
    }
}
