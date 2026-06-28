//! Digital Signature Algorithm (DSA) helper functions.
//!
//! This module provides helpers for signature schemes whose MASM verification procedures are in the
//! core library.
//!
//! These helpers encode public keys, signatures, messages, and advice inputs for the MASM
//! verification procedures exposed by the core library.
//!
//! Each submodule corresponds to a specific signature scheme:
//! - [`ecdsa_k256_keccak`]: ECDSA over secp256k1 with Keccak256 hashing
//! - [`eddsa_ed25519`]: EdDSA over Ed25519 with SHA-512 hashing
//! - [`falcon512_poseidon2`]: Falcon-512 with Poseidon2 hashing

// ECDSA K256 KECCAK
// ================================================================================================

/// ECDSA secp256k1 with Keccak256 signature helpers.
///
/// Functions in this module generate the public-key commitment and native advice elements expected
/// by the `ecdsa_k256_keccak::verify` ABI.
pub mod ecdsa_k256_keccak {
    extern crate alloc;

    use alloc::vec::Vec;

    use miden_core::{
        Felt, Word, crypto::hash::Poseidon2, serde::Serializable,
        utils::bytes_to_packed_u32_elements,
    };
    use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
    use miden_precompiles::{K1Base, Limbs, UintSpec};

    /// Signs the provided message with the supplied secret key and encodes the resulting signature
    /// and public key into the native advice-stack format expected by `ecdsa_k256_keccak::verify`.
    ///
    /// See [`encode_signature()`] for the advice encoding. Use [`public_key_commitment()`] to
    /// derive the `PK_COMM` word that must be provided on the operand stack alongside the
    /// message.
    pub fn sign(sk: &SigningKey, msg: Word) -> Vec<Felt> {
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        encode_signature(&pk, &sig)
    }

    /// Encodes the provided public key and signature into the native advice-stack format expected
    /// by `ecdsa_k256_keccak::verify`.
    ///
    /// The encoding is the structural order consumed from the advice stack:
    /// `[QX[8] || QY[8] || SIG_R[8] || SIG_S[8]]`, where each value is a little-endian `u32` limb
    /// represented as a field element. The public key is decompressed from compressed SEC1 form.
    pub fn encode_signature(pk: &PublicKey, sig: &Signature) -> Vec<Felt> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&decompress_public_key(&pk.to_bytes()));
        out.extend_from_slice(&signature_felts(sig));
        out
    }

    /// Computes the `PK_COMM` word expected by `ecdsa_k256_keccak::verify`.
    ///
    /// This intentionally preserves the previous public-key commitment semantics: Poseidon2 over
    /// the compressed SEC1 public key packed into little-endian `u32` field elements.
    pub fn public_key_commitment(pk: &PublicKey) -> Word {
        Poseidon2::hash_elements(&bytes_to_packed_u32_elements(&pk.to_bytes()))
    }

    fn signature_felts(signature: &Signature) -> [Felt; 16] {
        let mut felts = [Felt::from_u32(0); 16];
        felts[..8].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.r())));
        felts[8..].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.s())));
        felts
    }

    fn decompress_public_key(compressed: &[u8]) -> [Felt; 16] {
        assert_eq!(compressed.len(), 33, "public key must be compressed SEC1");
        let prefix = compressed[0];
        assert!(matches!(prefix, 0x02 | 0x03), "unexpected compressed SEC1 prefix");

        let x_bytes = compressed[1..].try_into().expect("x coordinate length");
        let x = be_bytes_to_le_limbs(x_bytes);
        assert!(K1Base::is_canonical(&x), "public key x must be canonical");
        let rhs = K1Base::add(K1Base::mul(K1Base::mul(x, x), x), k1_base_from_u32(7));
        let mut y = sqrt_k1_base(rhs);
        let should_be_odd = prefix == 0x03;
        if (y[0] & 1 != 0) != should_be_odd {
            y = K1Base::sub([0; 8], y);
        }

        let mut felts = [Felt::from_u32(0); 16];
        felts[..8].copy_from_slice(&limbs_to_felts(x));
        felts[8..].copy_from_slice(&limbs_to_felts(y));
        felts
    }

    fn sqrt_k1_base(value: Limbs) -> Limbs {
        let root = pow_k1_base(value, secp256k1_p_plus_one_over_four());
        assert_eq!(K1Base::mul(root, root), value, "public key y coordinate must exist");
        root
    }

    fn pow_k1_base(base: Limbs, exponent: Limbs) -> Limbs {
        let mut result = [1, 0, 0, 0, 0, 0, 0, 0];
        for limb in exponent.into_iter().rev() {
            for bit in (0..32).rev() {
                result = K1Base::mul(result, result);
                if (limb >> bit) & 1 == 1 {
                    result = K1Base::mul(result, base);
                }
            }
        }
        result
    }

    fn secp256k1_p_plus_one_over_four() -> Limbs {
        let mut p_plus_one = K1Base::MODULUS;
        let mut carry = 1u64;
        for limb in &mut p_plus_one {
            let sum = *limb as u64 + carry;
            *limb = sum as u32;
            carry = sum >> 32;
            if carry == 0 {
                break;
            }
        }
        debug_assert_eq!(carry, 0);

        let mut shifted = [0u32; 8];
        let mut carry_bits = 0u32;
        for i in (0..8).rev() {
            shifted[i] = (p_plus_one[i] >> 2) | (carry_bits << 30);
            carry_bits = p_plus_one[i] & 0b11;
        }
        debug_assert_eq!(carry_bits, 0, "p + 1 must be divisible by four");
        shifted
    }

    fn k1_base_from_u32(value: u32) -> Limbs {
        let mut limbs = [0; 8];
        limbs[0] = value;
        assert!(K1Base::is_canonical(&limbs), "small base-field element must be canonical");
        limbs
    }

    fn be_bytes_to_le_limbs(bytes: &[u8; 32]) -> [u32; 8] {
        core::array::from_fn(|i| {
            let offset = bytes.len() - (i + 1) * 4;
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 limb"))
        })
    }

    fn limbs_to_felts<const N: usize>(limbs: [u32; N]) -> [Felt; N] {
        limbs.map(Felt::from_u32)
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

    use miden_core::{Felt, Word, serde::Serializable, utils::bytes_to_packed_u32_elements};
    use miden_crypto::dsa::eddsa_25519_sha512::{PublicKey, Signature, SigningKey};

    /// Signs the provided message with the supplied secret key and encodes this signature and the
    /// associated public key into a vector of field elements in the format expected by
    /// `miden::core::crypto::dsa::eddsa_ed25519::verify` procedure.
    ///
    /// See [`encode_signature()`] for more info.
    pub fn sign(sk: &SigningKey, msg: Word) -> Vec<Felt> {
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
        out.extend(bytes_to_packed_u32_elements(&pk_bytes));
        let sig_bytes = sig.to_bytes();
        out.extend(bytes_to_packed_u32_elements(&sig_bytes));
        out
    }
}

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
