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
//! - [`falcon512_poseidon2`]: Falcon-512 with Poseidon2 hashing

// ECDSA K256 KECCAK
// ================================================================================================

/// ECDSA secp256k1 with Keccak256 signature helpers.
///
/// Functions in this module generate the public-key commitment and native advice witness expected
/// by the `ecdsa_k256_keccak::verify` ABI. The public-key coordinates are bound by that commitment,
/// but `r` and `s` are not committed to a particular signature encoding. Unlike the `miden-crypto`
/// Rust verifier, the MASM verifier intentionally accepts high-s values.
pub mod ecdsa_k256_keccak {
    extern crate alloc;

    use alloc::vec::Vec;

    use miden_core::{Felt, Word};
    use miden_crypto::{
        SequentialCommit,
        dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey},
        hash::keccak::Keccak256,
    };
    use miden_precompiles::{
        Limbs, glv_decompose, reduce_mod_n, scalar_inv_mod_n, scalar_mul_mod_n,
    };

    /// Which scalar-multiplication strategy the MASM verifier uses to compute `u1*G + u2*Q`: an
    /// untrusted, prover-supplied choice with no soundness implication either way — a wrong
    /// witness for either path fails verification, it can never forge one. GLV amortizes its two
    /// endomorphism-image bases across every signature that shares a proof, so it favors large
    /// batches; Straus has no such shared setup cost and favors small ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Algorithm {
        /// Classic 2-base joint wNAF multi-scalar multiplication (`u1*G + u2*Q`).
        Straus,
        /// GLV-endomorphism 4-base multi-scalar multiplication.
        Glv,
    }

    /// Signs the provided message with the supplied secret key and encodes the resulting signature
    /// and public key into the native advice-stack format expected by `ecdsa_k256_keccak::verify`.
    ///
    /// The `miden-crypto` signer produces a low-s signature, but the returned elements are
    /// uncommitted advice witness data and the MASM verifier does not require low-s. See
    /// [`encode_signature()`] for the advice encoding. Use [`public_key_commitment()`] to derive
    /// the `PK_COMM` word that must be provided on the operand stack alongside the message.
    pub fn sign(sk: &SigningKey, msg: Word, algo: Algorithm) -> Vec<Felt> {
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        encode_signature(&pk, &sig, msg, algo)
    }

    /// Number of felts a GLV witness occupies: the verifier's two ECDSA scalars (`u1`, `u2`) each
    /// split into a signed short pair via the secp256k1 GLV endomorphism, encoded as an 8-limb
    /// magnitude plus one sign felt (`1` = negative) per half.
    const GLV_HALVES_FELTS: usize = 4 * 9;

    /// Encodes the provided public key, signature, and message into the native advice-stack format
    /// expected by `ecdsa_k256_keccak::verify`.
    ///
    /// The encoding is the structural order consumed from the advice stack:
    /// `[QX[8] || QY[8] || SIG_R[8] || SIG_S[8] || ALGO || GLV_HALVES? || PAD]`, where each scalar
    /// value is a little-endian `u32` limb represented as a field element. The signature portion
    /// preserves `r` and `s` exactly, omits the recovery ID, and does not normalize or enforce
    /// low-s. `ALGO` is a single untrusted felt (`0` = Straus, `1` = GLV) selecting the verifier's
    /// scalar-multiplication strategy; `GLV_HALVES` (present only when `algo` is
    /// [`Algorithm::Glv`]) is an untrusted witness for the verifier's in-circuit GLV scalar
    /// decomposition (`u1 = k1a + λ·k1b`, `u2 = k2a + λ·k2b`, magnitude-then-sign-felt per half, in
    /// that order) — the MASM verifier re-derives and checks this relation, so an incorrect
    /// witness fails verification rather than forging anything. `PAD` is trailing zero felts
    /// rounding the total up to a multiple of 8 (`push_for_adv_pipe`'s requirement); the verifier
    /// drains them from advice unread. The result is advice witness data, not a commitment to the
    /// supplied signature encoding.
    ///
    /// The public-key elements come from [`SequentialCommit::to_elements()`], matching the
    /// commitment returned by [`public_key_commitment()`].
    pub fn encode_signature(
        pk: &PublicKey,
        sig: &Signature,
        msg: Word,
        algo: Algorithm,
    ) -> Vec<Felt> {
        let pk_elements = pk.to_elements();
        assert_eq!(
            pk_elements.len(),
            16,
            "ECDSA public key elements must be QX[8] || QY[8] native limbs",
        );

        let is_glv = algo == Algorithm::Glv;
        let mut out = Vec::with_capacity(16 + 16 + 1 + GLV_HALVES_FELTS + 7);
        out.extend(pk_elements);
        out.extend_from_slice(&signature_felts(sig));
        out.push(Felt::from_u32(is_glv as u32));
        if is_glv {
            out.extend_from_slice(&glv_advice_felts(sig, msg));
        }
        let pad = (8 - out.len() % 8) % 8;
        out.resize(out.len() + pad, Felt::from_u32(0));
        out
    }

    /// Computes the verifier's `u1`/`u2` ECDSA scalars the same way the MASM verifier does, splits
    /// each via the secp256k1 GLV endomorphism, and encodes the four signed halves as advice.
    fn glv_advice_felts(sig: &Signature, msg: Word) -> [Felt; GLV_HALVES_FELTS] {
        let z = z_from_message(msg);
        let r = be_bytes_to_le_limbs(sig.r());
        let s = be_bytes_to_le_limbs(sig.s());
        let s_inv = scalar_inv_mod_n(s);
        let u1 = scalar_mul_mod_n(z, s_inv);
        let u2 = scalar_mul_mod_n(r, s_inv);

        let [k1a, k1b] = glv_decompose(u1);
        let [k2a, k2b] = glv_decompose(u2);

        let mut out = [Felt::from_u32(0); GLV_HALVES_FELTS];
        let mut i = 0;
        for (neg, mag) in [k1a, k1b, k2a, k2b] {
            out[i..i + 8].copy_from_slice(&limbs_to_felts(mag));
            out[i + 8] = Felt::from_u32(neg as u32);
            i += 9;
        }
        out
    }

    /// The Keccak256 prehash scalar `z`, reduced mod the secp256k1 scalar-field order, matching
    /// `ecdsa_k256_keccak.masm`'s exact message-to-scalar conversion: each message felt's 8
    /// little-endian bytes are concatenated (in element order) into the 32-byte Keccak256
    /// preimage, and the resulting digest is converted back to native little-endian u32 limbs
    /// (see [`be_bytes_to_le_limbs`]) before reduction.
    fn z_from_message(msg: Word) -> Limbs {
        let mut preimage = [0u8; 32];
        for (i, felt) in msg.iter().enumerate() {
            preimage[i * 8..i * 8 + 8].copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
        }
        let digest: [u8; 32] = Keccak256::hash(&preimage).into();
        reduce_mod_n(be_bytes_to_le_limbs(&digest))
    }

    /// Computes the `PK_COMM` word expected by `ecdsa_k256_keccak::verify`.
    ///
    /// The commitment is delegated to [`PublicKey::to_commitment()`], which commits to the same
    /// native-coordinate element sequence returned by [`SequentialCommit::to_elements()`].
    pub fn public_key_commitment(pk: &PublicKey) -> Word {
        pk.to_commitment()
    }

    fn signature_felts(signature: &Signature) -> [Felt; 16] {
        let mut felts = [Felt::from_u32(0); 16];
        felts[..8].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.r())));
        felts[8..].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.s())));
        felts
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
