//! Core cryptographic primitive for Integrated Encryption Scheme (IES).
//!
//! This module defines the generic `CryptoBox` abstraction that combines a key agreement scheme
//! (e.g. K256 ECDH) with an AEAD scheme (e.g. XChaCha20-Poly1305) to provide authenticated
//! encryption.

use alloc::vec::Vec;

use rand::CryptoRng;

use super::{IesError, IesScheme};
use crate::{
    Felt,
    aead::AeadScheme,
    ecdh::KeyAgreementScheme,
    utils::{Serializable, zeroize::Zeroizing},
};

// CRYPTO BOX
// ================================================================================================

/// A generic CryptoBox primitive parameterized by key agreement and AEAD schemes.
pub(super) struct CryptoBox<K: KeyAgreementScheme, A: AeadScheme> {
    _phantom: core::marker::PhantomData<(K, A)>,
}

impl<K: KeyAgreementScheme, A: AeadScheme> CryptoBox<K, A> {
    const KDF_CONTEXT: &'static [u8] = b"miden-crypto/ies/hkdf-v2";

    /// Builds the HKDF `info` used for IES key derivation.
    /// Layout: `[KDF_CONTEXT || scheme_id || ephemeral_public_key || recipient_public_key]`.
    /// Each supported scheme uses fixed-size key encodings, with `scheme_id = scheme as u8`.
    fn build_kdf_info(
        scheme: IesScheme,
        ephemeral_public_key: &K::EphemeralPublicKey,
        recipient_public_key: &K::PublicKey,
    ) -> Vec<u8> {
        let ephemeral_bytes = ephemeral_public_key.to_bytes();
        let recipient_bytes = recipient_public_key.to_bytes();
        let mut info = Vec::with_capacity(
            Self::KDF_CONTEXT.len() + 1 + ephemeral_bytes.len() + recipient_bytes.len(),
        );
        info.extend_from_slice(Self::KDF_CONTEXT);
        info.push(scheme as u8);
        info.extend_from_slice(&ephemeral_bytes);
        info.extend_from_slice(&recipient_bytes);
        info
    }

    // BYTE-SPECIFIC METHODS
    // --------------------------------------------------------------------------------------------

    pub fn seal_bytes_with_associated_data<R: CryptoRng>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        scheme: IesScheme,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, K::EphemeralPublicKey), IesError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let kdf_info = Self::build_kdf_info(scheme, &ephemeral_public, recipient_public_key);
        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE, &kdf_info)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            A::key_from_uniform_bytes(&encryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = A::encrypt_bytes(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IesError::EncryptionFailed)?;

        Ok((ciphertext, ephemeral_public))
    }

    pub fn unseal_bytes_with_associated_data(
        recipient_private_key: &K::SecretKey,
        ephemeral_public_key: &K::EphemeralPublicKey,
        scheme: IesScheme,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IesError> {
        let shared_secret = Zeroizing::new(
            K::exchange_static_ephemeral(recipient_private_key, ephemeral_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let recipient_public_key = K::public_key(recipient_private_key);
        let kdf_info = Self::build_kdf_info(scheme, ephemeral_public_key, &recipient_public_key);
        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE, &kdf_info)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let decryption_key = Zeroizing::new(
            A::key_from_uniform_bytes(&decryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        A::decrypt_bytes_with_associated_data(&decryption_key, ciphertext, associated_data)
            .map_err(|_| IesError::DecryptionFailed)
    }

    // ELEMENT-SPECIFIC METHODS
    // --------------------------------------------------------------------------------------------

    pub fn seal_elements_with_associated_data<R: CryptoRng>(
        rng: &mut R,
        recipient_public_key: &K::PublicKey,
        scheme: IesScheme,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<(Vec<u8>, K::EphemeralPublicKey), IesError> {
        let (ephemeral_private, ephemeral_public) = K::generate_ephemeral_keypair(rng);

        let shared_secret = Zeroizing::new(
            K::exchange_ephemeral_static(ephemeral_private, recipient_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let kdf_info = Self::build_kdf_info(scheme, &ephemeral_public, recipient_public_key);
        let encryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE, &kdf_info)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let encryption_key = Zeroizing::new(
            A::key_from_uniform_bytes(&encryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        let ciphertext = A::encrypt_elements(&encryption_key, rng, plaintext, associated_data)
            .map_err(|_| IesError::EncryptionFailed)?;

        Ok((ciphertext, ephemeral_public))
    }

    pub fn unseal_elements_with_associated_data(
        recipient_private_key: &K::SecretKey,
        ephemeral_public_key: &K::EphemeralPublicKey,
        scheme: IesScheme,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, IesError> {
        let shared_secret = Zeroizing::new(
            K::exchange_static_ephemeral(recipient_private_key, ephemeral_public_key)
                .map_err(|_| IesError::KeyAgreementFailed)?,
        );

        let recipient_public_key = K::public_key(recipient_private_key);
        let kdf_info = Self::build_kdf_info(scheme, ephemeral_public_key, &recipient_public_key);
        let decryption_key_bytes = Zeroizing::new(
            K::extract_key_material(&shared_secret, <A as AeadScheme>::KEY_SIZE, &kdf_info)
                .map_err(|_| IesError::FailedExtractKeyMaterial)?,
        );

        let decryption_key = Zeroizing::new(
            A::key_from_uniform_bytes(&decryption_key_bytes)
                .map_err(|_| IesError::EncryptionKeyCreationFailed)?,
        );

        A::decrypt_elements_with_associated_data(&decryption_key, ciphertext, associated_data)
            .map_err(|_| IesError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aead::xchacha::XChaCha,
        dsa::eddsa_25519_sha512::PublicKey,
        ecdh::x25519::{EphemeralPublicKey, X25519},
        utils::Deserializable,
    };

    #[test]
    fn kdf_v2_known_answer() {
        let mut recipient = [0x66; 32];
        recipient[0] = 0x58; // Ed25519 basepoint encoding.
        let recipient = PublicKey::read_from_bytes(&recipient).unwrap();
        let mut ephemeral = [0; 32];
        ephemeral[0] = 9; // X25519 basepoint encoding.
        let ephemeral = EphemeralPublicKey::read_from_bytes(&ephemeral).unwrap();
        let info = CryptoBox::<X25519, XChaCha>::build_kdf_info(
            IesScheme::X25519XChaCha20Poly1305,
            &ephemeral,
            &recipient,
        );
        // Independently computed with HKDF-Extract and one HKDF-Expand block (RFC 5869).
        let key = crate::ecdh::extract_key_material(&[0x42; 32], None, 32, &info).unwrap();
        assert_eq!(
            hex::encode(key),
            "9a40b0d74ef91c20291e196482bea49d3ce7d1fd8203f1a75d37b4f60d51686d"
        );
    }
}
