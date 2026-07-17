//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

use alloc::vec::Vec;

use hkdf::Hkdf;
use rand::CryptoRng;
use sha2::{Sha256, digest::OutputSizeUser};
use thiserror::Error;

use crate::utils::{
    Deserializable, Serializable,
    zeroize::{Zeroize, ZeroizeOnDrop},
};

pub mod k256;
pub mod x25519;

// KEY AGREEMENT TRAIT
// ================================================================================================

pub(crate) trait KeyAgreementScheme {
    type EphemeralSecretKey: ZeroizeOnDrop;
    type EphemeralPublicKey: Serializable + Deserializable;

    type SecretKey;
    type PublicKey: Clone;

    type SharedSecret: AsRef<[u8]> + Zeroize + ZeroizeOnDrop;

    /// Returns an ephemeral key pair generated from the provided RNG.
    fn generate_ephemeral_keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> (Self::EphemeralSecretKey, Self::EphemeralPublicKey);

    /// Performs key exchange between ephemeral secret and static public key.
    fn exchange_ephemeral_static(
        ephemeral_sk: Self::EphemeralSecretKey,
        static_pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Performs key exchange between static secret and ephemeral public key.
    fn exchange_static_ephemeral(
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, KeyAgreementError>;

    /// Extracts key material from shared secret.
    ///
    /// `info` is the HKDF context string for domain separation and binding to the IES scheme and
    /// ephemeral public key (see `CryptoBox::build_kdf_info`).
    fn extract_key_material(
        shared_secret: &Self::SharedSecret,
        length: usize,
        info: &[u8],
    ) -> Result<Vec<u8>, KeyAgreementError>;
}

/// Extracts key material from shared secret bytes with HKDF-SHA256.
///
/// This is the KDF used by the integrated encryption scheme after ECDH key agreement.
pub fn extract_key_material(
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    length: usize,
    info: &[u8],
) -> Result<Vec<u8>, KeyAgreementError> {
    if length > 255 * Sha256::output_size() {
        return Err(KeyAgreementError::HkdfExpansionFailed);
    }
    let hkdf = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut buf = vec![0_u8; length];
    hkdf.expand(info, &mut buf)
        .map_err(|_| KeyAgreementError::HkdfExpansionFailed)?;
    Ok(buf)
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub enum KeyAgreementError {
    #[error("hkdf expansion failed")]
    HkdfExpansionFailed,
    #[error("shared secret is invalid")]
    InvalidSharedSecret,
}
