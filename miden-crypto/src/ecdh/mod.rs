//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementations.

use alloc::vec::Vec;

use rand::{CryptoRng, RngCore};
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
    fn generate_ephemeral_keypair<R: CryptoRng + RngCore>(
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

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub(crate) enum KeyAgreementError {
    #[error("hkdf expansion failed")]
    HkdfExpansionFailed,
    #[error("shared secret is invalid")]
    InvalidSharedSecret,
}
