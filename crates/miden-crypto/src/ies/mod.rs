//! Integrated Encryption Scheme (IES) utilities.
//!
//! This module combines elliptic-curve Diffie–Hellman (ECDH) key agreement with authenticated
//! encryption (AEAD) to provide sealed boxes that offer confidentiality and integrity for messages.
//! It exposes a simple API via [`SealingKey`], [`UnsealingKey`], [`SealedMessage`], and
//! [`IesError`].
//!
//! # Examples
//!
//! ```
//! use miden_crypto::{
//!     dsa::eddsa_25519_sha512::KeyExchangeKey,
//!     ies::{SealingKey, UnsealingKey},
//! };
//! use rand::rng;
//!
//! let mut rng = rng();
//! let secret_key = KeyExchangeKey::with_rng(&mut rng);
//! let public_key = secret_key.public_key();
//!
//! let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
//! let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
//!
//! let sealed = sealing_key.seal_bytes(&mut rng, b"hello world").unwrap();
//! let opened = unsealing_key.unseal_bytes(sealed).unwrap();
//!
//! assert_eq!(opened.as_slice(), b"hello world");
//! ```

mod crypto_box;
mod keys;
mod message;

#[cfg(test)]
mod tests;

pub use keys::{SealingKey, UnsealingKey};
pub use message::SealedMessage;
use thiserror::Error;

// IES SCHEME
// ================================================================================================

/// Supported schemes for IES
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IesScheme {
    K256XChaCha20Poly1305 = 0,
    X25519XChaCha20Poly1305 = 1,
    K256AeadPoseidon2 = 2,
    X25519AeadPoseidon2 = 3,
}

impl TryFrom<u8> for IesScheme {
    type Error = IesError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IesScheme::K256XChaCha20Poly1305),
            1 => Ok(IesScheme::X25519XChaCha20Poly1305),
            2 => Ok(IesScheme::K256AeadPoseidon2),
            3 => Ok(IesScheme::X25519AeadPoseidon2),
            _ => Err(IesError::UnsupportedScheme),
        }
    }
}

impl From<IesScheme> for u8 {
    fn from(algo: IesScheme) -> Self {
        algo as u8
    }
}

impl core::fmt::Display for IesScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl IesScheme {
    pub fn name(self) -> &'static str {
        match self {
            IesScheme::K256XChaCha20Poly1305 => "K256+XChaCha20-Poly1305",
            IesScheme::X25519XChaCha20Poly1305 => "X25519+XChaCha20-Poly1305",
            IesScheme::K256AeadPoseidon2 => "K256+AeadPoseidon2",
            IesScheme::X25519AeadPoseidon2 => "X25519+AeadPoseidon2",
        }
    }
}

// IES ERROR
// ================================================================================================

/// Error type for the Integrated Encryption Scheme (IES)
#[derive(Debug, Error)]
pub enum IesError {
    #[error("key agreement failed")]
    KeyAgreementFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid key size")]
    InvalidKeySize,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("ephemeral public key deserialization failed")]
    EphemeralPublicKeyDeserializationFailed,
    #[error("scheme mismatch")]
    SchemeMismatch,
    #[error("unsupported scheme")]
    UnsupportedScheme,
    #[error("failed to extract key material for encryption/decryption")]
    FailedExtractKeyMaterial,
    #[error("failed to construct the encryption/decryption key from the provided bytes")]
    EncryptionKeyCreationFailed,
}
