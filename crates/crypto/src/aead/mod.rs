//! AEAD (authenticated encryption with associated data) schemes.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use thiserror::Error;

use crate::{
    Felt,
    utils::{
        Deserializable,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
};

pub mod aead_eidos;
pub mod xchacha;

/// Indicates whether encrypted data originated from field elements or raw bytes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Elements = 0,
    Bytes = 1,
}

impl TryFrom<u8> for DataType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DataType::Elements),
            1 => Ok(DataType::Bytes),
            _ => Err("invalid data type value: expected 0 for Elements or 1 for Bytes".to_string()),
        }
    }
}

// AEAD TRAIT
// ================================================================================================

/// Authenticated encryption with associated data (AEAD) scheme
pub(crate) trait AeadScheme {
    const KEY_SIZE: usize;

    type Key: Deserializable + Zeroize + ZeroizeOnDrop;

    fn key_from_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError>;

    /// Derives a key from arbitrary uniform bytes (e.g. HKDF output), reducing into the key's
    /// native representation without rejecting any byte patterns.
    ///
    /// Unlike [`key_from_bytes`](AeadScheme::key_from_bytes), which deserializes a canonical
    /// encoding and rejects non-canonical values, this method accepts any `KEY_SIZE` bytes and
    /// is therefore suitable for KDF/IES output that may contain limbs outside the canonical
    /// range. The default impl delegates to `key_from_bytes`, which is correct for schemes
    /// whose key representation has no canonical constraint (e.g. raw byte keys).
    fn key_from_uniform_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError> {
        Self::key_from_bytes(bytes)
    }

    // BYTE METHODS
    // ================================================================================================

    fn encrypt_bytes<R: rand::CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    fn decrypt_bytes_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError>;

    // FELT METHODS
    // ================================================================================================

    /// Encrypts field elements with associated data, preserving their element representation.
    fn encrypt_elements<R: rand::CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<u8>, EncryptionError>;

    /// Decrypts field elements with associated data, rejecting ciphertexts encrypted as bytes.
    fn decrypt_elements_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError>;
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("authentication tag verification failed")]
    InvalidAuthTag,
    #[error("operation failed")]
    FailedOperation,
    #[error("input is too long")]
    InputTooLong,
    #[error("malformed expanded ciphertext")]
    MalformedCiphertext,
    #[error("malformed padding")]
    MalformedPadding,
    #[error("invalid data type: expected {expected:?}, found {found:?}")]
    InvalidDataType { expected: DataType, found: DataType },
    #[error(
        "failed to convert bytes, that are supposed to originate from field elements, back to field elements"
    )]
    FailedBytesToElementsConversion,
}
