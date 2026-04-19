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

pub mod aead_poseidon2;
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

    // BYTE METHODS
    // ================================================================================================

    fn encrypt_bytes<R: rand::CryptoRng + rand::RngCore>(
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

    /// Encrypts field elements with associated data. Default implementation converts to bytes.
    fn encrypt_elements<R: rand::CryptoRng + rand::RngCore>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<u8>, EncryptionError> {
        let plaintext_bytes = crate::utils::elements_to_bytes(plaintext);
        let ad_bytes = crate::utils::elements_to_bytes(associated_data);

        Self::encrypt_bytes(key, rng, &plaintext_bytes, &ad_bytes)
    }

    /// Decrypts field elements with associated data. Default implementation uses byte decryption.
    fn decrypt_elements_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        let ad_bytes = crate::utils::elements_to_bytes(associated_data);
        let plaintext_bytes = Self::decrypt_bytes_with_associated_data(key, ciphertext, &ad_bytes)?;

        match crate::utils::bytes_to_elements_exact(&plaintext_bytes) {
            Some(elements) => Ok(elements),
            None => Err(EncryptionError::FailedBytesToElementsConversion),
        }
    }
}

// ERROR TYPES
// ================================================================================================

/// Errors that can occur during encryption/decryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("authentication tag verification failed")]
    InvalidAuthTag,
    #[error("peration failed")]
    FailedOperation,
    #[error("malformed padding")]
    MalformedPadding,
    #[error("ciphertext length, in field elements, is not a multiple of `RATE_WIDTH`")]
    CiphertextLenNotMultipleRate,
    #[error("invalid data type: expected {expected:?}, found {found:?}")]
    InvalidDataType { expected: DataType, found: DataType },
    #[error(
        "failed to convert bytes, that are supposed to originate from field elements, back to field elements"
    )]
    FailedBytesToElementsConversion,
}
