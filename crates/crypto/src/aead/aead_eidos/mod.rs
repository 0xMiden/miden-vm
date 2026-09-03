//! Authenticated encryption built from the Eidos compression function.
//!
//! Encryption uses a counter-mode stream over canonical field-element limbs. Authentication uses
//! a polynomial MAC over the quadratic extension of the Miden base field. A `(key, nonce)` pair
//! must never be reused. See [`MAX_AUTHENTICATED_INPUT_FELTS`] and
//! [`MAX_VERIFICATION_DEGREE_BUDGET_PER_KEY`] for the message and key-usage limits.

use alloc::{format, string::ToString, vec::Vec};

use miden_crypto_derive::{SilentDebug, SilentDisplay};
use rand::{
    CryptoRng,
    distr::{Distribution, Uniform},
};
#[cfg(any(test, feature = "testing"))]
use subtle::ConstantTimeEq;

use super::{AeadScheme, DataType, EncryptionError};
use crate::{
    Felt, Word, ZERO,
    field::PrimeCharacteristicRing,
    utils::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader, bytes_to_elements_exact, bytes_to_elements_with_padding, elements_to_bytes,
        padded_elements_to_bytes, read_sensitive_array,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
};

/// Low-level stream and authentication operations over expanded `u32` limbs.
pub mod expanded;

#[cfg(test)]
mod tests;

/// Number of field elements in an Eidos AEAD secret key.
pub const SECRET_KEY_SIZE: usize = 4;

/// Serialized size of an Eidos AEAD secret key.
pub const SK_SIZE_BYTES: usize = SECRET_KEY_SIZE * Felt::NUM_BYTES;

/// Number of field elements in an Eidos AEAD nonce.
pub const NONCE_SIZE: usize = 4;

/// Serialized size of an Eidos AEAD nonce.
pub const NONCE_SIZE_BYTES: usize = NONCE_SIZE * Felt::NUM_BYTES;

/// Number of field elements in an Eidos AEAD authentication tag.
pub const AUTH_TAG_SIZE: usize = 2;

/// Registered Eidos domain ID for deriving the AEAD counter-mode chaining value.
pub const AEAD_CTR_DOMAIN_ID: u32 = 0x000006;

/// Registered Eidos selector for deriving the AEAD counter-mode chaining value.
pub const AEAD_CTR_SELECTOR: u32 = (AEAD_CTR_DOMAIN_ID << 8) | 1;

/// Registered Eidos domain ID for deriving the AEAD MAC key.
pub const AEAD_MAC_DOMAIN_ID: u32 = 0x000007;

/// Registered Eidos selector for deriving the AEAD MAC key.
pub const AEAD_MAC_SELECTOR: u32 = (AEAD_MAC_DOMAIN_ID << 8) | 1;

/// Maximum number of base-field elements in the padded polynomial-MAC input.
///
/// This count includes the nonce, associated data, expanded ciphertext, encoded lengths, and
/// padding. It limits each authentication polynomial to at most `2^27` quadratic-extension
/// coefficients.
pub const MAX_AUTHENTICATED_INPUT_FELTS: usize = 1 << 28;

/// Maximum sum of polynomial-degree bounds across verification attempts under one key when
/// targeting 96-bit authentication security.
///
/// For each attempt, the degree bound is the larger coefficient count of the submitted message and
/// any message previously authenticated with the same nonce. Applications are responsible for
/// enforcing this lifetime limit. Reusing a nonce is forbidden regardless of this budget.
pub const MAX_VERIFICATION_DEGREE_BUDGET_PER_KEY: u64 = 1 << 28;

/// Ciphertext and authentication data produced by [`SecretKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    data_type: DataType,
    ciphertext: Vec<Felt>,
    auth_tag: AuthTag,
    nonce: Nonce,
}

impl EncryptedData {
    /// Constructs encrypted data after validating its expanded ciphertext representation.
    pub fn from_parts(
        data_type: DataType,
        ciphertext: Vec<Felt>,
        auth_tag: AuthTag,
        nonce: Nonce,
    ) -> Result<Self, EncryptionError> {
        validate_ciphertext(&ciphertext)?;
        Ok(Self { data_type, ciphertext, auth_tag, nonce })
    }

    /// Returns the representation of the plaintext before encryption.
    pub fn data_type(&self) -> DataType {
        self.data_type
    }

    /// Returns the expanded u32-limb ciphertext.
    pub fn ciphertext(&self) -> &[Felt] {
        &self.ciphertext
    }

    /// Returns the authentication tag.
    pub fn auth_tag(&self) -> &AuthTag {
        &self.auth_tag
    }

    /// Returns the nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

/// Authentication tag over two elements of the Miden base field.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AuthTag([Felt; AUTH_TAG_SIZE]);

impl AuthTag {
    /// Constructs a tag from its field elements.
    pub fn new(elements: [Felt; AUTH_TAG_SIZE]) -> Self {
        Self(elements)
    }

    /// Returns the field elements in this tag.
    pub fn to_elements(self) -> [Felt; AUTH_TAG_SIZE] {
        self.0
    }
}

/// Eidos AEAD secret key.
#[derive(Clone, SilentDebug, SilentDisplay)]
pub struct SecretKey([Felt; SECRET_KEY_SIZE]);

impl SecretKey {
    /// Generates a key with the operating system's random-number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_rng(&mut rand::rng())
    }

    /// Generates a key with the supplied cryptographic random-number generator.
    pub fn with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(sample_felts(rng))
    }

    /// Constructs a key from four field elements.
    pub fn from_elements(elements: [Felt; SECRET_KEY_SIZE]) -> Self {
        Self(elements)
    }

    /// Returns the key as four field elements.
    ///
    /// The returned value contains secret key material and should be cleared after use.
    pub fn to_elements(&self) -> [Felt; SECRET_KEY_SIZE] {
        self.0
    }

    /// Encrypts field elements with a fresh random nonce.
    #[cfg(feature = "std")]
    pub fn encrypt_elements(&self, plaintext: &[Felt]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_elements_with_associated_data(plaintext, &[])
    }

    /// Encrypts field elements and authenticates the supplied associated data.
    #[cfg(feature = "std")]
    pub fn encrypt_elements_with_associated_data(
        &self,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_elements_with_nonce(
            plaintext,
            associated_data,
            Nonce::with_rng(&mut rand::rng()),
        )
    }

    /// Encrypts field elements with an explicit nonce.
    ///
    /// The caller must ensure that the nonce has not been used with this key before.
    pub fn encrypt_elements_with_nonce(
        &self,
        plaintext: &[Felt],
        associated_data: &[Felt],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        validate_encryption_lengths(plaintext.len(), associated_data.len())?;
        let authenticated_data = bind_data_type(DataType::Elements, associated_data)?;
        let (ciphertext, tag) = expanded::encrypt_felts_expanded_authenticated(
            self.as_word(),
            nonce.as_word(),
            &authenticated_data,
            plaintext,
        );

        EncryptedData::from_parts(DataType::Elements, ciphertext, AuthTag(tag), nonce)
    }

    /// Encrypts bytes with a fresh random nonce.
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_bytes_with_associated_data(plaintext, &[])
    }

    /// Encrypts bytes and authenticates the supplied associated data.
    #[cfg(feature = "std")]
    pub fn encrypt_bytes_with_associated_data(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_bytes_with_nonce(plaintext, associated_data, Nonce::with_rng(&mut rand::rng()))
    }

    /// Encrypts bytes with an explicit nonce.
    ///
    /// The caller must ensure that the nonce has not been used with this key before.
    pub fn encrypt_bytes_with_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        let plaintext = bytes_to_elements_with_padding(plaintext);
        let associated_data = bytes_to_elements_with_padding(associated_data);
        validate_encryption_lengths(plaintext.len(), associated_data.len())?;
        let authenticated_data = bind_data_type(DataType::Bytes, &associated_data)?;
        let (ciphertext, tag) = expanded::encrypt_felts_expanded_authenticated(
            self.as_word(),
            nonce.as_word(),
            &authenticated_data,
            &plaintext,
        );

        EncryptedData::from_parts(DataType::Bytes, ciphertext, AuthTag(tag), nonce)
    }

    /// Decrypts field elements after verifying their authentication tag.
    pub fn decrypt_elements(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<Felt>, EncryptionError> {
        self.decrypt_elements_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts field elements after authenticating the ciphertext and associated data.
    pub fn decrypt_elements_with_associated_data(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        ensure_data_type(encrypted_data, DataType::Elements)?;
        let authenticated_data = bind_data_type(DataType::Elements, associated_data)?;
        self.decrypt_felts(encrypted_data, &authenticated_data)
    }

    /// Decrypts bytes after verifying their authentication tag.
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_bytes_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts bytes after authenticating the ciphertext and associated data.
    pub fn decrypt_bytes_with_associated_data(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        ensure_data_type(encrypted_data, DataType::Bytes)?;
        let associated_data = bytes_to_elements_with_padding(associated_data);
        let authenticated_data = bind_data_type(DataType::Bytes, &associated_data)?;
        let plaintext = self.decrypt_felts(encrypted_data, &authenticated_data)?;
        let bytes =
            padded_elements_to_bytes(&plaintext).ok_or(EncryptionError::MalformedPadding)?;

        if bytes_to_elements_with_padding(&bytes) != plaintext {
            return Err(EncryptionError::MalformedPadding);
        }
        Ok(bytes)
    }

    fn decrypt_felts(
        &self,
        encrypted_data: &EncryptedData,
        authenticated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        validate_ciphertext(&encrypted_data.ciphertext)?;
        expanded::checked_mac_input_len(authenticated_data.len(), encrypted_data.ciphertext.len())
            .ok_or(EncryptionError::InputTooLong)?;
        expanded::decrypt_felts_expanded_authenticated(
            self.as_word(),
            encrypted_data.nonce.as_word(),
            authenticated_data,
            &encrypted_data.ciphertext,
            encrypted_data.auth_tag.0,
        )
        .ok_or(EncryptionError::InvalidAuthTag)
    }

    fn as_word(&self) -> Word {
        Word::new(self.0)
    }
}

#[cfg(any(test, feature = "testing"))]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0).fold(true, |equal, (left, right)| {
            equal & bool::from(left.as_canonical_u64_ct().ct_eq(&right.as_canonical_u64_ct()))
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl Eq for SecretKey {}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        for element in &mut self.0 {
            unsafe { core::ptr::write_volatile(element, ZERO) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

/// Nonce for one Eidos AEAD invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([Felt; NONCE_SIZE]);

impl Nonce {
    /// Generates a nonce with the supplied cryptographic random-number generator.
    pub fn with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(sample_felts(rng))
    }

    /// Returns the nonce as four field elements.
    pub fn to_elements(self) -> [Felt; NONCE_SIZE] {
        self.0
    }

    fn as_word(self) -> Word {
        Word::new(self.0)
    }
}

impl From<Word> for Nonce {
    fn from(word: Word) -> Self {
        Self(word.into())
    }
}

impl From<[Felt; NONCE_SIZE]> for Nonce {
    fn from(elements: [Felt; NONCE_SIZE]) -> Self {
        Self(elements)
    }
}

impl From<Nonce> for Word {
    fn from(nonce: Nonce) -> Self {
        nonce.as_word()
    }
}

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&elements_to_bytes(&self.0));
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = read_sensitive_array::<SK_SIZE_BYTES, _>(source)?;
        let elements = bytes_to_elements_exact(bytes.as_slice())
            .and_then(|elements| elements.try_into().ok())
            .ok_or_else(|| {
                DeserializationError::InvalidValue("malformed secret key".to_string())
            })?;
        Ok(Self(elements))
    }
}

impl Serializable for Nonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&elements_to_bytes(&self.0));
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; NONCE_SIZE_BYTES] = source.read_array()?;
        let elements = bytes_to_elements_exact(&bytes)
            .and_then(|elements| elements.try_into().ok())
            .ok_or_else(|| DeserializationError::InvalidValue("malformed nonce".to_string()))?;
        Ok(Self(elements))
    }
}

impl Serializable for EncryptedData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.data_type as u8);
        self.ciphertext.write_into(target);
        target.write_many(self.nonce.0);
        target.write_many(self.auth_tag.0);
    }
}

impl Deserializable for EncryptedData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let data_type = source.read_u8()?.try_into().map_err(|_| {
            DeserializationError::InvalidValue("invalid encrypted-data type".to_string())
        })?;
        let ciphertext = Vec::<Felt>::read_from(source)?;
        let nonce = Nonce(source.read()?);
        let auth_tag = AuthTag(source.read()?);

        Self::from_parts(data_type, ciphertext, auth_tag, nonce).map_err(|error| {
            DeserializationError::InvalidValue(format!("malformed Eidos ciphertext: {error}"))
        })
    }
}

/// Eidos authenticated-encryption implementation.
pub struct AeadEidos;

impl AeadScheme for AeadEidos {
    const KEY_SIZE: usize = SK_SIZE_BYTES;

    type Key = SecretKey;

    fn key_from_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError> {
        if bytes.len() != SK_SIZE_BYTES {
            return Err(EncryptionError::FailedOperation);
        }
        SecretKey::read_from_bytes_with_budget(bytes, SK_SIZE_BYTES)
            .map_err(|_| EncryptionError::FailedOperation)
    }

    fn key_from_uniform_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError> {
        if bytes.len() != SK_SIZE_BYTES {
            return Err(EncryptionError::FailedOperation);
        }

        let (chunks, remainder) = bytes.as_chunks::<{ Felt::NUM_BYTES }>();
        debug_assert!(remainder.is_empty());
        Ok(SecretKey::from_elements(core::array::from_fn(|i| {
            Felt::from_u64(u64::from_le_bytes(chunks[i]))
        })))
    }

    fn encrypt_bytes<R: CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let encrypted =
            key.encrypt_bytes_with_nonce(plaintext, associated_data, Nonce::with_rng(rng))?;
        Ok(encrypted.to_bytes())
    }

    fn decrypt_bytes_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let encrypted = read_encrypted_data_strict(ciphertext)?;
        key.decrypt_bytes_with_associated_data(&encrypted, associated_data)
    }

    fn encrypt_elements<R: CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<u8>, EncryptionError> {
        let encrypted =
            key.encrypt_elements_with_nonce(plaintext, associated_data, Nonce::with_rng(rng))?;
        Ok(encrypted.to_bytes())
    }

    fn decrypt_elements_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        let encrypted = read_encrypted_data_strict(ciphertext)?;
        key.decrypt_elements_with_associated_data(&encrypted, associated_data)
    }
}

fn read_encrypted_data_strict(ciphertext: &[u8]) -> Result<EncryptedData, EncryptionError> {
    let mut reader = BudgetedReader::new(SliceReader::new(ciphertext), ciphertext.len());
    let encrypted =
        EncryptedData::read_from(&mut reader).map_err(|_| EncryptionError::FailedOperation)?;
    if reader.has_more_bytes() {
        return Err(EncryptionError::FailedOperation);
    }
    Ok(encrypted)
}

fn sample_felts<R: CryptoRng + ?Sized, const N: usize>(rng: &mut R) -> [Felt; N] {
    let distribution =
        Uniform::new(0, Felt::ORDER).expect("the field order defines a valid sampling range");
    core::array::from_fn(|_| Felt::new_unchecked(distribution.sample(rng)))
}

fn bind_data_type(
    data_type: DataType,
    associated_data: &[Felt],
) -> Result<Vec<Felt>, EncryptionError> {
    let capacity = associated_data.len().checked_add(1).ok_or(EncryptionError::InputTooLong)?;
    u32::try_from(capacity).map_err(|_| EncryptionError::InputTooLong)?;

    let mut bound = Vec::with_capacity(capacity);
    bound.push(Felt::from_u32(data_type as u8 as u32));
    bound.extend_from_slice(associated_data);
    Ok(bound)
}

fn validate_encryption_lengths(
    plaintext_len: usize,
    associated_data_len: usize,
) -> Result<(), EncryptionError> {
    let ciphertext_len = plaintext_len.checked_mul(2).ok_or(EncryptionError::InputTooLong)?;
    let authenticated_data_len =
        associated_data_len.checked_add(1).ok_or(EncryptionError::InputTooLong)?;
    expanded::checked_mac_input_len(authenticated_data_len, ciphertext_len)
        .ok_or(EncryptionError::InputTooLong)?;
    Ok(())
}

fn validate_ciphertext(ciphertext: &[Felt]) -> Result<(), EncryptionError> {
    if !ciphertext.len().is_multiple_of(2)
        || ciphertext.iter().any(|felt| felt.as_canonical_u64() > u64::from(u32::MAX))
    {
        return Err(EncryptionError::MalformedCiphertext);
    }
    // Every high-level invocation authenticates a one-Felt data-type marker, even when the caller
    // supplies no associated data.
    expanded::checked_mac_input_len(1, ciphertext.len()).ok_or(EncryptionError::InputTooLong)?;
    Ok(())
}

fn ensure_data_type(
    encrypted_data: &EncryptedData,
    expected: DataType,
) -> Result<(), EncryptionError> {
    if encrypted_data.data_type != expected {
        return Err(EncryptionError::InvalidDataType {
            expected,
            found: encrypted_data.data_type,
        });
    }
    Ok(())
}
