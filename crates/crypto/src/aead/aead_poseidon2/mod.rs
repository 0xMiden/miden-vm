//! # Arithmetization Oriented AEAD
//!
//! This module implements an AEAD scheme optimized for speed within SNARKs/STARKs.
//! The design is described in \[1\] and is based on the MonkeySpongeWrap construction and uses
//! the Poseidon2 permutation, creating an encryption scheme that is highly efficient when executed
//! within zero-knowledge proof systems.
//!
//! \[1\] <https://eprint.iacr.org/2023/1668>

use alloc::{string::ToString, vec::Vec};
use core::ops::Range;

use miden_crypto_derive::{SilentDebug, SilentDisplay};
use num::Integer;
use rand::{
    Rng, RngExt,
    distr::{Distribution, StandardUniform, Uniform},
};
use subtle::ConstantTimeEq;

use crate::{
    Felt, ONE, Word, ZERO,
    aead::{AeadScheme, DataType, EncryptionError},
    hash::poseidon2::Poseidon2,
    utils::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader, bytes_to_elements_exact, bytes_to_elements_with_padding, elements_to_bytes,
        padded_elements_to_bytes, read_sensitive_array,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
};

#[cfg(test)]
mod test;

// CONSTANTS
// ================================================================================================

/// Size of a secret key in field elements
pub const SECRET_KEY_SIZE: usize = 4;

/// Size of a secret key in bytes
pub const SK_SIZE_BYTES: usize = SECRET_KEY_SIZE * Felt::NUM_BYTES;

/// Size of a nonce in field elements
pub const NONCE_SIZE: usize = 4;

/// Size of a nonce in bytes
pub const NONCE_SIZE_BYTES: usize = NONCE_SIZE * Felt::NUM_BYTES;

/// Size of an authentication tag in field elements
pub const AUTH_TAG_SIZE: usize = 4;

/// Size of the sponge state field elements
const STATE_WIDTH: usize = Poseidon2::STATE_WIDTH;

/// Capacity portion of the sponge state.
const CAPACITY_RANGE: Range<usize> = Poseidon2::CAPACITY_RANGE;

/// Rate portion of the sponge state
const RATE_RANGE: Range<usize> = Poseidon2::RATE_RANGE;

/// Size of the rate portion of the sponge state in field elements
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

/// Size of either the 1st or 2nd half of the rate portion of the sponge state in field elements
const HALF_RATE_WIDTH: usize = (Poseidon2::RATE_RANGE.end - Poseidon2::RATE_RANGE.start) / 2;

/// First half of the rate portion of the sponge state
const RATE_RANGE_FIRST_HALF: Range<usize> =
    Poseidon2::RATE_RANGE.start..Poseidon2::RATE_RANGE.start + HALF_RATE_WIDTH;

/// Second half of the rate portion of the sponge state
const RATE_RANGE_SECOND_HALF: Range<usize> =
    Poseidon2::RATE_RANGE.start + HALF_RATE_WIDTH..Poseidon2::RATE_RANGE.end;

/// Index of the first element of the rate portion of the sponge state
const RATE_START: usize = Poseidon2::RATE_RANGE.start;

/// Padding block used when the length of the data to encrypt is a multiple of `RATE_WIDTH`
const PADDING_BLOCK: [Felt; RATE_WIDTH] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

// TYPES AND STRUCTURES
// ================================================================================================

/// Encrypted data with its authentication tag
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedData {
    /// Indicates the original format of the data before encryption
    data_type: DataType,
    /// The encrypted ciphertext
    ciphertext: Vec<Felt>,
    /// The authentication tag attesting to the integrity of the ciphertext, and the associated
    /// data if it exists
    auth_tag: AuthTag,
    /// The nonce used during encryption
    nonce: Nonce,
}

impl EncryptedData {
    /// Constructs an EncryptedData from its component parts.
    pub fn from_parts(
        data_type: DataType,
        ciphertext: Vec<Felt>,
        auth_tag: AuthTag,
        nonce: Nonce,
    ) -> Self {
        Self { data_type, ciphertext, auth_tag, nonce }
    }

    /// Returns the data type of the encrypted data
    pub fn data_type(&self) -> DataType {
        self.data_type
    }

    /// Returns a reference to the ciphertext
    pub fn ciphertext(&self) -> &[Felt] {
        &self.ciphertext
    }

    /// Returns a reference to the authentication tag
    pub fn auth_tag(&self) -> &AuthTag {
        &self.auth_tag
    }

    /// Returns a reference to the nonce
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

/// An authentication tag represented as 4 field elements
#[derive(Debug, Default, Clone)]
pub struct AuthTag([Felt; AUTH_TAG_SIZE]);

impl AuthTag {
    /// Constructs an AuthTag from an array of field elements.
    pub fn new(elements: [Felt; AUTH_TAG_SIZE]) -> Self {
        Self(elements)
    }

    /// Returns the authentication tag as an array of field elements
    pub fn to_elements(&self) -> [Felt; AUTH_TAG_SIZE] {
        self.0
    }
}

impl PartialEq for AuthTag {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison on non-wasm targets to reduce timing leaks. On wasm, the
        // canonicalization helper is a host call and not guaranteed constant-time.
        let mut result = true;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            result &= bool::from(a.as_canonical_u64_ct().ct_eq(&b.as_canonical_u64_ct()));
        }
        result
    }
}

impl Eq for AuthTag {}

/// A 256-bit secret key represented as 4 field elements
#[derive(Clone, SilentDebug, SilentDisplay)]
pub struct SecretKey([Felt; SECRET_KEY_SIZE]);

impl SecretKey {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new random secret key using the default random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self::with_rng(&mut rng)
    }

    /// Creates a new random secret key using the provided random number generator.
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
    }

    /// Creates a secret key from the provided array of field elements.
    ///
    /// # Security Warning
    /// This method should be used with caution. Secret keys must be derived from a
    /// cryptographically secure source of entropy. Do not use predictable or low-entropy
    /// values as secret key material. Prefer using `new()` or `with_rng()` with a
    /// cryptographically secure random number generator.
    pub fn from_elements(elements: [Felt; SECRET_KEY_SIZE]) -> Self {
        Self(elements)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the secret key as an array of field elements.
    ///
    /// # Security Warning
    /// This method exposes the raw secret key material. Use with caution and ensure
    /// proper zeroization of the returned array when no longer needed.
    pub fn to_elements(&self) -> [Felt; SECRET_KEY_SIZE] {
        self.0
    }

    // ELEMENT ENCRYPTION
    // --------------------------------------------------------------------------------------------

    /// Encrypts and authenticates the provided sequence of field elements using this secret key
    /// and a random nonce.
    #[cfg(feature = "std")]
    pub fn encrypt_elements(&self, data: &[Felt]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_elements_with_associated_data(data, &[])
    }

    /// Encrypts the provided sequence of field elements and authenticates both the ciphertext as
    /// well as the provided associated data using this secret key and a random nonce.
    #[cfg(feature = "std")]
    pub fn encrypt_elements_with_associated_data(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
    ) -> Result<EncryptedData, EncryptionError> {
        let mut rng = rand::rng();
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_elements_with_nonce(data, associated_data, nonce)
    }

    /// Encrypts the provided sequence of field elements and authenticates both the ciphertext as
    /// well as the provided associated data using this secret key and the specified nonce.
    pub fn encrypt_elements_with_nonce(
        &self,
        data: &[Felt],
        associated_data: &[Felt],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        // Initialize as sponge state with key and nonce
        let mut sponge = SpongeState::new(self, &nonce);

        // Process the associated data
        let padded_associated_data = pad(associated_data);
        padded_associated_data.chunks(RATE_WIDTH).for_each(|chunk| {
            sponge.duplex_overwrite(chunk);
        });

        // Encrypt the data
        let mut ciphertext = Vec::with_capacity(data.len() + RATE_WIDTH);
        let data = pad(data);
        let mut data_block_iterator = data.chunks_exact(RATE_WIDTH);

        data_block_iterator.by_ref().for_each(|data_block| {
            let keystream = sponge.duplex_add(data_block);
            for (i, &plaintext_felt) in data_block.iter().enumerate() {
                ciphertext.push(plaintext_felt + keystream[i]);
            }
        });

        // Generate authentication tag
        let auth_tag = sponge.squeeze_tag();

        Ok(EncryptedData {
            data_type: DataType::Elements,
            ciphertext,
            auth_tag,
            nonce,
        })
    }

    // BYTE ENCRYPTION
    // --------------------------------------------------------------------------------------------

    /// Encrypts and authenticates the provided data using this secret key and a random nonce.
    ///
    /// Before encryption, the bytestring is converted to a sequence of field elements.
    #[cfg(feature = "std")]
    pub fn encrypt_bytes(&self, data: &[u8]) -> Result<EncryptedData, EncryptionError> {
        self.encrypt_bytes_with_associated_data(data, &[])
    }

    /// Encrypts the provided data and authenticates both the ciphertext as well as the provided
    /// associated data using this secret key and a random nonce.
    ///
    /// Before encryption, both the data and the associated data are converted to sequences of
    /// field elements.
    #[cfg(feature = "std")]
    pub fn encrypt_bytes_with_associated_data(
        &self,
        data: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedData, EncryptionError> {
        let mut rng = rand::rng();
        let nonce = Nonce::with_rng(&mut rng);

        self.encrypt_bytes_with_nonce(data, associated_data, nonce)
    }

    /// Encrypts the provided data and authenticates both the ciphertext as well as the provided
    /// associated data using this secret key and the specified nonce.
    ///
    /// Before encryption, both the data and the associated data are converted to sequences of
    /// field elements.
    pub fn encrypt_bytes_with_nonce(
        &self,
        data: &[u8],
        associated_data: &[u8],
        nonce: Nonce,
    ) -> Result<EncryptedData, EncryptionError> {
        let data_felt = bytes_to_elements_with_padding(data);
        let ad_felt = bytes_to_elements_with_padding(associated_data);

        let mut encrypted_data = self.encrypt_elements_with_nonce(&data_felt, &ad_felt, nonce)?;
        encrypted_data.data_type = DataType::Bytes;
        Ok(encrypted_data)
    }

    // ELEMENT DECRYPTION
    // --------------------------------------------------------------------------------------------

    /// Decrypts the provided encrypted data using this secret key.
    ///
    /// # Errors
    /// Returns an error if decryption fails or if the underlying data was encrypted as bytes
    /// rather than as field elements.
    pub fn decrypt_elements(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<Felt>, EncryptionError> {
        self.decrypt_elements_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts the provided encrypted data, given some associated data, using this secret key.
    ///
    /// # Errors
    /// Returns an error if decryption fails or if the underlying data was encrypted as bytes
    /// rather than as field elements.
    pub fn decrypt_elements_with_associated_data(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        if encrypted_data.data_type != DataType::Elements {
            return Err(EncryptionError::InvalidDataType {
                expected: DataType::Elements,
                found: encrypted_data.data_type,
            });
        }
        self.decrypt_elements_with_associated_data_unchecked(encrypted_data, associated_data)
    }

    /// Decrypts the provided encrypted data, given some associated data, using this secret key.
    fn decrypt_elements_with_associated_data_unchecked(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        if !encrypted_data.ciphertext.len().is_multiple_of(RATE_WIDTH) {
            return Err(EncryptionError::CiphertextLenNotMultipleRate);
        }

        // Initialize as sponge state with key and nonce
        let mut sponge = SpongeState::new(self, &encrypted_data.nonce);

        // Process the associated data
        let padded_associated_data = pad(associated_data);
        padded_associated_data.chunks(RATE_WIDTH).for_each(|chunk| {
            sponge.duplex_overwrite(chunk);
        });

        // Decrypt the data
        let mut plaintext = Vec::with_capacity(encrypted_data.ciphertext.len());
        let mut ciphertext_block_iterator = encrypted_data.ciphertext.chunks_exact(RATE_WIDTH);
        ciphertext_block_iterator.by_ref().for_each(|ciphertext_data_block| {
            let keystream = sponge.duplex_add(&[]);
            for (i, &ciphertext_felt) in ciphertext_data_block.iter().enumerate() {
                let plaintext_felt = ciphertext_felt - keystream[i];
                plaintext.push(plaintext_felt);
            }
            sponge.state[RATE_RANGE].copy_from_slice(ciphertext_data_block);
        });

        // Verify authentication tag
        let computed_tag = sponge.squeeze_tag();
        if computed_tag != encrypted_data.auth_tag {
            return Err(EncryptionError::InvalidAuthTag);
        }

        // Remove padding and return
        unpad(plaintext)
    }

    // BYTE DECRYPTION
    // --------------------------------------------------------------------------------------------

    /// Decrypts the provided encrypted data, as bytes, using this secret key.
    ///
    ///
    /// # Errors
    /// Returns an error if decryption fails or if the underlying data was encrypted as elements
    /// rather than as bytes.
    pub fn decrypt_bytes(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_bytes_with_associated_data(encrypted_data, &[])
    }

    /// Decrypts the provided encrypted data, as bytes, given some associated data using this
    /// secret key.
    ///
    /// # Errors
    /// Returns an error if decryption fails or if the underlying data was encrypted as elements
    /// rather than as bytes.
    pub fn decrypt_bytes_with_associated_data(
        &self,
        encrypted_data: &EncryptedData,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if encrypted_data.data_type != DataType::Bytes {
            return Err(EncryptionError::InvalidDataType {
                expected: DataType::Bytes,
                found: encrypted_data.data_type,
            });
        }

        let ad_felt = bytes_to_elements_with_padding(associated_data);
        let data_felts =
            self.decrypt_elements_with_associated_data_unchecked(encrypted_data, &ad_felt)?;

        match padded_elements_to_bytes(&data_felts) {
            Some(bytes) => Ok(bytes),
            None => Err(EncryptionError::MalformedPadding),
        }
    }
}

impl Distribution<SecretKey> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        let mut res = [ZERO; SECRET_KEY_SIZE];
        let uni_dist =
            Uniform::new(0, Felt::ORDER).expect("should not fail given the size of the field");
        for r in res.iter_mut() {
            let sampled_integer = uni_dist.sample(rng);
            *r = Felt::new_unchecked(sampled_integer);
        }
        SecretKey(res)
    }
}

#[cfg(any(test, feature = "testing"))]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        let mut result = true;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            result &= bool::from(a.as_canonical_u64_ct().ct_eq(&b.as_canonical_u64_ct()));
        }
        result
    }
}

#[cfg(any(test, feature = "testing"))]
impl Eq for SecretKey {}

impl Zeroize for SecretKey {
    /// Securely clears the shared secret from memory.
    ///
    /// # Security
    ///
    /// This implementation follows the same security methodology as the `zeroize` crate to ensure
    /// that sensitive cryptographic material is reliably cleared from memory:
    ///
    /// - **Volatile writes**: Uses `ptr::write_volatile` to prevent dead store elimination and
    ///   other compiler optimizations that might remove the zeroing operation.
    /// - **Memory ordering**: Includes a sequentially consistent compiler fence (`SeqCst`) to
    ///   prevent instruction reordering that could expose the secret data after this function
    ///   returns.
    fn zeroize(&mut self) {
        for element in self.0.iter_mut() {
            unsafe {
                core::ptr::write_volatile(element, ZERO);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// Manual Drop implementation to ensure zeroization on drop.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

// SPONGE STATE
// ================================================================================================

/// Internal sponge state
struct SpongeState {
    state: [Felt; STATE_WIDTH],
}

impl SpongeState {
    /// Creates a new sponge state
    fn new(sk: &SecretKey, nonce: &Nonce) -> Self {
        let mut state = [ZERO; STATE_WIDTH];

        state[RATE_RANGE_FIRST_HALF].copy_from_slice(&sk.0);
        state[RATE_RANGE_SECOND_HALF].copy_from_slice(&nonce.0);

        Self { state }
    }

    /// Duplex interface as described in Algorithm 2 in [1] with `d = 0`
    ///
    ///
    /// [1]: <https://eprint.iacr.org/2023/1668>
    fn duplex_overwrite(&mut self, data: &[Felt]) {
        self.permute();

        // add 1 to the first capacity element
        self.state[CAPACITY_RANGE.start] += ONE;

        // overwrite the rate portion with `data`
        self.state[RATE_RANGE].copy_from_slice(data);
    }

    /// Duplex interface as described in Algorithm 2 in [1] with `d = 1`
    ///
    ///
    /// [1]: <https://eprint.iacr.org/2023/1668>
    fn duplex_add(&mut self, data: &[Felt]) -> [Felt; RATE_WIDTH] {
        self.permute();

        let squeezed_data = self.squeeze_rate();

        for (idx, &element) in data.iter().enumerate() {
            self.state[RATE_START + idx] += element;
        }

        squeezed_data
    }

    /// Squeezes an authentication tag (from RATE0, the first rate word)
    fn squeeze_tag(&mut self) -> AuthTag {
        self.permute();
        AuthTag(
            self.state[RATE_RANGE_FIRST_HALF]
                .try_into()
                .expect("rate first half is exactly AUTH_TAG_SIZE elements"),
        )
    }

    /// Applies the Poseidon2 permutation to the sponge state
    fn permute(&mut self) {
        Poseidon2::apply_permutation(&mut self.state);
    }

    /// Squeeze the rate portion of the state
    fn squeeze_rate(&self) -> [Felt; RATE_WIDTH] {
        self.state[RATE_RANGE]
            .try_into()
            .expect("rate range is exactly RATE_WIDTH elements")
    }
}

// NONCE
// ================================================================================================

/// A 256-bit nonce represented as 4 field elements
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce([Felt; NONCE_SIZE]);

impl Nonce {
    /// Creates a new random nonce using the provided random number generator
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
    }
}

impl From<Word> for Nonce {
    fn from(word: Word) -> Self {
        Nonce(word.into())
    }
}

impl From<[Felt; NONCE_SIZE]> for Nonce {
    fn from(elements: [Felt; NONCE_SIZE]) -> Self {
        Nonce(elements)
    }
}

impl From<Nonce> for Word {
    fn from(nonce: Nonce) -> Self {
        nonce.0.into()
    }
}

impl From<Nonce> for [Felt; NONCE_SIZE] {
    fn from(nonce: Nonce) -> Self {
        nonce.0
    }
}

impl Distribution<Nonce> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Nonce {
        let mut res = [ZERO; NONCE_SIZE];
        let uni_dist =
            Uniform::new(0, Felt::ORDER).expect("should not fail given the size of the field");
        for r in res.iter_mut() {
            let sampled_integer = uni_dist.sample(rng);
            *r = Felt::new_unchecked(sampled_integer);
        }
        Nonce(res)
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let bytes = elements_to_bytes(&self.0);
        target.write_bytes(&bytes);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = read_sensitive_array::<SK_SIZE_BYTES, _>(source)?;

        match bytes_to_elements_exact(bytes.as_slice()) {
            Some(inner) => {
                let inner: [Felt; 4] = inner.try_into().map_err(|_| {
                    DeserializationError::InvalidValue("malformed secret key".to_string())
                })?;
                Ok(Self(inner))
            },
            None => Err(DeserializationError::InvalidValue("malformed secret key".to_string())),
        }
    }
}

impl Serializable for Nonce {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let bytes = elements_to_bytes(&self.0);
        target.write_bytes(&bytes);
    }
}

impl Deserializable for Nonce {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; NONCE_SIZE_BYTES] = source.read_array()?;

        match bytes_to_elements_exact(&bytes) {
            Some(inner) => {
                let inner: [Felt; 4] = inner.try_into().map_err(|_| {
                    DeserializationError::InvalidValue("malformed nonce".to_string())
                })?;
                Ok(Self(inner))
            },
            None => Err(DeserializationError::InvalidValue("malformed nonce".to_string())),
        }
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
        let data_type_value: u8 = source.read_u8()?;
        let data_type = data_type_value.try_into().map_err(|_| {
            DeserializationError::InvalidValue("invalid data type value".to_string())
        })?;

        let ciphertext = Vec::<Felt>::read_from(source)?;
        let nonce: [Felt; NONCE_SIZE] = source.read()?;
        let auth_tag: [Felt; AUTH_TAG_SIZE] = source.read()?;

        Ok(Self {
            ciphertext,
            nonce: Nonce(nonce),
            auth_tag: AuthTag(auth_tag),
            data_type,
        })
    }
}

//  HELPERS
// ================================================================================================

/// Performs padding on either the plaintext or associated data.
///
/// # Padding Scheme
///
/// This AEAD implementation uses an injective padding scheme to ensure that different plaintexts
/// always produce different ciphertexts, preventing ambiguity during decryption.
///
/// ## Data Padding
///
/// Plaintext data is padded using a 10* padding scheme:
///
/// - A padding separator (field element `ONE`) is appended to the message.
/// - The message is then zero-padded to reach the next rate boundary.
/// - **Security guarantee**: `[ONE]` and `[ONE, ZERO]` will produce different ciphertexts because
///   after padding they become `[ONE, ONE, 0, 0, ...]` and `[ONE, ZERO, ONE, 0, ...]` respectively,
///   ensuring injectivity.
///
/// ## Associated Data Padding
///
/// Associated data follows the same injective padding scheme:
///
/// - Padding separator (`ONE`) is appended.
/// - Zero-padded to rate boundary.
/// - **Security guarantee**: Different associated data inputs (like `[ONE]` vs `[ONE, ZERO]`)
///   produce different authentication tags due to the injective padding.
fn pad(data: &[Felt]) -> Vec<Felt> {
    // if data length is a multiple of 8, padding_elements will be 8
    let num_elem_final_block = data.len() % RATE_WIDTH;
    let padding_elements = RATE_WIDTH - num_elem_final_block;

    let mut result = data.to_vec();
    result.extend_from_slice(&PADDING_BLOCK[..padding_elements]);

    result
}

/// Removes the padding from the decoded ciphertext.
fn unpad(mut plaintext: Vec<Felt>) -> Result<Vec<Felt>, EncryptionError> {
    let (num_blocks, remainder) = plaintext.len().div_rem(&RATE_WIDTH);
    assert_eq!(remainder, 0);

    let final_block: &[Felt; RATE_WIDTH] =
        plaintext.last_chunk().ok_or(EncryptionError::MalformedPadding)?;

    let pos = match final_block.iter().rposition(|entry| *entry == ONE) {
        Some(pos) => pos,
        None => return Err(EncryptionError::MalformedPadding),
    };

    plaintext.truncate((num_blocks - 1) * RATE_WIDTH + pos);

    Ok(plaintext)
}

// AEAD SCHEME IMPLEMENTATION
// ================================================================================================

/// Poseidon2-based AEAD scheme implementation
pub struct AeadPoseidon2;

fn read_encrypted_data_strict(ciphertext: &[u8]) -> Result<EncryptedData, EncryptionError> {
    let mut reader = BudgetedReader::new(SliceReader::new(ciphertext), ciphertext.len());
    let encrypted_data =
        EncryptedData::read_from(&mut reader).map_err(|_| EncryptionError::FailedOperation)?;

    if reader.has_more_bytes() {
        return Err(EncryptionError::FailedOperation);
    }

    Ok(encrypted_data)
}

impl AeadScheme for AeadPoseidon2 {
    const KEY_SIZE: usize = SK_SIZE_BYTES;

    type Key = SecretKey;

    fn key_from_bytes(bytes: &[u8]) -> Result<Self::Key, EncryptionError> {
        if bytes.len() != SK_SIZE_BYTES {
            return Err(EncryptionError::FailedOperation);
        }

        SecretKey::read_from_bytes_with_budget(bytes, SK_SIZE_BYTES)
            .map_err(|_| EncryptionError::FailedOperation)
    }

    fn encrypt_bytes<R: rand::CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::with_rng(rng);
        let encrypted_data = key
            .encrypt_bytes_with_nonce(plaintext, associated_data, nonce)
            .map_err(|_| EncryptionError::FailedOperation)?;

        Ok(encrypted_data.to_bytes())
    }

    fn decrypt_bytes_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let encrypted_data = read_encrypted_data_strict(ciphertext)?;

        key.decrypt_bytes_with_associated_data(&encrypted_data, associated_data)
    }

    // OPTIMIZED FELT METHODS
    // --------------------------------------------------------------------------------------------

    fn encrypt_elements<R: rand::CryptoRng>(
        key: &Self::Key,
        rng: &mut R,
        plaintext: &[Felt],
        associated_data: &[Felt],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::with_rng(rng);
        let encrypted_data = key
            .encrypt_elements_with_nonce(plaintext, associated_data, nonce)
            .map_err(|_| EncryptionError::FailedOperation)?;

        Ok(encrypted_data.to_bytes())
    }

    fn decrypt_elements_with_associated_data(
        key: &Self::Key,
        ciphertext: &[u8],
        associated_data: &[Felt],
    ) -> Result<Vec<Felt>, EncryptionError> {
        let encrypted_data = read_encrypted_data_strict(ciphertext)?;

        key.decrypt_elements_with_associated_data(&encrypted_data, associated_data)
    }
}
