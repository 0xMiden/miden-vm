//! NTRU-HPS-2048-509 key encapsulation with Eidos hashing.
//!
//! Encapsulation uses the recipient's [`PublicKey`] and fresh randomness to produce a shared
//! secret and a capsule, the KEM ciphertext:
//!
//! ```text
//! Encapsulate(recipient_public_key, fresh_randomness)
//!     -> (capsule, shared_secret)
//!
//! Decapsulate(recipient_private_key, capsule)
//!     -> shared_secret
//! ```
//!
//! The sender sends the capsule to the recipient, who uses its [`SecretKey`] to recover the same
//! secret. That secret supplies key material for encrypting the application message; the capsule
//! is separate from the encrypted message. [`crate::ies::ntru_eidos`] combines these operations.
//!
//! Parameters, sampling, and polynomial encodings follow the
//! [reference implementation](https://github.com/jschanck/ntru/tree/6d96ed3746000b6497392a425712fe483988fc80)
//! and [NTRU specification](https://www.cryptojedi.org/papers/ntrunistr3-20200930.pdf).
//! Eidos replaces the reference hashes, so this is not the standard NTRU ciphersuite.
//!
//! Use [`PublicKey::encapsulate`] for native encapsulation or
//! [`PublicKey::encapsulate_with_advice`] to prepare the same operation for MASM.

use alloc::{boxed::Box, vec::Vec};

use rand::CryptoRng;
use subtle::{Choice, ConditionallySelectable};

use crate::{
    Felt, SequentialCommit, Word,
    hash::eidos::{Eidos, domains::NTRU_HPS509_PUBLIC_KEY},
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        read_sensitive_array, zeroize::Zeroizing,
    },
};

mod advice;
pub(crate) mod framing;
mod native;
pub use advice::EncapsulationAdvice;

use self::framing::felt;

/// Size of the canonical public polynomial encoding.
pub const PUBLIC_KEY_BYTES: usize = native::POLY_BYTES;
/// Size of a capsule in bytes.
pub const CIPHERTEXT_BYTES: usize = native::POLY_BYTES;
/// Size of the secret polynomials and fallback key encoding.
pub const SECRET_KEY_BYTES: usize = native::SECRET_BYTES + 32;
const COIN_BYTES: usize = native::COIN_BYTES;
const N: usize = native::N;

/// The recipient's 699-byte public polynomial encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_BYTES]>);

/// The recipient's secret polynomials and fallback key. Owned secret buffers are erased on drop.
pub struct SecretKey {
    bytes: Box<Zeroizing<[u8; native::SECRET_BYTES]>>,
    fallback: Zeroizing<[u8; 32]>,
    public_key: PublicKey,
}

/// A capsule (KEM ciphertext), distinct from the encrypted application message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext(Box<[u8; CIPHERTEXT_BYTES]>);

/// The four-Felt shared secret returned by encapsulation and decapsulation.
///
/// Use [`crate::ies::ntru_eidos`] to derive a key and nonce for message encryption.
pub struct SharedSecret(framing::SecretDigest);

impl SharedSecret {
    pub(crate) fn as_u64s(&self) -> &[u64; 4] {
        &self.0
    }

    /// Copies the KEM output into a Word for key derivation.
    pub fn to_word(&self) -> Word {
        Word::new(self.0.map(felt))
    }
}

impl SecretKey {
    /// Generates the recipient key pair.
    pub fn with_rng(rng: &mut impl CryptoRng) -> Self {
        let mut coins = Zeroizing::new([0; COIN_BYTES]);
        let mut fallback = Zeroizing::new([0; 32]);
        rng.fill_bytes(coins.as_mut());
        rng.fill_bytes(fallback.as_mut());
        let mut bytes = Box::new(Zeroizing::new([0; native::SECRET_BYTES]));
        let mut public = [0; PUBLIC_KEY_BYTES];
        native::keypair(&coins, &mut public, &mut bytes);
        Self {
            bytes,
            fallback,
            public_key: PublicKey(Box::new(public)),
        }
    }

    /// Decodes the 935-byte secret key and recovers its public key.
    ///
    /// Checks canonical polynomial encodings, the stored inverses, and the recovered
    /// public key's relation to the secret polynomials.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() != SECRET_KEY_BYTES {
            return Err(Error);
        }
        let bytes = Box::new(Zeroizing::new(encoded[..native::SECRET_BYTES].try_into().unwrap()));
        let public = native::restore_public_key(&bytes).ok_or(Error)?;
        Ok(Self {
            bytes,
            fallback: Zeroizing::new(encoded[native::SECRET_BYTES..].try_into().unwrap()),
            public_key: PublicKey(Box::new(public)),
        })
    }

    /// Encodes the three secret polynomials followed by the 32-byte fallback key.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_BYTES]> {
        let mut encoded = Zeroizing::new([0; SECRET_KEY_BYTES]);
        encoded[..native::SECRET_BYTES].copy_from_slice(self.bytes.as_slice());
        encoded[native::SECRET_BYTES..].copy_from_slice(self.fallback.as_ref());
        encoded
    }

    /// Returns the recipient's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Recovers the shared secret from a capsule.
    ///
    /// For an invalid capsule, returns a hash of the secret fallback key and the capsule instead.
    /// This does not expose a separate validity result; the IES layer checks the authentication tag
    /// before returning plaintext.
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> SharedSecret {
        let (recovered, failed) = native::recover(&ciphertext.0, &self.bytes);
        let candidate = framing::secret_bytes(framing::KEM, recovered.as_ref());
        let mut input = Zeroizing::new(Vec::with_capacity(32 + CIPHERTEXT_BYTES));
        input.extend_from_slice(self.fallback.as_ref());
        input.extend_from_slice(ciphertext.0.as_slice());
        let fallback = framing::secret_bytes(framing::FALLBACK, &input);
        let choose_fallback = Choice::from(failed);
        let mut selected = Zeroizing::new([0; 4]);
        for i in 0..4 {
            selected[i] = u64::conditional_select(&candidate[i], &fallback[i], choose_fallback);
        }
        SharedSecret(selected)
    }
}

impl PublicKey {
    /// Decodes a 699-byte public key, rejecting nonzero unused bits in its last byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| Error)?;
        if bytes[PUBLIC_KEY_BYTES - 1] & 0xf0 != 0 {
            return Err(Error);
        }
        Ok(Self(Box::new(bytes)))
    }

    /// Returns the canonical public polynomial encoding.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }

    /// Returns the four-Felt public-key commitment checked by MASM.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Uses fresh randomness to produce a capsule and shared secret.
    pub fn encapsulate(&self, rng: &mut impl CryptoRng) -> (Ciphertext, SharedSecret) {
        let sample = self.sample(rng);
        (sample.ciphertext, sample.secret)
    }

    pub(crate) fn polynomial(&self) -> [u16; 512] {
        let mut h = [0; 512];
        h[..native::N].copy_from_slice(&native::public_polynomial(&self.0));
        h
    }

    pub(crate) fn sample(&self, rng: &mut impl CryptoRng) -> Sample {
        let mut coins = Zeroizing::new([0; COIN_BYTES]);
        rng.fill_bytes(coins.as_mut());
        let sample = native::encapsulate(&self.0, &coins);
        Sample {
            ciphertext: Ciphertext(Box::new(sample.ciphertext)),
            secret: SharedSecret(framing::secret_bytes(framing::KEM, sample.encoded_pair.as_ref())),
            r: sample.r,
            m: sample.m,
        }
    }
}

impl Ciphertext {
    /// Accepts every fixed-size string, including invalid capsules.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Box::new(bytes.try_into().map_err(|_| Error)?)))
    }

    /// Returns the capsule bytes.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.0
    }
}

pub(crate) struct Sample {
    pub ciphertext: Ciphertext,
    pub secret: SharedSecret,
    pub r: Zeroizing<[u16; N]>,
    pub m: Zeroizing<[u16; N]>,
}

pub(crate) fn lift(trit: u16) -> u64 {
    if trit == 2 { 2047 } else { trit.into() }
}

#[cfg(test)]
mod tests;

impl SequentialCommit for PublicKey {
    type Commitment = Word;
    fn to_elements(&self) -> Vec<Felt> {
        self.polynomial().into_iter().map(Felt::from).collect()
    }
    fn to_commitment(&self) -> Word {
        Eidos::hash_elements_in_domain(&self.polynomial().map(Felt::from), NTRU_HPS509_PUBLIC_KEY)
    }
}

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.as_bytes());
    }
}
impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::from_bytes(&source.read_array::<PUBLIC_KEY_BYTES>()?)
            .map_err(|_| DeserializationError::InvalidValue("invalid NTRU public key".into()))
    }
}
impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.to_bytes().as_ref());
    }
}
impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = read_sensitive_array::<SECRET_KEY_BYTES, _>(source)?;
        Self::from_bytes(bytes.as_ref())
            .map_err(|_| DeserializationError::InvalidValue("invalid NTRU secret key".into()))
    }
}

/// A key or capsule encoding has the wrong size or violates the key's encoding rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid NTRU encoding")]
pub struct Error;
