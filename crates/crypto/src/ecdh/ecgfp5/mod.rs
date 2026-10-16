//! EcGFp5 Diffie-Hellman key agreement.
//!
//! Public keys use the canonical 40-byte EcGFp5 encoding: five little-endian Goldilocks
//! coefficients. Secret keys are nonzero integers below the prime group order, encoded as
//! 40 little-endian bytes. Identity public keys and noncanonical encodings are rejected.
//!
//! [`SecretKey::diffie_hellman`] computes a shared secret from a [`PublicKey`].
//! [`PublicKey::to_commitment`] returns the public-key commitment used by MASM.
//! [`PublicKey::advise`] prepares private advice for MASM key agreement.
//!
//! [`PreparedPublicKey`] expands a recipient key into paired 16-bit multiplication tables for
//! the generator and recipient. MASM's `agree_preprocessed` authenticates entries supplied through
//! advice against their Merkle commitment. It assumes the issuer generated the tables correctly.
//!
//! Agreement returns raw shared-secret material, not an encryption key. Applications must apply
//! a context-bound KDF and authenticated encryption.
//!
//! Advice generation and VM execution are variable-time and must run in an environment trusted
//! with the ephemeral secret. Keep the advice private, including its Merkle paths. A public proof
//! needs zero-knowledge to hide the private execution witness.
//!
//! # References
//!
//! - [Reference implementation](https://github.com/pornin/ecgfp5/tree/ce059c6d1e1662db437aecbf3db6bb67fe63c716)
//! - [EcGFp5: a Specialized Elliptic Curve](https://eprint.iacr.org/2022/274)

use alloc::vec::Vec;

mod advice;
mod direct;
mod native;
mod tables;

#[cfg(test)]
mod tests;

pub use advice::AgreementAdvice;
use native::{curve::Point, field::GFp5, scalar::Scalar};
use rand::CryptoRng;
pub use tables::PreparedPublicKey;

use crate::{
    Felt, SequentialCommit, Word,
    hash::eidos::{Eidos, domains::ECGFP5_PUBLIC_KEY},
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        read_sensitive_array,
        zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
    },
};

/// A canonical, nonzero EcGFp5 scalar. The owned scalar is erased on drop.
pub struct SecretKey(Zeroizing<Scalar>);

impl SecretKey {
    /// Samples a scalar uniformly from `1..n` using rejection sampling.
    pub fn with_rng<R: CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0; 40]);
        loop {
            rng.fill_bytes(bytes.as_mut());
            // The group order is just below 2^319.
            bytes[39] &= 0x7f;
            if let Ok(key) = Self::from_bytes(&bytes) {
                return key;
            }
        }
    }

    /// Decodes a 40-byte little-endian scalar, rejecting zero and values at least the group order.
    /// The caller retains responsibility for erasing the input bytes.
    pub fn from_bytes(bytes: &[u8; 40]) -> Result<Self, InvalidSecretKey> {
        let (scalar, valid) = Scalar::decode(bytes);
        let scalar = Zeroizing::new(scalar);
        if valid == 0 || scalar.iszero() != 0 {
            return Err(InvalidSecretKey);
        }
        Ok(Self(scalar))
    }

    /// Encodes the scalar. The returned buffer is erased on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 40]> {
        Zeroizing::new(self.0.encode())
    }

    /// Computes the public key using the conventional EcGFp5 generator.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(Point::mulgen(*self.0).encode().encode())
    }

    /// Computes raw shared-secret material with a validated, nonidentity public key.
    pub fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
        SharedSecret((public_key.point() * *self.0).encode().encode())
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.to_bytes().as_ref());
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = read_sensitive_array::<40, _>(source)?;
        Self::from_bytes(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("invalid EcGFp5 secret key".into()))
    }
}

/// A canonical, nonidentity EcGFp5 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 40]);

impl PublicKey {
    /// Returns the domain-separated Eidos commitment to the five-Felt public-key encoding.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Decodes a canonical point, rejecting invalid field coefficients and the identity.
    pub fn from_bytes(bytes: [u8; 40]) -> Result<Self, InvalidPublicKey> {
        let (encoding, canonical) = GFp5::decode(&bytes);
        let (_, valid) = Point::decode(encoding);
        if canonical == 0 || valid == 0 || encoding.iszero() != 0 {
            return Err(InvalidPublicKey);
        }
        Ok(Self(bytes))
    }

    /// Decodes the five coefficients used by the MASM procedure.
    pub fn from_elements(elements: [Felt; 5]) -> Result<Self, InvalidPublicKey> {
        let mut bytes = [0; 40];
        for (chunk, element) in bytes.chunks_exact_mut(8).zip(elements) {
            chunk.copy_from_slice(&element.as_canonical_u64().to_le_bytes());
        }
        Self::from_bytes(bytes)
    }

    /// Returns the canonical 40-byte encoding.
    pub fn to_bytes(self) -> [u8; 40] {
        self.0
    }

    /// Returns the five coefficients in increasing polynomial degree order.
    pub fn to_elements(self) -> [Felt; 5] {
        elements_from_bytes(&self.0)
    }

    fn point(self) -> Point {
        let (encoding, _) = GFp5::decode(&self.0);
        Point::decode(encoding).0
    }
}

impl SequentialCommit for PublicKey {
    type Commitment = Word;

    fn to_commitment(&self) -> Word {
        Eidos::hash_elements_in_domain(&PublicKey::to_elements(*self), ECGFP5_PUBLIC_KEY)
    }

    fn to_elements(&self) -> Vec<Felt> {
        PublicKey::to_elements(*self).to_vec()
    }
}

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::from_bytes(source.read_array()?)
            .map_err(|_| DeserializationError::InvalidValue("invalid EcGFp5 public key".into()))
    }
}

/// Raw DH output, encoded as a canonical EcGFp5 point. The owned bytes are erased on drop.
/// This value must pass through a KDF before use as an encryption key.
pub struct SharedSecret([u8; 40]);

impl SharedSecret {
    /// Returns the VM representation. The caller must protect and erase this copy.
    pub fn to_elements(&self) -> [Felt; 5] {
        elements_from_bytes(&self.0)
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

/// A secret scalar is zero or is not below the group order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid EcGFp5 secret scalar")]
pub struct InvalidSecretKey;

/// A point encoding is invalid, noncanonical, or the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid EcGFp5 public key")]
pub struct InvalidPublicKey;

fn elements_from_bytes(bytes: &[u8; 40]) -> [Felt; 5] {
    core::array::from_fn(|i| {
        Felt::new_unchecked(u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
    })
}
