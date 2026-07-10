//! ECDH (Elliptic Curve Diffie-Hellman) key agreement implementation over k256
//! i.e., secp256k1 curve.
//!
//! Note that the intended use is in the context of a one-way, sender initiated key agreement
//! scenario. Namely, when the sender knows the (static) public key of the receiver and it
//! uses that, together with an ephemeral secret key that it generates, to derive a shared
//! secret.
//!
//! This shared secret will then be used to encrypt some message (using for example a key
//! derivation function).
//!
//! The public key associated with the ephemeral secret key will be sent alongside the encrypted
//! message.

use alloc::{string::ToString, vec::Vec};

use hkdf::Hkdf;
use k256::{
    AffinePoint,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::CryptoRng;
use sha2::Sha256;

use crate::{
    dsa::ecdsa_k256_keccak::{KeyExchangeKey, PUBLIC_KEY_BYTES, PublicKey},
    ecdh::KeyAgreementScheme,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
};
// SHARED SECRET
// ================================================================================================

/// A shared secret computed using the ECDH (Elliptic Curve Diffie-Hellman) key agreement.
///
/// This type implements `ZeroizeOnDrop` because the inner `k256::ecdh::SharedSecret`
/// implements it, ensuring the shared secret is securely wiped from memory when dropped.
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    pub(crate) fn new(inner: k256::ecdh::SharedSecret) -> SharedSecret {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(inner.raw_secret_bytes());
        Self { bytes }
    }

    /// Returns a HKDF (HMAC-based Extract-and-Expand Key Derivation Function) that can be used
    /// to extract entropy from the shared secret.
    ///
    /// This basically converts a shared secret into uniformly random values that are appropriate
    /// for use as key material.
    pub fn extract(&self, salt: Option<&[u8]>) -> Hkdf<Sha256> {
        Hkdf::new(salt, &self.bytes)
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

// Safe to derive ZeroizeOnDrop because we implement Zeroize above
impl ZeroizeOnDrop for SharedSecret {}

// EPHEMERAL SECRET KEY
// ================================================================================================

/// Ephemeral secret key for ECDH key agreement over secp256k1 curve.
///
/// This type implements `ZeroizeOnDrop` because the inner `k256::ecdh::EphemeralSecret`
/// implements it, ensuring the secret key material is securely wiped from memory when dropped.
pub struct EphemeralSecretKey {
    inner: k256::ecdh::EphemeralSecret,
}

impl EphemeralSecretKey {
    /// Generates a new random ephemeral secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();

        Self::with_rng(&mut rng)
    }

    /// Generates a new ephemeral secret key using the provided random number generator.
    pub fn with_rng<R: CryptoRng>(rng: &mut R) -> Self {
        let sk_e = k256::ecdh::EphemeralSecret::generate_from_rng(rng);
        Self { inner: sk_e }
    }

    /// Gets the corresponding ephemeral public key for this ephemeral secret key.
    pub fn public_key(&self) -> EphemeralPublicKey {
        let pk = self.inner.public_key();
        EphemeralPublicKey { inner: pk }
    }

    /// Computes a Diffie-Hellman shared secret from an ephemeral secret key and the (static) public
    /// key of the other party.
    pub fn diffie_hellman(&self, pk_other: PublicKey) -> SharedSecret {
        let shared_secret_inner = self.inner.diffie_hellman(&pk_other.inner.into());

        SharedSecret::new(shared_secret_inner)
    }
}

impl ZeroizeOnDrop for EphemeralSecretKey {}

// EPHEMERAL PUBLIC KEY
// ================================================================================================

/// Ephemeral public key for ECDH key agreement over secp256k1 curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    pub(crate) inner: k256::PublicKey,
}

impl EphemeralPublicKey {
    /// Returns a reference to this ephemeral public key as an elliptic curve point in affine
    /// coordinates.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }
}

impl Serializable for EphemeralPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Compressed format
        let encoded = self.inner.to_sec1_point(true);

        target.write_bytes(encoded.as_bytes());
    }
}

impl Deserializable for EphemeralPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; PUBLIC_KEY_BYTES] = source.read_array()?;

        let inner = k256::PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| DeserializationError::InvalidValue("Invalid public key".to_string()))?;

        Ok(Self { inner })
    }
}

// KEY AGREEMENT TRAIT IMPLEMENTATION
// ================================================================================================

pub struct K256;

impl KeyAgreementScheme for K256 {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;

    type SecretKey = KeyExchangeKey;
    type PublicKey = PublicKey;

    type SharedSecret = SharedSecret;

    fn generate_ephemeral_keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> (Self::EphemeralSecretKey, Self::EphemeralPublicKey) {
        let sk = EphemeralSecretKey::with_rng(rng);
        let pk = sk.public_key();

        (sk, pk)
    }

    fn exchange_ephemeral_static(
        ephemeral_sk: Self::EphemeralSecretKey,
        static_pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, super::KeyAgreementError> {
        Ok(ephemeral_sk.diffie_hellman(static_pk.clone()))
    }

    fn exchange_static_ephemeral(
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, super::KeyAgreementError> {
        Ok(static_sk.get_shared_secret(ephemeral_pk.clone()))
    }

    fn extract_key_material(
        shared_secret: &Self::SharedSecret,
        length: usize,
        info: &[u8],
    ) -> Result<Vec<u8>, super::KeyAgreementError> {
        super::extract_key_material(shared_secret.as_ref(), None, length, info)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use super::{EphemeralPublicKey, EphemeralSecretKey};
    use crate::{
        dsa::ecdsa_k256_keccak::KeyExchangeKey,
        rand::test_utils::seeded_rng,
        utils::{Deserializable, Serializable},
    };

    #[test]
    fn key_agreement() {
        let mut rng = seeded_rng([0u8; 32]);

        // 1. Generate the static key-pair for Alice
        let sk = KeyExchangeKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // 2. Generate the ephemeral key-pair for Bob
        let sk_e = EphemeralSecretKey::with_rng(&mut rng);
        let pk_e = sk_e.public_key();

        // 3. Bob computes the shared secret key (Bob will send pk_e with the encrypted note to
        //    Alice)
        let shared_secret_key_1 = sk_e.diffie_hellman(pk);

        // 4. Alice uses its secret key and the ephemeral public key sent with the encrypted note by
        //    Bob in order to create the shared secret key. This shared secret key will be used to
        //    decrypt the encrypted note
        let shared_secret_key_2 = sk.get_shared_secret(pk_e);

        // Check that the computed shared secret keys are equal
        assert_eq!(shared_secret_key_1.as_ref(), shared_secret_key_2.as_ref());
    }

    #[test]
    fn test_serialization_round_trip() {
        let mut rng = seeded_rng([1u8; 32]);

        let sk_e = EphemeralSecretKey::with_rng(&mut rng);
        let pk_e = sk_e.public_key();

        let pk_e_bytes = pk_e.to_bytes();
        let pk_e_serialized = EphemeralPublicKey::read_from_bytes(&pk_e_bytes)
            .expect("failed to desrialize ephemeral public key");
        assert_eq!(pk_e_serialized, pk_e);
    }
}
