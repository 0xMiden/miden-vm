//! X25519 (Elliptic Curve Diffie-Hellman) key agreement implementation using
//! Curve25519.
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

use alloc::vec::Vec;

use hkdf::Hkdf;
use rand::CryptoRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    dsa::eddsa_25519_sha512::{KeyExchangeKey, PublicKey},
    ecdh::KeyAgreementScheme,
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
};
// SHARED SECRETE
// ================================================================================================

/// A shared secret computed using the X25519 (Elliptic Curve Diffie-Hellman) key agreement.
///
/// This type implements `ZeroizeOnDrop` because the inner `x25519_dalek::SharedSecret`
/// implements it, ensuring the shared secret is securely wiped from memory when dropped.
pub struct SharedSecret {
    bytes: [u8; 32],
}
impl SharedSecret {
    pub(crate) fn new(inner: x25519_dalek::SharedSecret) -> SharedSecret {
        Self { bytes: inner.to_bytes() }
    }

    /// Returns a HKDF that can be used to derive uniform keys from the shared secret.
    pub fn extract(&self, salt: Option<&[u8]>) -> Hkdf<Sha256> {
        Hkdf::new(salt, &self.bytes)
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// EPHEMERAL SECRET KEY
// ================================================================================================

/// Ephemeral secret key for X25519 key agreement.
///
/// This type implements `ZeroizeOnDrop` because the inner `x25519_dalek::EphemeralSecret`
/// implements it, ensuring the secret key material is securely wiped from memory when dropped.
pub struct EphemeralSecretKey {
    inner: x25519_dalek::EphemeralSecret,
}

impl ZeroizeOnDrop for EphemeralSecretKey {}

impl EphemeralSecretKey {
    /// Generates a new random ephemeral secret key using the OS random number generator.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rng();

        Self::with_rng(&mut rng)
    }

    /// Generates a new random ephemeral secret key using the provided RNG.
    pub fn with_rng<R: CryptoRng>(rng: &mut R) -> Self {
        let sk = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        Self { inner: sk }
    }

    /// Returns the corresponding ephemeral public key.
    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey {
            inner: x25519_dalek::PublicKey::from(&self.inner),
        }
    }

    /// Computes a Diffie-Hellman shared secret from this ephemeral secret key and the other party's
    /// static public key.
    pub fn diffie_hellman(self, pk_other: &PublicKey) -> SharedSecret {
        let shared = self.inner.diffie_hellman(&pk_other.to_x25519());
        SharedSecret::new(shared)
    }
}

// EPHEMERAL PUBLIC KEY
// ================================================================================================

/// Ephemeral public key for X25519 agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralPublicKey {
    pub(crate) inner: x25519_dalek::PublicKey,
}

impl Serializable for EphemeralPublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(self.inner.as_bytes());
    }
}

impl Deserializable for EphemeralPublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes: [u8; 32] = source.read_array()?;
        // Reject twist points and low-order points. We intentionally avoid the more expensive
        // torsion-free check; small-order rejection mitigates the most dangerous malleability
        // issues, even though it does not guarantee torsion-freeness.
        let mont = curve25519_dalek::montgomery::MontgomeryPoint(bytes);
        let edwards = mont.to_edwards(0).ok_or_else(|| {
            DeserializationError::InvalidValue("Invalid X25519 public key".into())
        })?;
        if edwards.is_small_order() {
            return Err(DeserializationError::InvalidValue("Invalid X25519 public key".into()));
        }

        Ok(Self {
            inner: x25519_dalek::PublicKey::from(bytes),
        })
    }
}

// KEY AGREEMENT TRAIT IMPLEMENTATION
// ================================================================================================

pub struct X25519;

impl KeyAgreementScheme for X25519 {
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
        let shared = ephemeral_sk.diffie_hellman(static_pk);
        if is_all_zero(shared.as_ref()) {
            return Err(super::KeyAgreementError::InvalidSharedSecret);
        }
        Ok(shared)
    }

    fn exchange_static_ephemeral(
        static_sk: &Self::SecretKey,
        ephemeral_pk: &Self::EphemeralPublicKey,
    ) -> Result<Self::SharedSecret, super::KeyAgreementError> {
        let shared = static_sk.get_shared_secret(ephemeral_pk.clone());
        if is_all_zero(shared.as_ref()) {
            return Err(super::KeyAgreementError::InvalidSharedSecret);
        }
        Ok(shared)
    }

    fn extract_key_material(
        shared_secret: &Self::SharedSecret,
        length: usize,
        info: &[u8],
    ) -> Result<Vec<u8>, super::KeyAgreementError> {
        super::extract_key_material(shared_secret.as_ref(), None, length, info)
    }
}

fn is_all_zero(bytes: &[u8]) -> bool {
    // Empty input is treated as invalid caller input rather than "all zero".
    if bytes.is_empty() {
        return false;
    }
    let acc = bytes.iter().fold(0u8, |acc, &byte| acc | byte);
    acc.ct_eq(&0u8).into()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::EIGHT_TORSION, montgomery::MontgomeryPoint};

    use super::*;
    use crate::{
        dsa::eddsa_25519_sha512::KeyExchangeKey, ecdh::KeyAgreementError,
        rand::test_utils::seeded_rng, utils::Deserializable,
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
        let shared_secret_key_1 = sk_e.diffie_hellman(&pk);

        // 4. Alice uses its secret key and the ephemeral public key sent with the encrypted note by
        //    Bob in order to create the shared secret key. This shared secret key will be used to
        //    decrypt the encrypted note
        let shared_secret_key_2 = sk.get_shared_secret(pk_e);

        // Check that the computed shared secret keys are equal
        assert_eq!(shared_secret_key_1.as_ref(), shared_secret_key_2.as_ref());
    }

    #[test]
    fn ephemeral_public_key_rejects_small_order() {
        let bytes = EIGHT_TORSION[1].to_montgomery().to_bytes();
        let result = EphemeralPublicKey::read_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn ephemeral_public_key_rejects_twist_point() {
        let bytes = find_twist_point_bytes();
        let result = EphemeralPublicKey::read_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn exchange_static_ephemeral_rejects_zero_shared_secret() {
        let mut rng = seeded_rng([0u8; 32]);
        let static_sk = KeyExchangeKey::with_rng(&mut rng);

        let low_order_bytes = EIGHT_TORSION[0].to_montgomery().to_bytes();
        let low_order_pk = EphemeralPublicKey {
            inner: x25519_dalek::PublicKey::from(low_order_bytes),
        };

        let result = X25519::exchange_static_ephemeral(&static_sk, &low_order_pk);
        assert!(matches!(result, Err(KeyAgreementError::InvalidSharedSecret)));
    }

    #[test]
    fn is_all_zero_accepts_arbitrary_lengths() {
        assert!(!is_all_zero(&[]));
        assert!(is_all_zero(&[0u8; 16]));
        assert!(!is_all_zero(&[0u8, 1u8, 0u8, 0u8]));
    }

    fn find_twist_point_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0u16..=u16::MAX {
            bytes[0] = (i & 0xff) as u8;
            bytes[1] = (i >> 8) as u8;
            if MontgomeryPoint(bytes).to_edwards(0).is_none() {
                return bytes;
            }
        }
        panic!("no twist point found in 16-bit search space");
    }
}
