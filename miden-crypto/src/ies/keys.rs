use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, RngCore};

use super::{IesError, IesScheme, crypto_box::CryptoBox, message::SealedMessage};
use crate::{
    Felt,
    aead::{aead_poseidon2::AeadPoseidon2, xchacha::XChaCha},
    dsa::{
        ecdsa_k256_keccak::PUBLIC_KEY_BYTES as K256_PUBLIC_KEY_BYTES,
        eddsa_25519_sha512::PUBLIC_KEY_BYTES as X25519_PUBLIC_KEY_BYTES,
    },
    ecdh::{KeyAgreementScheme, k256::K256, x25519::X25519},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// TYPE ALIASES
// ================================================================================================

/// Instantiation of sealed box using K256 + XChaCha20Poly1305
type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;
/// Instantiation of sealed box using X25519 + XChaCha20Poly1305
type X25519XChaCha20Poly1305 = CryptoBox<X25519, XChaCha>;
/// Instantiation of sealed box using K256 + AeadPoseidon2
type K256AeadPoseidon2 = CryptoBox<K256, AeadPoseidon2>;
/// Instantiation of sealed box using X25519 + AeadPoseidon2
type X25519AeadPoseidon2 = CryptoBox<X25519, AeadPoseidon2>;

// HELPER MACROS
// ================================================================================================

/// Generates seal_bytes_with_associated_data method implementation
macro_rules! impl_seal_bytes_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seals the provided plaintext (represented as bytes) and associated data with this
        /// sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
        pub fn seal_bytes_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<SealedMessage, IesError> {
            match self {
                $(
                    $variant(key) => {
                        let scheme = self.scheme();
                        let (ciphertext, ephemeral) = <$crypto_box>::seal_bytes_with_associated_data(
                            rng,
                            key,
                            scheme,
                            plaintext,
                            associated_data,
                        )?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates seal_elements_with_associated_data method implementation
macro_rules! impl_seal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seals the provided plaintext (represented as filed elements) and associated data with
        /// this sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
        pub fn seal_elements_with_associated_data<R: CryptoRng + RngCore>(
            &self,
            rng: &mut R,
            plaintext: &[Felt],
            associated_data: &[Felt],
        ) -> Result<SealedMessage, IesError> {
            match self {
                $(
                    $variant(key) => {
                        let scheme = self.scheme();
                        let (ciphertext, ephemeral) = <$crypto_box>::seal_elements_with_associated_data(
                            rng,
                            key,
                            scheme,
                            plaintext,
                            associated_data,
                        )?;

                        Ok(SealedMessage {
                            ephemeral_key: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Generates unseal_bytes_with_associated_data method implementation
macro_rules! impl_unseal_bytes_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Unseals the provided message using this unsealing key and returns the plaintext as bytes.
        ///
        /// # Errors
        /// Returns an error if:
        /// - The message was not sealed as bytes (i.e., if it was sealed using `seal_elements()`
        ///   or `seal_elements_with_associated_data()`)
        /// - The scheme used to seal the message does not match this unsealing key's scheme
        /// - Decryption or authentication fails
        pub fn unseal_bytes_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[u8],
        ) -> Result<Vec<u8>, IesError> {
            // Check scheme compatibility using constant-time comparison
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.ephemeral_key.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { ephemeral_key, ciphertext } = sealed_message;

            match (self, ephemeral_key) {
                $(
                    ($variant(key), $ephemeral_variant(ephemeral)) => {
                        <$crypto_box>::unseal_bytes_with_associated_data(
                            key,
                            &ephemeral,
                            self.scheme(),
                            &ciphertext,
                            associated_data,
                        )
                    }
                )*
                _ => Err(IesError::SchemeMismatch),
            }
        }
    };
}

/// Generates unseal_elements_with_associated_data method implementation
macro_rules! impl_unseal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Unseals the provided message using this unsealing key and returns the plaintext as field elements.
        ///
        /// # Errors
        /// Returns an error if:
        /// - The message was not sealed as elements (i.e., if it was sealed using `seal_bytes()`
        ///   or `seal_bytes_with_associated_data()`)
        /// - The scheme used to seal the message does not match this unsealing key's scheme
        /// - Decryption or authentication fails
        pub fn unseal_elements_with_associated_data(
            &self,
            sealed_message: SealedMessage,
            associated_data: &[Felt],
        ) -> Result<Vec<Felt>, IesError> {
            // Check scheme compatibility
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.ephemeral_key.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { ephemeral_key, ciphertext } = sealed_message;

            match (self, ephemeral_key) {
                $(
                    ($variant(key), $ephemeral_variant(ephemeral)) => {
                        <$crypto_box>::unseal_elements_with_associated_data(
                            key,
                            &ephemeral,
                            self.scheme(),
                            &ciphertext,
                            associated_data,
                        )
                    }
                )*
                _ => Err(IesError::SchemeMismatch),
            }
        }
    };
}

// SEALING KEY
// ================================================================================================

/// Public key for sealing messages to a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519_sha512::PublicKey),
    K256AeadPoseidon2(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519AeadPoseidon2(crate::dsa::eddsa_25519_sha512::PublicKey),
}

impl SealingKey {
    /// Returns scheme identifier for this sealing key.
    pub fn scheme(&self) -> IesScheme {
        match self {
            SealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            SealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            SealingKey::K256AeadPoseidon2(_) => IesScheme::K256AeadPoseidon2,
            SealingKey::X25519AeadPoseidon2(_) => IesScheme::X25519AeadPoseidon2,
        }
    }

    /// Seals the provided plaintext (represented as bytes) with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
    pub fn seal_bytes<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<SealedMessage, IesError> {
        self.seal_bytes_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_bytes_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadPoseidon2 => K256AeadPoseidon2, EphemeralPublicKey::K256AeadPoseidon2;
        SealingKey::X25519AeadPoseidon2 => X25519AeadPoseidon2, EphemeralPublicKey::X25519AeadPoseidon2;
    }

    /// Seals the provided plaintext (represented as filed elements) with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
    pub fn seal_elements<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        plaintext: &[Felt],
    ) -> Result<SealedMessage, IesError> {
        self.seal_elements_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_elements_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        SealingKey::K256AeadPoseidon2 => K256AeadPoseidon2, EphemeralPublicKey::K256AeadPoseidon2;
        SealingKey::X25519AeadPoseidon2 => X25519AeadPoseidon2, EphemeralPublicKey::X25519AeadPoseidon2;
    }
}

impl fmt::Display for SealingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} sealing key", self.scheme())
    }
}

impl Serializable for SealingKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.scheme().into());

        match self {
            SealingKey::K256XChaCha20Poly1305(key) => key.write_into(target),
            SealingKey::X25519XChaCha20Poly1305(key) => key.write_into(target),
            SealingKey::K256AeadPoseidon2(key) => key.write_into(target),
            SealingKey::X25519AeadPoseidon2(key) => key.write_into(target),
        }
    }
}

impl Deserializable for SealingKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = IesScheme::try_from(source.read_u8()?)
            .map_err(|_| DeserializationError::InvalidValue("Unsupported IES scheme".into()))?;

        match scheme {
            IesScheme::K256XChaCha20Poly1305 => {
                let key = crate::dsa::ecdsa_k256_keccak::PublicKey::read_from(source)?;
                Ok(SealingKey::K256XChaCha20Poly1305(key))
            },
            IesScheme::X25519XChaCha20Poly1305 => {
                let key = crate::dsa::eddsa_25519_sha512::PublicKey::read_from(source)?;
                Ok(SealingKey::X25519XChaCha20Poly1305(key))
            },
            IesScheme::K256AeadPoseidon2 => {
                let key = crate::dsa::ecdsa_k256_keccak::PublicKey::read_from(source)?;
                Ok(SealingKey::K256AeadPoseidon2(key))
            },
            IesScheme::X25519AeadPoseidon2 => {
                let key = crate::dsa::eddsa_25519_sha512::PublicKey::read_from(source)?;
                Ok(SealingKey::X25519AeadPoseidon2(key))
            },
        }
    }
}

// UNSEALING KEY
// ================================================================================================

/// Secret key for unsealing messages.
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::KeyExchangeKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519_sha512::KeyExchangeKey),
    K256AeadPoseidon2(crate::dsa::ecdsa_k256_keccak::KeyExchangeKey),
    X25519AeadPoseidon2(crate::dsa::eddsa_25519_sha512::KeyExchangeKey),
}

impl UnsealingKey {
    /// Returns scheme identifier for this unsealing key.
    pub fn scheme(&self) -> IesScheme {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            UnsealingKey::K256AeadPoseidon2(_) => IesScheme::K256AeadPoseidon2,
            UnsealingKey::X25519AeadPoseidon2(_) => IesScheme::X25519AeadPoseidon2,
        }
    }

    /// Returns scheme name for this unsealing key.
    pub fn scheme_name(&self) -> &'static str {
        self.scheme().name()
    }

    /// Unseals the provided message using this unsealing key.
    ///
    /// The message must have been sealed as bytes (i.e., using `seal_bytes()` or
    /// `seal_bytes_with_associated_data()` method), otherwise an error will be returned.
    pub fn unseal_bytes(&self, sealed_message: SealedMessage) -> Result<Vec<u8>, IesError> {
        self.unseal_bytes_with_associated_data(sealed_message, &[])
    }

    impl_unseal_bytes_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadPoseidon2 => K256AeadPoseidon2, EphemeralPublicKey::K256AeadPoseidon2;
        UnsealingKey::X25519AeadPoseidon2 => X25519AeadPoseidon2, EphemeralPublicKey::X25519AeadPoseidon2;
    }

    /// Unseals the provided message using this unsealing key.
    ///
    /// The message must have been sealed as elements (i.e., using `seal_elements()` or
    /// `seal_elements_with_associated_data()` method), otherwise an error will be returned.
    pub fn unseal_elements(&self, sealed_message: SealedMessage) -> Result<Vec<Felt>, IesError> {
        self.unseal_elements_with_associated_data(sealed_message, &[])
    }

    impl_unseal_elements_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, EphemeralPublicKey::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, EphemeralPublicKey::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadPoseidon2 => K256AeadPoseidon2, EphemeralPublicKey::K256AeadPoseidon2;
        UnsealingKey::X25519AeadPoseidon2 => X25519AeadPoseidon2, EphemeralPublicKey::X25519AeadPoseidon2;
    }
}

impl fmt::Display for UnsealingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} unsealing key", self.scheme())
    }
}

impl Serializable for UnsealingKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.scheme().into());

        match self {
            UnsealingKey::K256XChaCha20Poly1305(key) => key.write_into(target),
            UnsealingKey::X25519XChaCha20Poly1305(key) => key.write_into(target),
            UnsealingKey::K256AeadPoseidon2(key) => key.write_into(target),
            UnsealingKey::X25519AeadPoseidon2(key) => key.write_into(target),
        }
    }
}

impl Deserializable for UnsealingKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = IesScheme::try_from(source.read_u8()?)
            .map_err(|_| DeserializationError::InvalidValue("Unsupported IES scheme".into()))?;

        match scheme {
            IesScheme::K256XChaCha20Poly1305 => {
                let key = crate::dsa::ecdsa_k256_keccak::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::K256XChaCha20Poly1305(key))
            },
            IesScheme::X25519XChaCha20Poly1305 => {
                let key = crate::dsa::eddsa_25519_sha512::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::X25519XChaCha20Poly1305(key))
            },
            IesScheme::K256AeadPoseidon2 => {
                let key = crate::dsa::ecdsa_k256_keccak::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::K256AeadPoseidon2(key))
            },
            IesScheme::X25519AeadPoseidon2 => {
                let key = crate::dsa::eddsa_25519_sha512::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::X25519AeadPoseidon2(key))
            },
        }
    }
}

// EPHEMERAL PUBLIC KEY
// ================================================================================================

/// Ephemeral public key, part of sealed messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EphemeralPublicKey {
    K256XChaCha20Poly1305(crate::ecdh::k256::EphemeralPublicKey),
    X25519XChaCha20Poly1305(crate::ecdh::x25519::EphemeralPublicKey),
    K256AeadPoseidon2(crate::ecdh::k256::EphemeralPublicKey),
    X25519AeadPoseidon2(crate::ecdh::x25519::EphemeralPublicKey),
}

impl EphemeralPublicKey {
    /// Get scheme identifier for this ephemeral key
    pub fn scheme(&self) -> IesScheme {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            EphemeralPublicKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            EphemeralPublicKey::K256AeadPoseidon2(_) => IesScheme::K256AeadPoseidon2,
            EphemeralPublicKey::X25519AeadPoseidon2(_) => IesScheme::X25519AeadPoseidon2,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EphemeralPublicKey::K256XChaCha20Poly1305(key) => key.to_bytes(),
            EphemeralPublicKey::X25519XChaCha20Poly1305(key) => key.to_bytes(),
            EphemeralPublicKey::K256AeadPoseidon2(key) => key.to_bytes(),
            EphemeralPublicKey::X25519AeadPoseidon2(key) => key.to_bytes(),
        }
    }

    /// Deserialize from bytes with explicit scheme
    pub fn from_bytes(scheme: IesScheme, bytes: &[u8]) -> Result<Self, IesError> {
        let expected_len = match scheme {
            IesScheme::K256XChaCha20Poly1305 | IesScheme::K256AeadPoseidon2 => {
                K256_PUBLIC_KEY_BYTES
            },
            IesScheme::X25519XChaCha20Poly1305 | IesScheme::X25519AeadPoseidon2 => {
                X25519_PUBLIC_KEY_BYTES
            },
        };

        if bytes.len() != expected_len {
            return Err(IesError::EphemeralPublicKeyDeserializationFailed);
        }

        match scheme {
            IesScheme::K256XChaCha20Poly1305 => {
                let key =
                    <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::K256XChaCha20Poly1305(key))
            },
            IesScheme::K256AeadPoseidon2 => {
                let key =
                    <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::K256AeadPoseidon2(key))
            },
            IesScheme::X25519XChaCha20Poly1305 => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::X25519XChaCha20Poly1305(key))
            },
            IesScheme::X25519AeadPoseidon2 => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(EphemeralPublicKey::X25519AeadPoseidon2(key))
            },
        }
    }
}
