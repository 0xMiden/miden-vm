use alloc::vec::Vec;
use core::fmt;

use rand::CryptoRng;

use super::{
    IesError, IesScheme, crypto_box::CryptoBox, ecgfp5_eidos::adapter, message::SealedMessage,
    ntru_eidos::adapter as ntru_adapter,
};
use crate::{
    Felt,
    aead::{aead_eidos::AeadEidos, xchacha::XChaCha},
    dsa::{
        ecdsa_k256_keccak::PUBLIC_KEY_BYTES as K256_PUBLIC_KEY_BYTES,
        eddsa_25519_sha512::PUBLIC_KEY_BYTES as X25519_PUBLIC_KEY_BYTES,
    },
    ecdh::{KeyAgreementScheme, ecgfp5, k256::K256, x25519::X25519},
    kem::ntru_hps509 as ntru,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// TYPE ALIASES
// ================================================================================================

/// Sealed-box construction using K256 and XChaCha20-Poly1305.
type K256XChaCha20Poly1305 = CryptoBox<K256, XChaCha>;
/// Sealed-box construction using X25519 and XChaCha20-Poly1305.
type X25519XChaCha20Poly1305 = CryptoBox<X25519, XChaCha>;
/// Sealed-box construction using K256 and Eidos authenticated encryption.
type K256AeadEidos = CryptoBox<K256, AeadEidos>;
/// Sealed-box construction using X25519 and Eidos authenticated encryption.
type X25519AeadEidos = CryptoBox<X25519, AeadEidos>;

// HELPER MACROS
// ================================================================================================

// EcGFp5 and NTRU use dedicated Eidos key schedules; the other schemes use CryptoBox.

/// Implements byte sealing for each supported scheme.
macro_rules! impl_seal_bytes_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seals the provided plaintext (represented as bytes) and associated data with this
        /// sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
        pub fn seal_bytes_with_associated_data<R: CryptoRng>(
            &self,
            rng: &mut R,
            plaintext: &[u8],
            associated_data: &[u8],
        ) -> Result<SealedMessage, IesError> {
            match self {
                SealingKey::Ecgfp5Eidos(key) => {
                    adapter::seal_bytes(key, rng, plaintext, associated_data)
                },
                SealingKey::NtruEidos(key) => {
                    ntru_adapter::seal_bytes(key, rng, plaintext, associated_data)
                },
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
                            encapsulation: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Implements field-element sealing for each supported scheme.
macro_rules! impl_seal_elements_with_associated_data {
    ($($variant:path => $crypto_box:ty, $ephemeral_variant:path;)*) => {
        /// Seals the provided field elements and associated data with
        /// this sealing key.
        ///
        /// The returned message can be unsealed with the [UnsealingKey] associated with this
        /// sealing key.
        pub fn seal_elements_with_associated_data<R: CryptoRng>(
            &self,
            rng: &mut R,
            plaintext: &[Felt],
            associated_data: &[Felt],
        ) -> Result<SealedMessage, IesError> {
            match self {
                SealingKey::Ecgfp5Eidos(key) => {
                    adapter::seal_elements(key, rng, plaintext, associated_data)
                },
                SealingKey::NtruEidos(key) => {
                    ntru_adapter::seal_elements(key, rng, plaintext, associated_data)
                },
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
                            encapsulation: $ephemeral_variant(ephemeral),
                            ciphertext,
                        })
                    }
                )*
            }
        }
    };
}

/// Implements byte unsealing for each supported scheme.
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
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.encapsulation.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { encapsulation, ciphertext } = sealed_message;

            match (self, encapsulation) {
                (UnsealingKey::Ecgfp5Eidos(key), PublicEncapsulation::Ecgfp5Eidos(ephemeral)) => {
                    adapter::open_bytes(key, ephemeral, &ciphertext, associated_data)
                },
                (UnsealingKey::NtruEidos(key), PublicEncapsulation::NtruEidos(encapsulation)) => {
                    ntru_adapter::open_bytes(key, encapsulation, &ciphertext, associated_data)
                },
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

/// Implements field-element unsealing for each supported scheme.
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
            let self_algo = self.scheme() as u8;
            let msg_algo = sealed_message.encapsulation.scheme() as u8;

            let compatible = self_algo == msg_algo;
            if !compatible {
                return Err(IesError::SchemeMismatch);
            }

            let SealedMessage { encapsulation, ciphertext } = sealed_message;

            match (self, encapsulation) {
                (UnsealingKey::Ecgfp5Eidos(key), PublicEncapsulation::Ecgfp5Eidos(ephemeral)) => {
                    adapter::open_elements(key, ephemeral, &ciphertext, associated_data)
                },
                (UnsealingKey::NtruEidos(key), PublicEncapsulation::NtruEidos(encapsulation)) => {
                    ntru_adapter::open_elements(key, encapsulation, &ciphertext, associated_data)
                },
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub enum SealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519_sha512::PublicKey),
    K256AeadEidos(crate::dsa::ecdsa_k256_keccak::PublicKey),
    X25519AeadEidos(crate::dsa::eddsa_25519_sha512::PublicKey),
    Ecgfp5Eidos(ecgfp5::PublicKey),
    NtruEidos(ntru::PublicKey),
}

impl SealingKey {
    /// Returns scheme identifier for this sealing key.
    pub fn scheme(&self) -> IesScheme {
        match self {
            SealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            SealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            SealingKey::K256AeadEidos(_) => IesScheme::K256AeadEidos,
            SealingKey::X25519AeadEidos(_) => IesScheme::X25519AeadEidos,
            SealingKey::Ecgfp5Eidos(_) => IesScheme::Ecgfp5Eidos,
            SealingKey::NtruEidos(_) => IesScheme::NtruEidos,
        }
    }

    /// Seals the provided plaintext (represented as bytes) with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
    pub fn seal_bytes<R: CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<SealedMessage, IesError> {
        self.seal_bytes_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_bytes_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, PublicEncapsulation::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, PublicEncapsulation::X25519XChaCha20Poly1305;
        SealingKey::K256AeadEidos => K256AeadEidos, PublicEncapsulation::K256AeadEidos;
        SealingKey::X25519AeadEidos => X25519AeadEidos, PublicEncapsulation::X25519AeadEidos;
    }

    /// Seals the provided field elements with this sealing key.
    ///
    /// The returned message can be unsealed with the [UnsealingKey] associated with this sealing
    /// key.
    pub fn seal_elements<R: CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[Felt],
    ) -> Result<SealedMessage, IesError> {
        self.seal_elements_with_associated_data(rng, plaintext, &[])
    }

    impl_seal_elements_with_associated_data! {
        SealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, PublicEncapsulation::K256XChaCha20Poly1305;
        SealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, PublicEncapsulation::X25519XChaCha20Poly1305;
        SealingKey::K256AeadEidos => K256AeadEidos, PublicEncapsulation::K256AeadEidos;
        SealingKey::X25519AeadEidos => X25519AeadEidos, PublicEncapsulation::X25519AeadEidos;
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
            SealingKey::K256AeadEidos(key) => key.write_into(target),
            SealingKey::X25519AeadEidos(key) => key.write_into(target),
            SealingKey::Ecgfp5Eidos(key) => key.write_into(target),
            SealingKey::NtruEidos(key) => key.write_into(target),
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
            IesScheme::K256AeadEidos => {
                let key = crate::dsa::ecdsa_k256_keccak::PublicKey::read_from(source)?;
                Ok(SealingKey::K256AeadEidos(key))
            },
            IesScheme::X25519AeadEidos => {
                let key = crate::dsa::eddsa_25519_sha512::PublicKey::read_from(source)?;
                Ok(SealingKey::X25519AeadEidos(key))
            },
            IesScheme::Ecgfp5Eidos => {
                Ok(SealingKey::Ecgfp5Eidos(ecgfp5::PublicKey::read_from(source)?))
            },
            IesScheme::NtruEidos => Ok(SealingKey::NtruEidos(ntru::PublicKey::read_from(source)?)),
        }
    }
}

// UNSEALING KEY
// ================================================================================================

/// Secret key for unsealing messages.
pub enum UnsealingKey {
    K256XChaCha20Poly1305(crate::dsa::ecdsa_k256_keccak::KeyExchangeKey),
    X25519XChaCha20Poly1305(crate::dsa::eddsa_25519_sha512::KeyExchangeKey),
    K256AeadEidos(crate::dsa::ecdsa_k256_keccak::KeyExchangeKey),
    X25519AeadEidos(crate::dsa::eddsa_25519_sha512::KeyExchangeKey),
    Ecgfp5Eidos(ecgfp5::SecretKey),
    NtruEidos(ntru::SecretKey),
}

impl UnsealingKey {
    /// Returns scheme identifier for this unsealing key.
    pub fn scheme(&self) -> IesScheme {
        match self {
            UnsealingKey::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            UnsealingKey::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            UnsealingKey::K256AeadEidos(_) => IesScheme::K256AeadEidos,
            UnsealingKey::X25519AeadEidos(_) => IesScheme::X25519AeadEidos,
            UnsealingKey::Ecgfp5Eidos(_) => IesScheme::Ecgfp5Eidos,
            UnsealingKey::NtruEidos(_) => IesScheme::NtruEidos,
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
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, PublicEncapsulation::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, PublicEncapsulation::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadEidos => K256AeadEidos, PublicEncapsulation::K256AeadEidos;
        UnsealingKey::X25519AeadEidos => X25519AeadEidos, PublicEncapsulation::X25519AeadEidos;
    }

    /// Unseals the provided message using this unsealing key.
    ///
    /// The message must have been sealed as elements (i.e., using `seal_elements()` or
    /// `seal_elements_with_associated_data()` method), otherwise an error will be returned.
    pub fn unseal_elements(&self, sealed_message: SealedMessage) -> Result<Vec<Felt>, IesError> {
        self.unseal_elements_with_associated_data(sealed_message, &[])
    }

    impl_unseal_elements_with_associated_data! {
        UnsealingKey::K256XChaCha20Poly1305 => K256XChaCha20Poly1305, PublicEncapsulation::K256XChaCha20Poly1305;
        UnsealingKey::X25519XChaCha20Poly1305 => X25519XChaCha20Poly1305, PublicEncapsulation::X25519XChaCha20Poly1305;
        UnsealingKey::K256AeadEidos => K256AeadEidos, PublicEncapsulation::K256AeadEidos;
        UnsealingKey::X25519AeadEidos => X25519AeadEidos, PublicEncapsulation::X25519AeadEidos;
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
            UnsealingKey::K256AeadEidos(key) => key.write_into(target),
            UnsealingKey::X25519AeadEidos(key) => key.write_into(target),
            UnsealingKey::Ecgfp5Eidos(key) => key.write_into(target),
            UnsealingKey::NtruEidos(key) => key.write_into(target),
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
            IesScheme::K256AeadEidos => {
                let key = crate::dsa::ecdsa_k256_keccak::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::K256AeadEidos(key))
            },
            IesScheme::X25519AeadEidos => {
                let key = crate::dsa::eddsa_25519_sha512::KeyExchangeKey::read_from(source)?;
                Ok(UnsealingKey::X25519AeadEidos(key))
            },
            IesScheme::Ecgfp5Eidos => {
                Ok(UnsealingKey::Ecgfp5Eidos(ecgfp5::SecretKey::read_from(source)?))
            },
            IesScheme::NtruEidos => {
                Ok(UnsealingKey::NtruEidos(ntru::SecretKey::read_from(source)?))
            },
        }
    }
}

// PUBLIC ENCAPSULATION
// ================================================================================================

/// Public material for recovering the shared secret: an ephemeral point or a KEM ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PublicEncapsulation {
    K256XChaCha20Poly1305(crate::ecdh::k256::EphemeralPublicKey),
    X25519XChaCha20Poly1305(crate::ecdh::x25519::EphemeralPublicKey),
    K256AeadEidos(crate::ecdh::k256::EphemeralPublicKey),
    X25519AeadEidos(crate::ecdh::x25519::EphemeralPublicKey),
    Ecgfp5Eidos(ecgfp5::PublicKey),
    NtruEidos(ntru::Ciphertext),
}

impl PublicEncapsulation {
    /// Returns the scheme identifier for this encapsulation.
    pub fn scheme(&self) -> IesScheme {
        match self {
            PublicEncapsulation::K256XChaCha20Poly1305(_) => IesScheme::K256XChaCha20Poly1305,
            PublicEncapsulation::X25519XChaCha20Poly1305(_) => IesScheme::X25519XChaCha20Poly1305,
            PublicEncapsulation::K256AeadEidos(_) => IesScheme::K256AeadEidos,
            PublicEncapsulation::X25519AeadEidos(_) => IesScheme::X25519AeadEidos,
            PublicEncapsulation::Ecgfp5Eidos(_) => IesScheme::Ecgfp5Eidos,
            PublicEncapsulation::NtruEidos(_) => IesScheme::NtruEidos,
        }
    }

    /// Encodes the public encapsulation without a scheme prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicEncapsulation::K256XChaCha20Poly1305(key) => key.to_bytes(),
            PublicEncapsulation::X25519XChaCha20Poly1305(key) => key.to_bytes(),
            PublicEncapsulation::K256AeadEidos(key) => key.to_bytes(),
            PublicEncapsulation::X25519AeadEidos(key) => key.to_bytes(),
            PublicEncapsulation::Ecgfp5Eidos(key) => key.to_bytes().to_vec(),
            PublicEncapsulation::NtruEidos(ciphertext) => ciphertext.as_bytes().to_vec(),
        }
    }

    /// Deserializes the public encapsulation for the specified scheme.
    pub fn from_bytes(scheme: IesScheme, bytes: &[u8]) -> Result<Self, IesError> {
        let expected_len = match scheme {
            IesScheme::K256XChaCha20Poly1305 | IesScheme::K256AeadEidos => K256_PUBLIC_KEY_BYTES,
            IesScheme::X25519XChaCha20Poly1305 | IesScheme::X25519AeadEidos => {
                X25519_PUBLIC_KEY_BYTES
            },
            IesScheme::Ecgfp5Eidos => 40,
            IesScheme::NtruEidos => ntru::CIPHERTEXT_BYTES,
        };

        if bytes.len() != expected_len {
            return Err(if scheme == IesScheme::NtruEidos {
                IesError::InvalidEncapsulation
            } else {
                IesError::EphemeralPublicKeyDeserializationFailed
            });
        }

        match scheme {
            IesScheme::NtruEidos => ntru::Ciphertext::from_bytes(bytes)
                .map(PublicEncapsulation::NtruEidos)
                .map_err(|_| IesError::InvalidEncapsulation),
            IesScheme::Ecgfp5Eidos => {
                let bytes = bytes
                    .try_into()
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                let key = ecgfp5::PublicKey::from_bytes(bytes)
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(PublicEncapsulation::Ecgfp5Eidos(key))
            },
            IesScheme::K256XChaCha20Poly1305 => {
                let key =
                    <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(PublicEncapsulation::K256XChaCha20Poly1305(key))
            },
            IesScheme::K256AeadEidos => {
                let key =
                    <K256 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                    .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(PublicEncapsulation::K256AeadEidos(key))
            },
            IesScheme::X25519XChaCha20Poly1305 => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(PublicEncapsulation::X25519XChaCha20Poly1305(key))
            },
            IesScheme::X25519AeadEidos => {
                let key =
                    <X25519 as KeyAgreementScheme>::EphemeralPublicKey::read_from_bytes_with_budget(
                        bytes,
                        expected_len,
                    )
                        .map_err(|_| IesError::EphemeralPublicKeyDeserializationFailed)?;
                Ok(PublicEncapsulation::X25519AeadEidos(key))
            },
        }
    }
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
mod key_arbitrary {
    use proptest::prelude::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::{PublicEncapsulation, SealingKey};
    use crate::dsa::{
        ecdsa_k256_keccak::KeyExchangeKey as K256KeyExchangeKey,
        eddsa_25519_sha512::PublicKey as Ed25519PublicKey,
    };

    fn seed32(a: u64) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&a.to_be_bytes());
        seed
    }

    fn k256_key_exchange_key(seed: [u8; 32]) -> K256KeyExchangeKey {
        let mut rng = ChaCha20Rng::from_seed(seed);
        K256KeyExchangeKey::with_rng(&mut rng)
    }

    fn k256_public_key(seed: [u8; 32]) -> crate::dsa::ecdsa_k256_keccak::PublicKey {
        k256_key_exchange_key(seed).public_key()
    }

    fn ecgfp5_public_key(seed: [u8; 32]) -> crate::ecdh::ecgfp5::PublicKey {
        let mut rng = ChaCha20Rng::from_seed(seed);
        crate::ecdh::ecgfp5::SecretKey::with_rng(&mut rng).public_key()
    }

    impl Arbitrary for SealingKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // EC variants need valid points; NTRU decoding only constrains the unused bits.
            prop_oneof![
                (0u64..)
                    .prop_map(|a| Self::K256XChaCha20Poly1305(k256_public_key(seed32(a))))
                    .boxed(),
                any::<Ed25519PublicKey>().prop_map(Self::X25519XChaCha20Poly1305).boxed(),
                (0u64..).prop_map(|a| Self::K256AeadEidos(k256_public_key(seed32(a)))).boxed(),
                any::<Ed25519PublicKey>().prop_map(Self::X25519AeadEidos).boxed(),
                (0u64..).prop_map(|a| Self::Ecgfp5Eidos(ecgfp5_public_key(seed32(a)))).boxed(),
                any::<[u8; super::ntru::PUBLIC_KEY_BYTES]>()
                    .prop_map(|mut bytes| {
                        bytes[super::ntru::PUBLIC_KEY_BYTES - 1] &= 0x0f;
                        Self::NtruEidos(super::ntru::PublicKey::from_bytes(&bytes).unwrap())
                    })
                    .boxed(),
            ]
            .boxed()
        }
    }

    impl Arbitrary for PublicEncapsulation {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                any::<crate::ecdh::k256::EphemeralPublicKey>()
                    .prop_map(Self::K256XChaCha20Poly1305)
                    .boxed(),
                any::<crate::ecdh::x25519::EphemeralPublicKey>()
                    .prop_map(Self::X25519XChaCha20Poly1305)
                    .boxed(),
                any::<crate::ecdh::k256::EphemeralPublicKey>()
                    .prop_map(Self::K256AeadEidos)
                    .boxed(),
                any::<crate::ecdh::x25519::EphemeralPublicKey>()
                    .prop_map(Self::X25519AeadEidos)
                    .boxed(),
                (0u64..).prop_map(|a| Self::Ecgfp5Eidos(ecgfp5_public_key(seed32(a)))).boxed(),
                any::<[u8; super::ntru::CIPHERTEXT_BYTES]>()
                    .prop_map(|bytes| {
                        Self::NtruEidos(super::ntru::Ciphertext::from_bytes(&bytes).unwrap())
                    })
                    .boxed(),
            ]
            .boxed()
        }
    }
}
