use alloc::vec::Vec;
use core::convert::TryFrom;

use super::{IesScheme, keys::EphemeralPublicKey};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SEALED MESSAGE
// ================================================================================================

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Ephemeral public key (determines scheme and provides key material)
    pub(super) ephemeral_key: EphemeralPublicKey,
    /// Encrypted ciphertext with authentication tag and nonce
    pub(super) ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Returns the scheme used to create this sealed message.
    pub(super) fn scheme(&self) -> IesScheme {
        self.ephemeral_key.scheme()
    }

    /// Returns the scheme name used to create this sealed message.
    pub fn scheme_name(&self) -> &'static str {
        self.scheme().name()
    }

    /// Returns the byte representation of this sealed message.
    pub fn to_bytes(&self) -> Vec<u8> {
        <Self as Serializable>::to_bytes(self)
    }
}

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let scheme = self.scheme();
        target.write_u8(scheme as u8);

        self.ephemeral_key.to_bytes().write_into(target);
        self.ciphertext.write_into(target);
    }
}

impl Deserializable for SealedMessage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = match IesScheme::try_from(source.read_u8()?) {
            Ok(a) => a,
            Err(_) => {
                return Err(DeserializationError::InvalidValue("Unsupported scheme".into()));
            },
        };

        let eph_key_bytes = Vec::<u8>::read_from(source)?;
        let ephemeral_key =
            EphemeralPublicKey::from_bytes(scheme, &eph_key_bytes).map_err(|e| {
                DeserializationError::InvalidValue(format!("Invalid ephemeral key: {e}"))
            })?;

        let ciphertext = Vec::<u8>::read_from(source)?;

        Ok(Self { ephemeral_key, ciphertext })
    }
}
