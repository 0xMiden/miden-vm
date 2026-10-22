use alloc::vec::Vec;
use core::convert::TryFrom;

use super::{IesScheme, keys::PublicEncapsulation};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// SEALED MESSAGE
// ================================================================================================

/// A sealed message containing encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct SealedMessage {
    /// Ephemeral point or KEM ciphertext used to recover the shared secret.
    pub(super) encapsulation: PublicEncapsulation,
    /// Scheme-specific ciphertext encoding, including its authentication tag.
    pub(super) ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Returns the scheme used to create this sealed message.
    pub(super) fn scheme(&self) -> IesScheme {
        self.encapsulation.scheme()
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

#[cfg(any(test, feature = "arbitrary"))]
mod sealed_message_arbitrary {
    use proptest::prelude::*;

    use super::SealedMessage;
    use crate::ies::keys::PublicEncapsulation;

    impl Arbitrary for SealedMessage {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // The reader validates the public encapsulation under the scheme byte.
            (any::<PublicEncapsulation>(), proptest::collection::vec(any::<u8>(), 0..=32))
                .prop_map(|(encapsulation, ciphertext)| Self { encapsulation, ciphertext })
                .boxed()
        }
    }
}

impl Serializable for SealedMessage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let scheme = self.scheme();
        target.write_u8(scheme as u8);

        self.encapsulation.to_bytes().write_into(target);
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

        let encapsulation_bytes = Vec::<u8>::read_from(source)?;
        let encapsulation =
            PublicEncapsulation::from_bytes(scheme, &encapsulation_bytes).map_err(|e| {
                DeserializationError::InvalidValue(format!("Invalid public encapsulation: {e}"))
            })?;

        let ciphertext = Vec::<u8>::read_from(source)?;

        Ok(Self { encapsulation, ciphertext })
    }
}
