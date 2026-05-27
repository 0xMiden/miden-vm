use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
#[cfg(all(feature = "arbitrary", feature = "std"))]
use proptest_derive::Arbitrary;

use super::DecoratorDataOffset;
use crate::serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Represents a serialized [`Decorator`].
///
/// The serialized representation of [`DecoratorInfo`] is guaranteed to be fixed width, so that the
/// decorators stored in the `decorators` table of the serialized [`MastForest`] can be accessed
/// quickly by index.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(all(feature = "arbitrary", feature = "std"), derive(Arbitrary))]
#[cfg_attr(
    all(feature = "arbitrary", feature = "std", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
pub struct DecoratorInfo {
    variant: EncodedDecoratorVariant,
    decorator_data_offset: DecoratorDataOffset,
}

impl Serializable for DecoratorInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { variant, decorator_data_offset } = self;

        variant.write_into(target);
        decorator_data_offset.write_into(target);
    }
}

impl Deserializable for DecoratorInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let variant = source.read()?;
        let decorator_data_offset = source.read()?;

        Ok(Self { variant, decorator_data_offset })
    }

    /// Returns the minimum serialized size: 1 byte variant + 4 bytes offset.
    fn min_serialized_size() -> usize {
        5
    }
}

// ENCODED DATA VARIANT
// ===============================================================================================

/// Stores all legacy executable decorator variants, without any associated data.
///
/// This is effectively equivalent to a set of constants, and designed to convert between variant
/// discriminant and enum variant conveniently.
#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[cfg_attr(all(feature = "arbitrary", feature = "std"), derive(Arbitrary))]
#[cfg_attr(
    all(feature = "arbitrary", feature = "std", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[repr(u8)]
pub enum EncodedDecoratorVariant {
    // Note: AssemblyOp removed in version [0, 0, 2] - now stored separately in DebugInfo
    // Reserved: these used to encode the removed `debug` decorators.
    DebugOptionsStackAll = 0,
    DebugOptionsStackTop = 1,
    DebugOptionsMemAll = 2,
    DebugOptionsMemInterval = 3,
    DebugOptionsLocalInterval = 4,
    DebugOptionsAdvStackTop = 5,
    // Reserved: this used to encode the removed `trace` decorator.
    TraceDecorator = 6,
}

impl EncodedDecoratorVariant {
    /// Returns the discriminant of the given decorator variant.
    ///
    /// To distinguish them from [`crate::Operation`] discriminants, the most significant bit of
    /// decorator discriminant is always set to 1.
    pub fn discriminant(&self) -> u8 {
        self.to_u8().expect("guaranteed to fit in a `u8` due to #[repr(u8)]")
    }

    /// The inverse operation of [`Self::discriminant`].
    pub fn from_discriminant(discriminant: u8) -> Option<Self> {
        Self::from_u8(discriminant)
    }
}

impl Serializable for EncodedDecoratorVariant {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.discriminant().write_into(target);
    }
}

impl Deserializable for EncodedDecoratorVariant {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant: u8 = source.read_u8()?;

        Self::from_discriminant(discriminant).ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "invalid decorator discriminant: {discriminant}"
            ))
        })
    }

    /// Returns the fixed serialized size: 1 byte discriminant.
    fn min_serialized_size() -> usize {
        1
    }
}
