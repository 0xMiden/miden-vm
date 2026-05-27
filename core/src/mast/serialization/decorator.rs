use alloc::vec::Vec;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
#[cfg(all(feature = "arbitrary", feature = "std"))]
use proptest_derive::Arbitrary;

use super::{
    DecoratorDataOffset,
    string_table::{StringTable, StringTableBuilder},
};
use crate::{
    operations::Decorator,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

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

impl DecoratorInfo {
    pub fn from_decorator(
        decorator: &Decorator,
        decorator_data_offset: DecoratorDataOffset,
    ) -> Self {
        let variant = EncodedDecoratorVariant::from(decorator);
        Self { variant, decorator_data_offset }
    }

    pub fn try_into_decorator(
        &self,
        _string_table: &StringTable,
        decorator_data: &[u8],
    ) -> Result<Decorator, DeserializationError> {
        let offset = self.decorator_data_offset as usize;
        if offset > decorator_data.len() {
            return Err(DeserializationError::InvalidValue(format!(
                "decorator data offset {offset} is out of bounds (data length: {})",
                decorator_data.len()
            )));
        }
        let mut data_reader = SliceReader::new(&decorator_data[offset..]);
        match self.variant {
            EncodedDecoratorVariant::Trace => {
                let value = data_reader.read_u32()?;

                Ok(Decorator::Trace(value))
            },
        }
    }
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

/// Stores all the possible [`Decorator`] variants, without any associated data.
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
    Trace = 6,
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

impl From<&Decorator> for EncodedDecoratorVariant {
    fn from(decorator: &Decorator) -> Self {
        match decorator {
            Decorator::Trace(_) => Self::Trace,
        }
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

// DECORATOR DATA BUILDER
// ===============================================================================================

/// Builds the decorator `data` section of a serialized [`crate::mast::MastForest`].
#[derive(Debug, Default)]
pub struct DecoratorDataBuilder {
    decorator_data: Vec<u8>,
    decorator_infos: Vec<DecoratorInfo>,
    string_table_builder: StringTableBuilder,
}

/// Constructors
impl DecoratorDataBuilder {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Mutators
impl DecoratorDataBuilder {
    pub fn add_decorator(&mut self, decorator: &Decorator) {
        let decorator_data_offset = self.encode_decorator_data(decorator);
        self.decorator_infos
            .push(DecoratorInfo::from_decorator(decorator, decorator_data_offset));
    }

    /// Encodes the decorator's extra data in the internal data buffer, and returns the offset of
    /// the newly added data.
    pub fn encode_decorator_data(&mut self, decorator: &Decorator) -> DecoratorDataOffset {
        let data_offset = self.decorator_data.len() as DecoratorDataOffset;

        match decorator {
            Decorator::Trace(value) => {
                self.decorator_data.extend(value.to_le_bytes());

                data_offset
            },
        }
    }

    /// Returns the serialized [`crate::mast::MastForest`] decorator data field.
    pub fn finalize(self) -> (Vec<u8>, Vec<DecoratorInfo>, StringTable) {
        (
            self.decorator_data,
            self.decorator_infos,
            self.string_table_builder.into_table(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decorator_data_offset_out_of_bounds() {
        let info = DecoratorInfo {
            variant: EncodedDecoratorVariant::Trace,
            decorator_data_offset: 99,
        };
        let data: Vec<u8> = vec![1, 2, 3];
        let string_table = StringTable::new(vec![], vec![]);
        let result = info.try_into_decorator(&string_table, &data);
        assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
    }
}
