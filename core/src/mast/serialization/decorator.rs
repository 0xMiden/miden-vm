use alloc::vec::Vec;

use miden_crypto::field::PrimeField64;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
#[cfg(all(feature = "arbitrary", feature = "std"))]
use proptest_derive::Arbitrary;

use super::{
    DecoratorDataOffset,
    string_table::{StringTable, StringTableBuilder},
};
use crate::{
    operations::{DebugOptions, DebugVarInfo, DebugVarLocation, Decorator},
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
        // This is safe because for decorators that don't use the offset, `0` is used (and hence
        // will never access an element outside). Note that in this implementation, we trust the
        // encoder.
        let mut data_reader =
            SliceReader::new(&decorator_data[self.decorator_data_offset as usize..]);
        match self.variant {
            EncodedDecoratorVariant::DebugOptionsStackAll => {
                Ok(Decorator::Debug(DebugOptions::StackAll))
            },
            EncodedDecoratorVariant::DebugOptionsStackTop => {
                let value = data_reader.read_u8()?;

                Ok(Decorator::Debug(DebugOptions::StackTop(value)))
            },
            EncodedDecoratorVariant::DebugOptionsMemAll => {
                Ok(Decorator::Debug(DebugOptions::MemAll))
            },
            EncodedDecoratorVariant::DebugOptionsMemInterval => {
                let start = data_reader.read_u32()?;
                let end = data_reader.read_u32()?;

                Ok(Decorator::Debug(DebugOptions::MemInterval(start, end)))
            },
            EncodedDecoratorVariant::DebugOptionsLocalInterval => {
                let start = data_reader.read_u16()?;
                let second = data_reader.read_u16()?;
                let end = data_reader.read_u16()?;

                Ok(Decorator::Debug(DebugOptions::LocalInterval(start, second, end)))
            },
            EncodedDecoratorVariant::Trace => {
                let value = data_reader.read_u32()?;

                Ok(Decorator::Trace(value))
            },
            EncodedDecoratorVariant::DebugOptionsAdvStackTop => {
                let value = data_reader.read_u16()?;
                Ok(Decorator::Debug(DebugOptions::AdvStackTop(value)))
            },
            EncodedDecoratorVariant::DebugVar => {
                // Read variable name
                let name_idx = data_reader.read_usize()?;
                let name = string_table.read_string(name_idx)?;

                // Read value location tag and data
                let location_tag = data_reader.read_u8()?;
                let value_location = match location_tag {
                    0 => DebugVarLocation::Stack(data_reader.read_u8()?),
                    1 => DebugVarLocation::Memory(data_reader.read_u32()?),
                    2 => {
                        let value = data_reader.read_u64()?;
                        DebugVarLocation::Const(crate::Felt::new(value))
                    },
                    3 => DebugVarLocation::Local(data_reader.read_u16()? as i16),
                    4 => {
                        let len = data_reader.read_u16()? as usize;
                        let bytes = data_reader.read_vec(len)?;
                        DebugVarLocation::Expression(bytes)
                    },
                    _ => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid DebugVarLocation tag: {location_tag}"
                        )));
                    },
                };

                let mut debug_var = DebugVarInfo::new(name, value_location);

                // Read optional type_id
                if data_reader.read_bool()? {
                    debug_var.set_type_id(data_reader.read_u32()?);
                }

                // Read optional arg_index (1-based, stored as raw u32)
                if data_reader.read_bool()? {
                    let arg_index = data_reader.read_u32()?;
                    // set_arg_index expects a non-zero value for 1-based indices
                    if arg_index > 0 {
                        debug_var.set_arg_index(arg_index);
                    }
                }

                // Read optional source location
                if data_reader.read_bool()? {
                    use miden_debug_types::{ColumnNumber, FileLineCol, LineNumber, Uri};
                    let uri_idx = data_reader.read_usize()?;
                    let uri = Uri::from(string_table.read_arc_str(uri_idx)?);
                    let line = data_reader.read_u32()?;
                    let column = data_reader.read_u32()?;
                    debug_var.set_location(FileLineCol::new(
                        uri,
                        LineNumber::new(line).unwrap_or_default(),
                        ColumnNumber::new(column).unwrap_or_default(),
                    ));
                }

                Ok(Decorator::DebugVar(debug_var))
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
    DebugOptionsStackAll = 0,
    DebugOptionsStackTop = 1,
    DebugOptionsMemAll = 2,
    DebugOptionsMemInterval = 3,
    DebugOptionsLocalInterval = 4,
    DebugOptionsAdvStackTop = 5,
    Trace = 6,
    DebugVar = 7,
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
            Decorator::Debug(debug_options) => match debug_options {
                DebugOptions::StackAll => Self::DebugOptionsStackAll,
                DebugOptions::StackTop(_) => Self::DebugOptionsStackTop,
                DebugOptions::MemAll => Self::DebugOptionsMemAll,
                DebugOptions::MemInterval(..) => Self::DebugOptionsMemInterval,
                DebugOptions::LocalInterval(..) => Self::DebugOptionsLocalInterval,
                DebugOptions::AdvStackTop(_) => Self::DebugOptionsAdvStackTop,
            },
            Decorator::Trace(_) => Self::Trace,
            Decorator::DebugVar(_) => Self::DebugVar,
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
        let decorator_data_offset = self.encode_decorator_data(decorator).unwrap_or(0);
        self.decorator_infos
            .push(DecoratorInfo::from_decorator(decorator, decorator_data_offset));
    }

    /// If a decorator has extra data to store, encode it in internal data buffer, and return the
    /// offset of the newly added data. If not, return `None`.
    pub fn encode_decorator_data(&mut self, decorator: &Decorator) -> Option<DecoratorDataOffset> {
        let data_offset = self.decorator_data.len() as DecoratorDataOffset;

        match decorator {
            Decorator::Debug(debug_options) => match debug_options {
                DebugOptions::StackTop(value) => {
                    self.decorator_data.push(*value);
                    Some(data_offset)
                },
                DebugOptions::AdvStackTop(value) => {
                    self.decorator_data.extend(value.to_le_bytes());
                    Some(data_offset)
                },
                DebugOptions::MemInterval(start, end) => {
                    self.decorator_data.extend(start.to_le_bytes());
                    self.decorator_data.extend(end.to_le_bytes());

                    Some(data_offset)
                },
                DebugOptions::LocalInterval(start, second, end) => {
                    self.decorator_data.extend(start.to_le_bytes());
                    self.decorator_data.extend(second.to_le_bytes());
                    self.decorator_data.extend(end.to_le_bytes());

                    Some(data_offset)
                },
                DebugOptions::StackAll | DebugOptions::MemAll => None,
            },
            Decorator::Trace(value) => {
                self.decorator_data.extend(value.to_le_bytes());

                Some(data_offset)
            },
            Decorator::DebugVar(debug_var) => {
                // Write variable name
                let name_offset = self.string_table_builder.add_string(debug_var.name());
                self.decorator_data.write_usize(name_offset);

                // Write value location with tag
                match debug_var.value_location() {
                    DebugVarLocation::Stack(pos) => {
                        self.decorator_data.push(0); // tag
                        self.decorator_data.push(*pos);
                    },
                    DebugVarLocation::Memory(addr) => {
                        self.decorator_data.push(1); // tag
                        self.decorator_data.extend(addr.to_le_bytes());
                    },
                    DebugVarLocation::Const(felt) => {
                        self.decorator_data.push(2); // tag
                        // Serialize Felt as u64
                        self.decorator_data.extend(felt.as_canonical_u64().to_le_bytes());
                    },
                    DebugVarLocation::Local(offset) => {
                        self.decorator_data.push(3); // tag
                        self.decorator_data.extend(offset.to_le_bytes());
                    },
                    DebugVarLocation::Expression(bytes) => {
                        self.decorator_data.push(4); // tag
                        self.decorator_data.extend((bytes.len() as u16).to_le_bytes());
                        self.decorator_data.extend(bytes);
                    },
                }

                // Write optional type_id
                self.decorator_data.write_bool(debug_var.type_id().is_some());
                if let Some(type_id) = debug_var.type_id() {
                    self.decorator_data.extend(type_id.to_le_bytes());
                }

                // Write optional arg_index (serialize NonZeroU32 as u32)
                self.decorator_data.write_bool(debug_var.arg_index().is_some());
                if let Some(arg_index) = debug_var.arg_index() {
                    self.decorator_data.extend(arg_index.get().to_le_bytes());
                }

                // Write optional source location
                self.decorator_data.write_bool(debug_var.location().is_some());
                if let Some(loc) = debug_var.location() {
                    let uri_offset = self.string_table_builder.add_string(loc.uri.as_str());
                    self.decorator_data.write_usize(uri_offset);
                    self.decorator_data.extend(loc.line.to_u32().to_le_bytes());
                    self.decorator_data.extend(loc.column.to_u32().to_le_bytes());
                }

                Some(data_offset)
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
