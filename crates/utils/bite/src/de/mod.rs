use alloc::{format, vec::Vec};

use serde::de;
use smallvec::ToSmallVec;

use super::{Error, Limits, MAGIC, Result, VERSION, varint};
use crate::Type;

/// Deserialize a value of type `T` from the given BITE-encoded byte slice.
pub fn from_bytes<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: de::Deserialize<'de>,
{
    from_bytes_with_limits(bytes, Limits::default())
}

/// Deserialize a value of type `T` from the given BITE-encoded byte slice, while applying the
/// provided limits during deserialization.
pub fn from_bytes_with_limits<'de, T>(bytes: &'de [u8], limits: Limits) -> Result<T>
where
    T: de::Deserialize<'de>,
{
    let mut deserializer = BiteDeserializer::new(bytes, limits)?;
    T::deserialize(&mut deserializer)
}

struct BiteDeserializer<'de> {
    data: &'de [u8],
    position: usize,
    depth: usize,
    limits: Limits,
    strings: Vec<&'de str>,
}

struct Snapshot {
    position: usize,
    depth: usize,
}

impl<'de> BiteDeserializer<'de> {
    pub fn new(data: &'de [u8], limits: Limits) -> Result<Self> {
        let mut deserializer = Self {
            data,
            position: 0,
            strings: Vec::new(),
            limits,
            depth: 0,
        };

        deserializer.read_header()?;
        deserializer.read_string_table()?;

        Ok(deserializer)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            position: self.position,
            depth: self.depth,
        }
    }

    fn restore(&mut self, snapshot: Snapshot) {
        self.position = snapshot.position;
        self.depth = snapshot.depth;
    }

    fn read_header(&mut self) -> Result<()> {
        if self.data.len() < 8 {
            return Err(Error::UnexpectedEof);
        }

        if &self.data[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        self.position = MAGIC.len();

        let version = self.data[self.position];
        if version != VERSION {
            return Err(Error::InvalidVersion(version));
        }
        self.position += 1;

        Ok(())
    }

    fn read_string_table(&mut self) -> Result<()> {
        log::trace!(target: "de", "reading string table");
        // Read number of entries in string table
        let num_strings = self.read_varint()?;
        let num_strings = u32::try_from(num_strings).map_err(|_| Error::LimitExceeded {
            limit_type: "string table length",
            value: num_strings,
            max: u32::MAX as usize,
        })? as usize;

        log::trace!(target: "de", "found string table with {num_strings} entries");

        // Read string table entries
        self.strings.reserve(num_strings);
        for id in 0..num_strings {
            let len = self.read_varint()?;
            let len = u32::try_from(len).map_err(|_| Error::LimitExceeded {
                limit_type: "string length",
                value: len,
                max: u32::MAX as usize,
            })? as usize;
            log::trace!(target: "de", "reading string id {id} (length is {len})");
            let bytes = self.read_bytes(len)?;
            let s = core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
            log::trace!(target: "de", "string id {id} read as '{s}'");
            self.strings.push(s);
        }

        log::trace!(target: "de", "successfully read all string table entries");

        Ok(())
    }

    #[inline]
    fn read_byte(&mut self) -> Result<u8> {
        let byte = self.data.get(self.position).copied().ok_or(Error::UnexpectedEof)?;

        self.position += 1;

        Ok(byte)
    }

    #[inline]
    fn read_bytes(&mut self, count: usize) -> Result<&'de [u8]> {
        let bytes = self
            .data
            .get(self.position..self.position + count)
            .ok_or(Error::UnexpectedEof)?;
        self.position += count;
        Ok(bytes)
    }

    #[inline]
    fn read_exact<const N: usize>(&mut self) -> Result<&'de [u8; N]> {
        let bytes = self.data.get(self.position..self.position + N).ok_or(Error::UnexpectedEof)?;
        self.position += N;
        Ok(unsafe { <&'de [u8; N]>::try_from(bytes).unwrap_unchecked() })
    }

    #[inline]
    fn read_varint(&mut self) -> Result<u64> {
        varint::decode(self.data, &mut self.position)
    }

    #[inline]
    fn read_type_tag(&mut self) -> Result<Type> {
        self.read_byte().and_then(Type::try_from)
    }

    #[inline]
    fn peek_type_tag(&mut self) -> Result<Type> {
        let byte = self.data.get(self.position).copied().ok_or(Error::UnexpectedEof)?;

        Type::try_from(byte)
    }

    #[inline]
    fn expect_type_tag(&mut self, expected: Type) -> Result<()> {
        self.read_type_tag().and_then(|ty| {
            if ty != expected {
                Err(Error::UnexpectedType {
                    actual: ty,
                    expected: [expected].to_smallvec(),
                })
            } else {
                Ok(())
            }
        })
    }

    #[inline]
    fn expect_type_tags(&mut self, expected: &[Type]) -> Result<Type> {
        self.read_type_tag().and_then(|ty| {
            if expected.contains(&ty) {
                Ok(ty)
            } else {
                Err(Error::UnexpectedType {
                    actual: ty,
                    expected: expected.to_smallvec(),
                })
            }
        })
    }

    fn check_depth(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > self.limits.max_depth {
            return Err(Error::LimitExceeded {
                limit_type: "depth",
                value: self.depth as u64,
                max: self.limits.max_depth,
            });
        }
        Ok(())
    }

    fn exit_depth(&mut self) {
        self.depth -= 1;
    }
}

impl<'de> de::Deserializer<'de> for &mut BiteDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let ty = self.read_type_tag()?;
        log::trace!(target: "de", "deserialize_any: {ty}");
        match ty {
            Type::False => visitor.visit_bool(false),
            Type::True => visitor.visit_bool(true),
            Type::None => visitor.visit_none(),
            Type::Some => visitor.visit_some(self),
            Type::Int => {
                let value = self.read_varint()?;
                visitor.visit_u64(value)
            },
            Type::SInt => {
                let value = self.read_varint()?;
                let leading_zeroes = value.leading_zeros();
                log::trace!(target: "de", "parsed signed integer with {leading_zeroes} leading zeros");
                match leading_zeroes {
                    0..32 => visitor.visit_i64(value as i64),
                    32..48 => visitor.visit_i32(value as u32 as i32),
                    48..56 => visitor.visit_i16(value as u16 as i16),
                    _ => visitor.visit_i8(value as u8 as i8),
                }
            },
            Type::I8 => {
                let byte = self.read_byte()?;
                visitor.visit_i8(byte as i8)
            },
            Type::U8 => {
                let byte = self.read_byte()?;
                visitor.visit_u8(byte)
            },
            Type::F32 => {
                self.position -= 1;
                self.deserialize_f32(visitor)
            },
            Type::F64 => {
                self.position -= 1;
                self.deserialize_f64(visitor)
            },
            Type::Char => {
                self.position -= 1;
                self.deserialize_char(visitor)
            },
            Type::Bytes => {
                self.position -= 1;
                self.deserialize_bytes(visitor)
            },
            Type::Str => {
                self.position -= 1;
                self.deserialize_str(visitor)
            },
            Type::Seq => {
                self.position -= 1;
                self.deserialize_seq(visitor)
            },
            Type::Map => {
                self.position -= 1;
                self.deserialize_map(visitor)
            },
            Type::UnitVariant | Type::NewtypeVariant | Type::StructVariant | Type::TupleVariant => {
                self.position -= 1;
                self.check_depth()?;
                let result = visitor.visit_enum(EnumAccess::new(self));
                self.exit_depth();
                result
            },
        }
    }

    fn deserialize_bool<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize bool");
        let ty = self.expect_type_tags(&[Type::True, Type::False])?;
        visitor.visit_bool(ty == Type::True)
    }

    fn deserialize_i8<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize i8");
        self.expect_type_tag(Type::I8)?;
        let byte = self.read_byte()?;
        visitor.visit_i8(byte as i8)
    }

    fn deserialize_i16<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize i16");
        self.expect_type_tag(Type::SInt)?;
        let value = self.read_varint()?;
        if value > u16::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid i16 value, got {value} which is out of range for that type"
            )));
        }
        visitor.visit_i16(value as u16 as i16)
    }

    fn deserialize_i32<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize i32");
        self.expect_type_tag(Type::SInt)?;
        let value = self.read_varint()?;
        if value > u32::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid i32 value, got {value} which is out of range for that type"
            )));
        }
        visitor.visit_i32(value as u32 as i32)
    }

    fn deserialize_i64<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize i64");
        self.expect_type_tag(Type::SInt)?;
        let value = self.read_varint()?;
        visitor.visit_i64(value as i64)
    }

    fn deserialize_u8<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize u8");
        self.expect_type_tag(Type::U8)?;
        visitor.visit_u8(self.read_byte()?)
    }

    fn deserialize_u16<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize u16");
        self.expect_type_tag(Type::Int)?;
        let value = self.read_varint()?;
        if value > u16::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid u16 value, got {value} which is out of range for that type"
            )));
        }
        visitor.visit_u16(value as u16)
    }

    fn deserialize_u32<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize u32");
        self.expect_type_tag(Type::Int)?;
        let value = self.read_varint()?;
        if value > u32::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid u32 value, got {value} which is out of range for that type"
            )));
        }
        visitor.visit_u32(value as u32)
    }

    fn deserialize_u64<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize u64");
        self.expect_type_tag(Type::Int)?;
        let value = self.read_varint()?;
        visitor.visit_u64(value)
    }

    fn deserialize_f32<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize f32");
        self.expect_type_tag(Type::F32)?;
        let bytes = self.read_exact::<4>()?;
        let value = f32::from_le_bytes(*bytes);
        visitor.visit_f32(value)
    }

    fn deserialize_f64<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize f64");
        self.expect_type_tag(Type::F64)?;
        let bytes = self.read_exact::<8>()?;
        let value = f64::from_le_bytes(*bytes);
        visitor.visit_f64(value)
    }

    fn deserialize_char<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize char");
        self.expect_type_tag(Type::Char)?;
        let code = self.read_varint()?;
        let code = u32::try_from(code).map_err(|_| Error::InvalidUtf8Char)?;
        let c = char::from_u32(code).ok_or(Error::InvalidUtf8Char)?;
        visitor.visit_char(c)
    }

    fn deserialize_str<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize str");
        self.expect_type_tag(Type::Str)?;
        let index = self.read_varint()?;
        log::trace!(target: "de", "parsed string index {index}");
        if index > u32::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid string table index, got {index} which is out of bounds"
            )));
        }
        let index = index as usize;
        if index >= self.strings.len() {
            return Err(Error::InvalidStringId(index));
        }
        visitor.visit_borrowed_str(self.strings[index])
    }

    fn deserialize_string<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize bytes");
        self.expect_type_tag(Type::Bytes)?;
        let len = self.read_varint()?;
        log::trace!(target: "de", "parsed length of {len}");
        if len > usize::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid length, got {len} which is out of bounds"
            )));
        }
        let bytes = self.read_bytes(len as usize)?;
        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize option");
        match self.read_type_tag()? {
            Type::None => visitor.visit_none(),
            Type::Some => visitor.visit_some(self),
            _ => {
                // The field must've been skipped
                self.position -= 1;
                visitor.visit_none()
            },
        }
    }

    fn deserialize_unit<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize unit");
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize unit struct '{_name}'");
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize newtype struct '{_name}'");
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize sequence");

        // If we don't see the seq tag, the sequence may have been skipped, so read an empty one
        if self.peek_type_tag()? != Type::Seq {
            return visitor.visit_seq(SeqAccess::new(self, 0));
        }

        self.expect_type_tag(Type::Seq)?;
        let len = self.read_varint()?;
        log::trace!(target: "de", "parsed length of {len}");
        if len > usize::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid sequence length, got {len} which is out of bounds"
            )));
        }
        let len = len as usize;
        if len > self.limits.max_sequence_length {
            return Err(Error::LimitExceeded {
                limit_type: "sequence_length",
                value: len as u64,
                max: self.limits.max_sequence_length,
            });
        }
        self.check_depth()?;
        let result = visitor.visit_seq(SeqAccess::new(self, len));
        self.exit_depth();
        result
    }

    fn deserialize_tuple<V: de::Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize tuple (expected arity {len})");

        self.check_depth()?;
        let result = visitor.visit_seq(SeqAccess::new(self, len));
        self.exit_depth();
        result
    }

    fn deserialize_tuple_struct<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize tuple struct '{_name}' (expected arity {len})");
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize map");

        // If we don't see the map tag, the map may have been skipped, so read an empty map
        if self.peek_type_tag()? != Type::Map {
            return visitor.visit_map(MapAccess::new(self, 0)?);
        }

        self.expect_type_tag(Type::Map)?;
        let len = self.read_varint()?;
        log::trace!(target: "de", "parsed length of {len}");
        if len > usize::MAX as u64 {
            return Err(Error::Custom(format!(
                "expected valid map size, got {len} which is out of bounds"
            )));
        }
        let len = len as usize;
        if len > self.limits.max_map_entries {
            return Err(Error::LimitExceeded {
                limit_type: "map_entries",
                value: len as u64,
                max: self.limits.max_map_entries,
            });
        }
        self.check_depth()?;
        let result = visitor.visit_map(MapAccess::new(self, len)?);
        self.exit_depth();
        result
    }

    fn deserialize_struct<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize struct '{_name}' with {} fields", fields.len());

        self.check_depth()?;
        let result = visitor.visit_seq(SeqAccess::new(self, fields.len()));
        self.exit_depth();
        result
    }

    fn deserialize_enum<V: de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize enum '{_name}' with {} variants", _variants.len());
        self.check_depth()?;
        let result = visitor.visit_enum(EnumAccess::new(self));
        self.exit_depth();
        result
    }

    fn deserialize_identifier<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize identifier");
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize ignored");
        self.deserialize_any(visitor)
    }
}

// Helper structs for complex types
struct SeqAccess<'a, 'de> {
    de: &'a mut BiteDeserializer<'de>,
    remaining: usize,
}

impl<'a, 'de> SeqAccess<'a, 'de> {
    fn new(de: &'a mut BiteDeserializer<'de>, count: usize) -> Self {
        Self { de, remaining: count }
    }
}

impl<'de> de::SeqAccess<'de> for SeqAccess<'_, 'de> {
    type Error = Error;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            log::trace!(target: "de", "finished deserializing sequence");
            return Ok(None);
        }
        log::trace!(target: "de", "deserialize next element");
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct MapAccess<'a, 'de> {
    de: &'a mut BiteDeserializer<'de>,
    remaining: usize,
    current_key: usize,
    next_value: usize,
    keys_end: usize,
    values_end: usize,
}

impl<'a, 'de> MapAccess<'a, 'de> {
    fn new(de: &'a mut BiteDeserializer<'de>, count: usize) -> Result<Self> {
        // If the map is empty, there is nothing to do
        if count == 0 {
            let pos = de.position;
            return Ok(Self {
                de,
                remaining: 0,
                current_key: pos,
                next_value: pos,
                keys_end: pos,
                values_end: pos,
            });
        }

        // We begin at the start of the key segment
        //
        // The length of the segment comes first
        let keys_len = de.read_varint()?;

        // The offset of the first key immediately follows the length
        let current_key = de.position;

        // The offset of the value segment occurs immediately after the keys
        let value_segment_offset = usize::try_from(keys_len).map_err(|_| Error::LimitExceeded {
            limit_type: "map keys",
            value: keys_len,
            max: u32::MAX as usize,
        })?;

        // Validate the value segment offset
        let value_segment_start =
            current_key.checked_add(value_segment_offset).ok_or(Error::UnexpectedEof)?;

        // Save the current deserializer state while we look forward at the value segment
        let snapshot = de.snapshot();
        de.position = value_segment_start;

        // The size of the value segment precedes the values themselves, parse that now
        let values_len = de.read_varint()?;
        let value_segment_len = usize::try_from(values_len).map_err(|_| Error::LimitExceeded {
            limit_type: "map values",
            value: values_len,
            max: u32::MAX as usize,
        })?;

        // The offset of the first value immediately follows the length
        let next_value = de.position;

        // Validate the value segment length
        let values_end = next_value.checked_add(value_segment_len).ok_or(Error::UnexpectedEof)?;

        // Restore the deserializer state to the start of the key segment, if the map is non-empty
        de.restore(snapshot);

        Ok(Self {
            de,
            remaining: count,
            current_key,
            next_value,
            keys_end: value_segment_start,
            values_end,
        })
    }
}

impl<'de> de::MapAccess<'de> for MapAccess<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            log::trace!(target: "de", "finished deserializing map");
            return Ok(None);
        }
        self.remaining -= 1;

        log::trace!(target: "de", "deserialize next map key");

        // If we expect more keys, but we're already past the end of the keys segment, the file
        // is corrupted
        if self.de.position >= self.keys_end {
            return Err(Error::MapCorrupted);
        }

        let key = seed.deserialize(&mut *self.de).map(Some)?;
        self.current_key = self.de.position;

        // Similarly, if we finish deserializing a key and we've moved past the end of the keys
        // segment, the file is corrupted
        if self.de.position > self.keys_end {
            return Err(Error::MapCorrupted);
        }

        Ok(key)
    }

    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize next map value");

        // We need to snapshot the current deserializer and advance into the values segment
        let snapshot = self.de.snapshot();
        self.de.position = self.next_value;

        // If we expect more values, but we're already past the end of the values segment, the file
        // is corrupted
        if self.de.position >= self.values_end {
            return Err(Error::MapCorrupted);
        }

        let value = seed.deserialize(&mut *self.de)?;
        self.next_value = self.de.position;

        // Similarly, if we finish deserializing a value and we've moved past the end of the values
        // segment, the file is corrupted
        if self.de.position > self.values_end {
            return Err(Error::MapCorrupted);
        }

        // Restore the deserializer state to the next key, if present
        if self.remaining > 0 {
            self.de.restore(snapshot);
        }

        Ok(value)
    }
}

struct EnumAccess<'a, 'de> {
    de: &'a mut BiteDeserializer<'de>,
}

impl<'a, 'de> EnumAccess<'a, 'de> {
    fn new(de: &'a mut BiteDeserializer<'de>) -> Self {
        Self { de }
    }
}

impl<'de> de::EnumAccess<'de> for EnumAccess<'_, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        log::trace!(target: "de", "deserialize enum variant");
        self.de.expect_type_tags(&[
            Type::UnitVariant,
            Type::NewtypeVariant,
            Type::StructVariant,
            Type::TupleVariant,
        ])?;
        let val = seed.deserialize(&mut *self.de)?;
        Ok((val, self))
    }
}

impl<'de> de::VariantAccess<'de> for EnumAccess<'_, 'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        log::trace!(target: "de", "deserialize unit variant");
        Ok(())
    }

    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        log::trace!(target: "de", "deserialize newtype variant");
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: de::Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize tuple variant of len {len}");
        self.de.check_depth()?;
        let result = visitor.visit_seq(SeqAccess::new(&mut *self.de, len));
        self.de.exit_depth();
        result
    }

    fn struct_variant<V: de::Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        log::trace!(target: "de", "deserialize struct variant with {} fields", fields.len());
        self.de.check_depth()?;
        let result = visitor.visit_seq(SeqAccess::new(&mut *self.de, fields.len()));
        self.de.exit_depth();
        result
    }
}
