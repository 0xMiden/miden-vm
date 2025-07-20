use alloc::vec::Vec;

use serde::ser;

use super::{Error, MAGIC, Result, VERSION, varint};
use crate::Type;

/// Serialize `value` into a vector of BITE-encoded bytes
pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: ser::Serialize,
{
    let allocator = bumpalo::Bump::new();
    let mut serializer = BiteSerializer::new(&allocator);

    // Serialize data to temporary buffer
    value.serialize(&mut serializer)?;

    // Create output buffer with header, string table, and serialized data
    let capacity =
        serializer.output.len() + MAGIC.len() + 1 + 4 + serializer.strings.size_in_bytes();
    let mut output = Vec::with_capacity(capacity);

    // Magic
    output.extend_from_slice(MAGIC);

    // Version
    output.push(VERSION);

    // String table length
    log::trace!(target: "ser", "serializing string table with {} entries", serializer.strings.len());
    varint::encode(serializer.strings.len() as u64, &mut output);

    // String table
    if !serializer.strings.is_empty() {
        for (i, s) in serializer.strings.iter().enumerate() {
            log::trace!(target: "ser", "serializing string id {i}: '{s}'");
            varint::encode(s.len() as u64, &mut output);
            output.extend_from_slice(s.as_bytes());
        }
    }

    // Data
    output.append(&mut serializer.output);

    Ok(output)
}

/// Implements serialization of the Serde data model into BITE binary format
pub struct BiteSerializer<'a> {
    strings: StringTable<'a>,
    output: Vec<u8>,
}

impl<'a> BiteSerializer<'a> {
    pub fn new(allocator: &'a bumpalo::Bump) -> Self {
        Self {
            strings: StringTable::new(allocator),
            output: Vec::with_capacity(1024),
        }
    }

    #[inline]
    fn write_byte(&mut self, byte: u8) {
        self.output.push(byte);
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
    }

    #[inline]
    fn write_varint(&mut self, value: u64) {
        varint::encode(value, &mut self.output);
    }
}

// Implement serde::Serializer for CbfSerializer
impl<'a, 'alloc> ser::Serializer for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = SeqSerializer<'a, 'alloc>;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = MapSerializer<'a, 'alloc>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        log::trace!(target: "ser", "serializing bool: {v}");
        self.write_byte(if v { Type::True.tag() } else { Type::False.tag() });
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        log::trace!(target: "ser", "serializing i8: {v}");
        self.write_bytes(&[Type::I8.tag(), v as u8]);
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        log::trace!(target: "ser", "serializing i16: {v}");
        self.write_byte(Type::SInt.tag());
        self.write_varint(v as u16 as u64);
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        log::trace!(target: "ser", "serializing i32: {v}");
        self.write_byte(Type::SInt.tag());
        self.write_varint(v as u32 as u64);
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        log::trace!(target: "ser", "serializing i64: {v}");
        self.write_byte(Type::SInt.tag());
        self.write_varint(v as u64);
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        log::trace!(target: "ser", "serializing u8: {v}");
        self.write_bytes(&[Type::U8.tag(), v]);
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        log::trace!(target: "ser", "serializing u16: {v}");
        self.write_byte(Type::Int.tag());
        self.write_varint(v as u64);
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        log::trace!(target: "ser", "serializing u32: {v}");
        self.write_byte(Type::Int.tag());
        self.write_varint(v as u64);
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        log::trace!(target: "ser", "serializing u64: {v}");
        self.write_byte(Type::Int.tag());
        self.write_varint(v);
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        log::trace!(target: "ser", "serializing f32: {v}");
        self.write_byte(Type::F32.tag());
        self.write_bytes(&v.to_le_bytes());
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        log::trace!(target: "ser", "serializing f64: {v}");
        self.write_byte(Type::F64.tag());
        self.write_bytes(&v.to_le_bytes());
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        log::trace!(target: "ser", "serializing char: {v}");
        self.write_byte(Type::Char.tag());
        self.write_varint(v as u32 as u64);
        Ok(())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        log::trace!(target: "ser", "serializing string: {v}");
        let id = self.strings.add_string(v);
        log::trace!(target: "ser", "mapped string '{v}' to string id {}", id.to_index());
        self.write_byte(Type::Str.tag());
        self.write_varint(id.to_index() as u64);
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        log::trace!(target: "ser", "serializing {} bytes", v.len());
        self.write_byte(Type::Bytes.tag());
        self.write_varint(v.len() as u64);
        self.write_bytes(v);
        Ok(())
    }

    fn serialize_none(self) -> Result<()> {
        log::trace!(target: "ser", "serializing None");
        self.write_byte(Type::None.tag());
        Ok(())
    }

    fn serialize_some<T: ?Sized + ser::Serialize>(self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing Some");
        self.write_byte(Type::Some.tag());
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        log::trace!(target: "ser", "serializing unit");
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        log::trace!(target: "ser", "serializing unit struct '{_name}'");
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        log::trace!(target: "ser", "serializing unit variant '{_name}::{_variant}' (index {variant_index})");
        self.write_byte(Type::UnitVariant.tag());
        self.write_varint(variant_index as u64);
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + ser::Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()> {
        log::trace!(target: "ser", "serializing newtype struct '{_name}'");
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + ser::Serialize>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()> {
        log::trace!(target: "ser", "serializing newtype variant '{_name}::{_variant}' (index {variant_index})");
        self.write_byte(Type::NewtypeVariant.tag());
        self.write_varint(variant_index as u64);
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        log::trace!(target: "ser", "serializing sequence (len = {len:?})");
        Ok(SeqSerializer {
            ser: self,
            count: len,
            counted: 0,
            data: Vec::with_capacity(len.map(|len| len * 8).unwrap_or_default()),
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        log::trace!(target: "ser", "serializing tuple (len = {_len})");
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        log::trace!(target: "ser", "serializing tuple (len = {_len})");
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        log::trace!(target: "ser", "serializing tuple variant '{_name}::{_variant}' (index = {variant_index})");
        self.write_byte(Type::TupleVariant.tag());
        self.write_varint(variant_index as u64);
        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        log::trace!(target: "ser", "serializing map (len = {len:?})");
        let capacity = len.unwrap_or_default();
        Ok(MapSerializer {
            ser: self,
            count: len,
            counted: 0,
            keys: Vec::with_capacity(capacity),
            values: Vec::with_capacity(capacity),
        })
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        log::trace!(target: "ser", "serializing struct '{_name}'");
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        log::trace!(target: "ser", "serializing struct variant '{_name}::{_variant}' (index = {variant_index})");
        self.write_byte(Type::StructVariant.tag());
        self.write_varint(variant_index as u64);
        Ok(self)
    }
}

#[doc(hidden)]
pub struct SeqSerializer<'a, 'alloc> {
    ser: &'a mut BiteSerializer<'alloc>,
    count: Option<usize>,
    counted: usize,
    data: Vec<u8>,
}

impl<'a, 'alloc> ser::SerializeSeq for SeqSerializer<'a, 'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + ser::Serialize>(&mut self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing sequence element {}", self.counted + 1);
        value.serialize(&mut *self.ser)?;
        self.counted += 1;
        Ok(())
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing sequence");
        let count = core::cmp::max(self.counted, self.count.unwrap_or(self.counted));

        // Write the type tag first
        self.ser.write_byte(Type::Seq.tag());

        // Write the seq arity
        self.ser.write_varint(count as u64);

        // Empty sequences are serialized only as a count
        if count == 0 {
            return Ok(());
        }

        // Write all elements
        self.ser.write_varint(self.data.len() as u64);
        self.ser.write_bytes(&self.data);
        Ok(())
    }
}

#[doc(hidden)]
pub struct MapSerializer<'a, 'alloc> {
    ser: &'a mut BiteSerializer<'alloc>,
    count: Option<usize>,
    counted: usize,
    keys: Vec<u8>,
    values: Vec<u8>,
}

impl<'a, 'alloc> ser::SerializeMap for MapSerializer<'a, 'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: ?Sized + ser::Serialize>(&mut self, key: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing map key {}", self.counted + 1);
        let pos = self.ser.output.len();
        key.serialize(&mut *self.ser)?;
        self.keys.extend_from_slice(&self.ser.output[pos..]);
        self.ser.output.truncate(pos);
        self.counted += 1;
        Ok(())
    }

    fn serialize_value<T: ?Sized + ser::Serialize>(&mut self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing map value {}", self.counted);
        let pos = self.ser.output.len();
        value.serialize(&mut *self.ser)?;
        self.values.extend_from_slice(&self.ser.output[pos..]);
        self.ser.output.truncate(pos);
        Ok(())
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing map");
        let count = core::cmp::max(self.counted, self.count.unwrap_or(self.counted));

        // Write the type tag first
        self.ser.write_byte(Type::Map.tag());

        // Write the map arity
        self.ser.write_varint(count as u64);

        // Empty maps are serialized only as a count
        if count == 0 {
            return Ok(());
        }

        // Write all keys
        self.ser.write_varint(self.keys.len() as u64);
        self.ser.write_bytes(&self.keys);
        // Write all values
        self.ser.write_varint(self.values.len() as u64);
        self.ser.write_bytes(&self.values);
        Ok(())
    }
}

impl<'a, 'alloc> ser::SerializeTuple for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized + ser::Serialize>(&mut self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing tuple element");
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing tuple");
        Ok(())
    }
}

impl<'a, 'alloc> ser::SerializeTupleStruct for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + ser::Serialize>(&mut self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing tuple field");
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing tuple struct");
        Ok(())
    }
}

impl<'a, 'alloc> ser::SerializeTupleVariant for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + ser::Serialize>(&mut self, value: &T) -> Result<()> {
        log::trace!(target: "ser", "serializing tuple field");
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing tuple variant");
        Ok(())
    }
}

impl<'a, 'alloc> ser::SerializeStruct for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + ser::Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        log::trace!(target: "ser", "serializing struct field '{_key}'");
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing struct");
        Ok(())
    }
}

impl<'a, 'alloc> ser::SerializeStructVariant for &'a mut BiteSerializer<'alloc> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + ser::Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<()> {
        log::trace!(target: "ser", "serializing struct field '{_key}'");
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        log::trace!(target: "ser", "finished serializing struct variant");
        Ok(())
    }
}

/// A typed wrapper around an index value encoded as a u32
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct StringId(u32);

impl StringId {
    #[inline(always)]
    const fn to_index(self) -> usize {
        self.0 as usize
    }
}

/// The in-memory representation of the string table during serialization.
///
/// Strings are automatically de-duplicated during insertion, and ordered lexicographically.
struct StringTable<'a> {
    allocator: &'a bumpalo::Bump,
    #[cfg(feature = "std")]
    strings: indexmap::IndexSet<&'a str>,
    #[cfg(not(feature = "std"))]
    strings: indexmap::IndexSet<&'a str, rustc_hash::FxBuildHasher>,
}

impl<'a> StringTable<'a> {
    #[cfg(feature = "std")]
    fn new(allocator: &'a bumpalo::Bump) -> Self {
        Self { allocator, strings: Default::default() }
    }

    #[cfg(not(feature = "std"))]
    fn new(allocator: &'a bumpalo::Bump) -> Self {
        Self {
            allocator,
            strings: indexmap::IndexSet::with_hasher(rustc_hash::FxBuildHasher::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    pub fn size_in_bytes(&self) -> usize {
        self.strings.iter().map(|k| k.len()).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.strings.iter().copied()
    }

    /// Insert `s` into the string table, if not already present, and return the associated
    /// [StringId].
    ///
    /// The returned [StringId] represents the index of the string in the encoded strings table,
    /// which will be resolved to a `&str` during deserialization.
    pub fn add_string(&mut self, s: &str) -> StringId {
        if let Some(id) = self.strings.get_index_of(s) {
            return StringId(id as u32);
        }

        let id = StringId(self.strings.len() as u32);
        let s = self.allocator.alloc_str(s);
        self.strings.insert(s);
        debug_assert_eq!(id.to_index(), self.strings.get_index_of(s).unwrap());
        id
    }
}
