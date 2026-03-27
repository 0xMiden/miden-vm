// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec::Vec,
};

// ERROR
// ================================================================================================

/// Defines errors which can occur during deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeserializationError {
    /// Indicates that the deserialization failed because of insufficient data.
    UnexpectedEOF,
    /// Indicates that the deserialization failed because the value was not valid.
    InvalidValue(String),
    /// Indicates that deserialization failed for an unknown reason.
    UnknownError(String),
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializationError {}

impl core::fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEOF => write!(f, "unexpected end of file"),
            Self::InvalidValue(msg) => write!(f, "invalid value: {}", msg),
            Self::UnknownError(msg) => write!(f, "unknown error: {}", msg),
        }
    }
}

mod byte_reader;
#[cfg(feature = "std")]
pub use byte_reader::ReadAdapter;
pub use byte_reader::{BudgetedReader, ByteReader, ReadManyIter, SliceReader};

mod byte_writer;
pub use byte_writer::ByteWriter;

// SERIALIZABLE TRAIT
// ================================================================================================

/// Defines how to serialize `Self` into bytes.
pub trait Serializable {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------
    /// Serializes `self` into bytes and writes these bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Serializes `self` into a vector of bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.get_size_hint());
        self.write_into(&mut result);
        result
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    ///
    /// The default implementation returns zero.
    fn get_size_hint(&self) -> usize {
        0
    }
}

impl<T: Serializable> Serializable for &T {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        (*self).write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        (*self).get_size_hint()
    }
}

impl Serializable for () {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {}

    fn get_size_hint(&self) -> usize {
        0
    }
}

impl<T1> Serializable for (T1,)
where
    T1: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl<T1, T2> Serializable for (T1, T2)
where
    T1: Serializable,
    T2: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint()
    }
}

impl<T1, T2, T3> Serializable for (T1, T2, T3)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint() + self.2.get_size_hint()
    }
}

impl<T1, T2, T3, T4> Serializable for (T1, T2, T3, T4)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
    }
}

impl<T1, T2, T3, T4, T5> Serializable for (T1, T2, T3, T4, T5)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
    T5: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
        self.4.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
    }
}

impl<T1, T2, T3, T4, T5, T6> Serializable for (T1, T2, T3, T4, T5, T6)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
    T5: Serializable,
    T6: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
        self.4.write_into(target);
        self.5.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
            + self.5.get_size_hint()
    }
}

impl Serializable for u8 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl Serializable for u16 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl Serializable for u32 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl Serializable for u64 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Serializable for u128 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u128(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u128>()
    }
}

impl Serializable for usize {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(*self)
    }

    fn get_size_hint(&self) -> usize {
        byte_writer::usize_encoded_len(*self as u64)
    }
}

impl<T: Serializable> Serializable for Option<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Some(v) => {
                target.write_bool(true);
                v.write_into(target);
            },
            None => target.write_bool(false),
        }
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<bool>() + self.as_ref().map(|value| value.get_size_hint()).unwrap_or(0)
    }
}

impl<T: Serializable, const C: usize> Serializable for [T; C] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_many(self)
    }

    fn get_size_hint(&self) -> usize {
        let mut size = 0;
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for [T] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        for element in self.iter() {
            element.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for element in self {
            size += element.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<K: Serializable, V: Serializable> Serializable for BTreeMap<K, V> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for BTreeSet<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl Serializable for str {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        self.len().get_size_hint() + self.len()
    }
}

impl Serializable for String {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_str().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.as_str().get_size_hint()
    }
}

impl Serializable for Arc<str> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_ref().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.as_ref().get_size_hint()
    }
}

// DESERIALIZABLE
// ================================================================================================

/// Defines how to deserialize `Self` from bytes.
pub trait Deserializable: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Reads a sequence of bytes from the provided `source`, attempts to deserialize these bytes
    /// into `Self`, and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The `source` does not contain enough bytes to deserialize `Self`.
    /// * Bytes read from the `source` do not represent a valid value for `Self`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError>;

    /// Returns the minimum serialized size for one instance of this type.
    ///
    /// This is used by [`ByteReader::max_alloc`] to estimate how many elements can be
    /// deserialized from the remaining budget, preventing denial-of-service attacks from
    /// malicious length prefixes.
    ///
    /// The default implementation returns `size_of::<Self>()`, which is conservative: it may
    /// reject valid input for types where the serialized size is smaller than the in-memory
    /// size (e.g., structs with computed/cached fields that aren't serialized).
    ///
    /// Override this method for types where the serialized representation is smaller than
    /// the in-memory representation to allow more elements to be deserialized.
    fn min_serialized_size() -> usize {
        core::mem::size_of::<Self>()
    }

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Attempts to deserialize the provided `bytes` into `Self` and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The `bytes` do not contain enough information to deserialize `Self`.
    /// * The `bytes` do not represent a valid value for `Self`.
    ///
    /// Note: if `bytes` contains more data than needed to deserialize `self`, no error is
    /// returned.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from(&mut SliceReader::new(bytes))
    }

    /// Deserializes `Self` from bytes with a byte budget limit.
    ///
    /// This is the recommended method for deserializing untrusted input. The budget limits
    /// how many bytes can be consumed during deserialization, preventing denial-of-service
    /// attacks that exploit length fields to cause huge allocations.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The budget is exhausted before deserialization completes.
    /// * The `bytes` do not contain enough information to deserialize `Self`.
    /// * The `bytes` do not represent a valid value for `Self`.
    fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, DeserializationError> {
        Self::read_from(&mut BudgetedReader::new(SliceReader::new(bytes), budget))
    }
}

impl Deserializable for () {
    fn read_from<R: ByteReader>(_source: &mut R) -> Result<Self, DeserializationError> {
        Ok(())
    }
}

impl<T1> Deserializable for (T1,)
where
    T1: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        Ok((v1,))
    }
}

impl<T1, T2> Deserializable for (T1, T2)
where
    T1: Deserializable,
    T2: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        Ok((v1, v2))
    }

    fn min_serialized_size() -> usize {
        T1::min_serialized_size().saturating_add(T2::min_serialized_size())
    }
}

impl<T1, T2, T3> Deserializable for (T1, T2, T3)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        Ok((v1, v2, v3))
    }

    fn min_serialized_size() -> usize {
        T1::min_serialized_size()
            .saturating_add(T2::min_serialized_size())
            .saturating_add(T3::min_serialized_size())
    }
}

impl<T1, T2, T3, T4> Deserializable for (T1, T2, T3, T4)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        Ok((v1, v2, v3, v4))
    }

    fn min_serialized_size() -> usize {
        T1::min_serialized_size()
            .saturating_add(T2::min_serialized_size())
            .saturating_add(T3::min_serialized_size())
            .saturating_add(T4::min_serialized_size())
    }
}

impl<T1, T2, T3, T4, T5> Deserializable for (T1, T2, T3, T4, T5)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
    T5: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        let v5 = T5::read_from(source)?;
        Ok((v1, v2, v3, v4, v5))
    }

    fn min_serialized_size() -> usize {
        T1::min_serialized_size()
            .saturating_add(T2::min_serialized_size())
            .saturating_add(T3::min_serialized_size())
            .saturating_add(T4::min_serialized_size())
            .saturating_add(T5::min_serialized_size())
    }
}

impl<T1, T2, T3, T4, T5, T6> Deserializable for (T1, T2, T3, T4, T5, T6)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
    T5: Deserializable,
    T6: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        let v5 = T5::read_from(source)?;
        let v6 = T6::read_from(source)?;
        Ok((v1, v2, v3, v4, v5, v6))
    }

    fn min_serialized_size() -> usize {
        T1::min_serialized_size()
            .saturating_add(T2::min_serialized_size())
            .saturating_add(T3::min_serialized_size())
            .saturating_add(T4::min_serialized_size())
            .saturating_add(T5::min_serialized_size())
            .saturating_add(T6::min_serialized_size())
    }
}

impl Deserializable for u8 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u8()
    }
}

impl Deserializable for u16 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u16()
    }
}

impl Deserializable for u32 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u32()
    }
}

impl Deserializable for u64 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u64()
    }
}

impl Deserializable for u128 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u128()
    }
}

impl Deserializable for usize {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_usize()
    }

    fn min_serialized_size() -> usize {
        1 // vint64 encoding: minimum 1 byte for values 0-127
    }
}

impl<T: Deserializable> Deserializable for Option<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_bool()? {
            Ok(Some(T::read_from(source)?))
        } else {
            Ok(None)
        }
    }

    /// Returns 1 (just the bool discriminator).
    ///
    /// The `Some` variant would be `1 + T::min_serialized_size()`, but we use the minimum
    /// to allow more elements through the early check.
    fn min_serialized_size() -> usize {
        1
    }
}

impl<T: Deserializable, const C: usize> Deserializable for [T; C] {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let data: Vec<T> = source.read_many_iter(C)?.collect::<Result<_, _>>()?;

        // The iterator yields exactly C elements (or fails early), so this always succeeds
        Ok(data.try_into().unwrap_or_else(|v: Vec<T>| {
            panic!("Expected a Vec of length {} but it was {}", C, v.len())
        }))
    }

    fn min_serialized_size() -> usize {
        C.saturating_mul(T::min_serialized_size())
    }
}

impl<T: Deserializable> Deserializable for Vec<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        source.read_many_iter(len)?.collect()
    }

    /// Returns 1 (the minimum vint length prefix size).
    ///
    /// The actual serialized size depends on the number of elements, which we don't know
    /// at the point this is called. Using the minimum allows more elements through the
    /// early check; budget enforcement during actual reads provides the real protection.
    fn min_serialized_size() -> usize {
        1
    }
}

impl<K: Deserializable + Ord, V: Deserializable> Deserializable for BTreeMap<K, V> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        source.read_many_iter(len)?.collect()
    }

    fn min_serialized_size() -> usize {
        1 // minimum vint length prefix
    }
}

impl<T: Deserializable + Ord> Deserializable for BTreeSet<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        source.read_many_iter(len)?.collect()
    }

    fn min_serialized_size() -> usize {
        1 // minimum vint length prefix
    }
}

impl Deserializable for String {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        let data: Vec<u8> = source.read_many_iter(len)?.collect::<Result<_, _>>()?;

        String::from_utf8(data).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }

    fn min_serialized_size() -> usize {
        1 // minimum vint length prefix
    }
}

impl Deserializable for Arc<str> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        String::read_from(source).map(Arc::from)
    }

    fn min_serialized_size() -> usize {
        1 // minimum vint length prefix
    }
}

// GOLDILOCKS FIELD ELEMENT IMPLEMENTATIONS
// ================================================================================================

impl Serializable for p3_goldilocks::Goldilocks {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        use p3_field::PrimeField64;
        target.write_u64(self.as_canonical_u64());
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Deserializable for p3_goldilocks::Goldilocks {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use p3_field::integers::QuotientMap;

        let value = source.read_u64()?;
        Self::from_canonical_checked(value).ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "value {} is not a valid Goldilocks field element",
                value
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn arc_str_roundtrip() {
        let original: Arc<str> = Arc::from("hello world");
        let bytes = original.to_bytes();
        let deserialized = Arc::<str>::read_from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn string_roundtrip() {
        let original = String::from("hello world");
        let bytes = original.to_bytes();
        let deserialized = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn empty_string_roundtrip() {
        let arc: Arc<str> = Arc::from("");
        let bytes = arc.to_bytes();
        let deserialized = Arc::<str>::read_from_bytes(&bytes).unwrap();
        assert_eq!(deserialized, Arc::from(""));

        let string = String::from("");
        let bytes = string.to_bytes();
        let deserialized = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(deserialized, "");
    }

    #[test]
    fn multibyte_utf8_roundtrip() {
        let text = "héllo 🌍";

        let arc: Arc<str> = Arc::from(text);
        let bytes = arc.to_bytes();
        let deserialized = Arc::<str>::read_from_bytes(&bytes).unwrap();
        assert_eq!(&*deserialized, text);

        let string = String::from(text);
        let bytes = string.to_bytes();
        let deserialized = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(deserialized, text);

        // Cross-compat: Arc<str> bytes can be read as String and vice versa
        let arc_bytes = Arc::<str>::from(text).to_bytes();
        let string_bytes = String::from(text).to_bytes();
        assert_eq!(arc_bytes, string_bytes);
        assert_eq!(String::read_from_bytes(&arc_bytes).unwrap(), text);
        assert_eq!(&*Arc::<str>::read_from_bytes(&string_bytes).unwrap(), text);
    }

    #[test]
    fn arc_str_string_cross_compat() {
        // Arc<str> -> bytes -> String
        let arc: Arc<str> = Arc::from("cross type");
        let bytes = arc.to_bytes();
        let as_string = String::read_from_bytes(&bytes).unwrap();
        assert_eq!(as_string, "cross type");

        // String -> bytes -> Arc<str>
        let string = String::from("other direction");
        let bytes = string.to_bytes();
        let as_arc = Arc::<str>::read_from_bytes(&bytes).unwrap();
        assert_eq!(&*as_arc, "other direction");
    }
}
