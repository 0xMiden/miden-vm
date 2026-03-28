//! A [Word] type used in the Miden protocol and associated utilities.

use alloc::{string::String, vec::Vec};
#[cfg(not(all(target_family = "wasm", miden)))]
use core::fmt::Display;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut, Index, IndexMut, Range},
    slice,
};

#[cfg(not(all(target_family = "wasm", miden)))]
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(not(all(target_family = "wasm", miden)))]
use p3_field::integers::QuotientMap;
use thiserror::Error;

use super::Felt;
use crate::utils::bytes_to_hex_string;

#[cfg(test)]
mod tests;

// WORD
// ================================================================================================

/// A unit of data consisting of 4 field elements.
///
/// For ordering a word with `Ord` the word's elements are treated as limbs of an integer
/// in little-endian limb order and thus comparison starts from the most significant element.
#[derive(Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(
    not(all(target_family = "wasm", miden)),
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(
    not(all(target_family = "wasm", miden)),
    serde(into = "String", try_from = "&str")
)]
#[repr(C)]
#[cfg_attr(all(target_family = "wasm", miden), repr(align(16)))]
pub struct Word {
    /// The underlying elements of this word.
    pub a: Felt,
    pub b: Felt,
    pub c: Felt,
    pub d: Felt,
    // The fields have to be public since the WIT->Rust bindings generation uses the fields
    // directly.
    // We cannot define this type as `Word([Felt;4])` since there is no struct tuple support
    // and fixed array support is not complete in WIT. For the type remapping to work the
    // bindings are expecting the remapped type to be the same shape as the one generated from
    // WIT.
    //
    // see sdk/base-macros/wit/miden.wit in the compiler repo, so we have to define it like that
    // here.
}

// Compile-time assertions to ensure `Word` has the same layout as `[Felt; 4]`. This is relied upon
// in `as_elements_array`/`as_elements_array_mut`.
const _: () = {
    assert!(Word::NUM_ELEMENTS == 4, "Word::NUM_ELEMENTS is assumed to be 4");
    assert!(Word::SERIALIZED_SIZE == 32, "Word::SERIALIZED_SIZE is assumed to be 32");
    assert!(core::mem::size_of::<Word>() == Word::NUM_ELEMENTS * core::mem::size_of::<Felt>());
    assert!(core::mem::offset_of!(Word, a) == 0);
    assert!(core::mem::offset_of!(Word, b) == core::mem::size_of::<Felt>());
    assert!(core::mem::offset_of!(Word, c) == 2 * core::mem::size_of::<Felt>());
    assert!(core::mem::offset_of!(Word, d) == 3 * core::mem::size_of::<Felt>());
};

impl core::fmt::Debug for Word {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Word").field(&self.into_elements()).finish()
    }
}

impl Word {
    /// The number of field elements in the word.
    pub const NUM_ELEMENTS: usize = 4;

    /// The serialized size of the word in bytes.
    pub const SERIALIZED_SIZE: usize = 32;

    /// Creates a new [`Word`] from the given field elements.
    pub const fn new(value: [Felt; Self::NUM_ELEMENTS]) -> Self {
        let [a, b, c, d] = value;
        Self { a, b, c, d }
    }

    /// Returns the elements of this word as an array.
    pub const fn into_elements(self) -> [Felt; Self::NUM_ELEMENTS] {
        [self.a, self.b, self.c, self.d]
    }

    /// Returns the elements of this word as an array reference.
    ///
    /// # Safety
    /// This assumes the four fields of [`Word`] are laid out contiguously with no padding, in
    /// the same order as `[Felt; 4]`.
    fn as_elements_array(&self) -> &[Felt; Self::NUM_ELEMENTS] {
        unsafe { &*(&self.a as *const Felt as *const [Felt; Self::NUM_ELEMENTS]) }
    }

    /// Returns the elements of this word as a mutable array reference.
    ///
    /// # Safety
    /// This assumes the four fields of [`Word`] are laid out contiguously with no padding, in
    /// the same order as `[Felt; 4]`.
    fn as_elements_array_mut(&mut self) -> &mut [Felt; Self::NUM_ELEMENTS] {
        unsafe { &mut *(&mut self.a as *mut Felt as *mut [Felt; Self::NUM_ELEMENTS]) }
    }

    /// Parses a hex string into a new [`Word`].
    ///
    /// The input must contain valid hex prefixed with `0x`. The input after the prefix
    /// must contain between 0 and 64 characters (inclusive).
    ///
    /// The input is interpreted to have little-endian byte ordering. Nibbles are interpreted
    /// to have big-endian ordering so that "0x10" represents Felt::new(16), not Felt::new(1).
    ///
    /// This function is usually used via the `word!` macro.
    ///
    /// ```
    /// use miden_field::{Felt, Word, word};
    /// let word = word!("0x1000000000000000200000000000000030000000000000004000000000000000");
    /// assert_eq!(word, Word::new([Felt::new(16), Felt::new(32), Felt::new(48), Felt::new(64)]));
    /// ```
    #[cfg(not(all(target_family = "wasm", miden)))]
    pub const fn parse(hex: &str) -> Result<Self, &'static str> {
        const fn parse_hex_digit(digit: u8) -> Result<u8, &'static str> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'A'..=b'F' => Ok(digit - b'A' + 0x0a),
                b'a'..=b'f' => Ok(digit - b'a' + 0x0a),
                _ => Err("Invalid hex character"),
            }
        }
        // Enforce and skip the '0x' prefix.
        let hex_bytes = match hex.as_bytes() {
            [b'0', b'x', rest @ ..] => rest,
            _ => return Err("Hex string must have a \"0x\" prefix"),
        };

        if hex_bytes.len() > 64 {
            return Err("Hex string has more than 64 characters");
        }

        let mut felts = [0u64; 4];
        let mut i = 0;
        while i < hex_bytes.len() {
            let hex_digit = match parse_hex_digit(hex_bytes[i]) {
                // SAFETY: u8 cast to u64 is safe. We cannot use u64::from in const context so we
                // are forced to cast.
                Ok(v) => v as u64,
                Err(e) => return Err(e),
            };

            // This digit's nibble offset within the felt. We need to invert the nibbles per
            // byte to ensure little-endian ordering i.e. ABCD -> BADC.
            let inibble = if i.is_multiple_of(2) {
                (i + 1) % 16
            } else {
                (i - 1) % 16
            };

            let value = hex_digit << (inibble * 4);
            felts[i / 2 / 8] += value;

            i += 1;
        }

        // Ensure each felt is within bounds as `Felt::new` silently wraps around.
        // This matches the behavior of `Word::try_from(String)`.
        let mut idx = 0;
        while idx < felts.len() {
            if felts[idx] >= Felt::ORDER {
                return Err("Felt overflow");
            }
            idx += 1;
        }

        Ok(Self::new([
            Felt::new(felts[0]),
            Felt::new(felts[1]),
            Felt::new(felts[2]),
            Felt::new(felts[3]),
        ]))
    }

    /// Returns a new [Word] consisting of four ZERO elements.
    pub const fn empty() -> Self {
        Self::new([Felt::ZERO; Self::NUM_ELEMENTS])
    }

    /// Returns true if the word consists of four ZERO elements.
    pub fn is_empty(&self) -> bool {
        let elements = self.as_elements_array();
        elements[0] == Felt::ZERO
            && elements[1] == Felt::ZERO
            && elements[2] == Felt::ZERO
            && elements[3] == Felt::ZERO
    }

    /// Returns the word as a slice of field elements.
    pub fn as_elements(&self) -> &[Felt] {
        self.as_elements_array()
    }

    /// Returns the word as a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut result = [0; Self::SERIALIZED_SIZE];

        let elements = self.as_elements_array();
        result[..8].copy_from_slice(&elements[0].as_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&elements[1].as_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&elements[2].as_canonical_u64().to_le_bytes());
        result[24..].copy_from_slice(&elements[3].as_canonical_u64().to_le_bytes());

        result
    }

    /// Returns an iterator over the elements of multiple words.
    pub fn words_as_elements_iter<'a, I>(words: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        words.flat_map(|d| d.as_elements().iter())
    }

    /// Returns all elements of multiple words as a slice.
    pub fn words_as_elements(words: &[Self]) -> &[Felt] {
        let len = words.len() * Self::NUM_ELEMENTS;
        unsafe { slice::from_raw_parts(words.as_ptr() as *const Felt, len) }
    }

    /// Returns hexadecimal representation of this word prefixed with `0x`.
    pub fn to_hex(&self) -> String {
        bytes_to_hex_string(self.as_bytes())
    }

    /// Returns internal elements of this word as a vector.
    pub fn to_vec(&self) -> Vec<Felt> {
        self.as_elements().to_vec()
    }

    /// Returns a copy of this word with its elements in reverse order.
    pub fn reversed(&self) -> Self {
        Word {
            a: self.d,
            b: self.c,
            c: self.b,
            d: self.a,
        }
    }
}

impl Hash for Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.as_bytes());
    }
}

impl Deref for Word {
    type Target = [Felt; Word::NUM_ELEMENTS];

    fn deref(&self) -> &Self::Target {
        self.as_elements_array()
    }
}

impl DerefMut for Word {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_elements_array_mut()
    }
}

impl Index<usize> for Word {
    type Output = Felt;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_elements_array()[index]
    }
}

impl IndexMut<usize> for Word {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_elements_array_mut()[index]
    }
}

impl Index<Range<usize>> for Word {
    type Output = [Felt];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.as_elements_array()[index]
    }
}

impl IndexMut<Range<usize>> for Word {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        &mut self.as_elements_array_mut()[index]
    }
}

impl Ord for Word {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare the canonical u64 representation of both words.
        //
        // It will iterate the elements in reverse and will return the first computation different
        // than `Equal`. Otherwise, the ordering is equal.
        //
        // We use `as_canonical_u64()` to ensure we're comparing the actual field element values
        // in their canonical form (that is, `x in [0,p)`). P3's Goldilocks field uses unreduced
        // representation (not Montgomery form), meaning internal values may be in [0, 2^64) even
        // though the field order is p = 2^64 - 2^32 + 1. This method canonicalizes to [0, p).
        //
        // We must iterate over and compare each element individually. A simple bytestring
        // comparison would be inappropriate because `Word`s internal representation is not
        // naturally lexicographically comparable.
        for (felt0, felt1) in self
            .iter()
            .rev()
            .map(Felt::as_canonical_u64)
            .zip(other.iter().rev().map(Felt::as_canonical_u64))
        {
            let ordering = felt0.cmp(&felt1);
            if let Ordering::Less | Ordering::Greater = ordering {
                return ordering;
            }
        }

        Ordering::Equal
    }
}

impl PartialOrd for Word {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl Display for Word {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// CONVERSIONS: FROM WORD
// ================================================================================================

/// Errors that can occur when working with a [Word].
#[derive(Debug, Error)]
pub enum WordError {
    /// Hex-encoded field elements parsed are invalid.
    #[error("hex encoded values of a word are invalid")]
    HexParse(#[from] crate::utils::HexParseError),
    /// Field element conversion failed due to invalid value.
    #[error("failed to convert to field element: {0}")]
    InvalidFieldElement(String),
    /// Failed to convert a slice to an array of expected length.
    #[error("invalid input length: expected {1} {0}, but received {2}")]
    InvalidInputLength(&'static str, usize, usize),
    /// Failed to convert the word's field elements to the specified type.
    #[error("failed to convert the word's field elements to type {0}")]
    TypeConversion(&'static str),
}

impl TryFrom<&Word> for [bool; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [bool; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        fn to_bool(v: u64) -> Option<bool> {
            if v <= 1 { Some(v == 1) } else { None }
        }

        let [a, b, c, d] = value.into_elements();
        Ok([
            to_bool(a.as_canonical_u64()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(b.as_canonical_u64()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(c.as_canonical_u64()).ok_or(WordError::TypeConversion("bool"))?,
            to_bool(d.as_canonical_u64()).ok_or(WordError::TypeConversion("bool"))?,
        ])
    }
}

impl TryFrom<&Word> for [u8; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u8; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        let [a, b, c, d] = value.into_elements();
        Ok([
            a.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            b.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            c.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
            d.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u8"))?,
        ])
    }
}

impl TryFrom<&Word> for [u16; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u16; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        let [a, b, c, d] = value.into_elements();
        Ok([
            a.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            b.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            c.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
            d.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u16"))?,
        ])
    }
}

impl TryFrom<&Word> for [u32; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: &Word) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<Word> for [u32; Word::NUM_ELEMENTS] {
    type Error = WordError;

    fn try_from(value: Word) -> Result<Self, Self::Error> {
        let [a, b, c, d] = value.into_elements();
        Ok([
            a.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            b.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            c.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
            d.as_canonical_u64().try_into().map_err(|_| WordError::TypeConversion("u32"))?,
        ])
    }
}

impl From<&Word> for [u64; Word::NUM_ELEMENTS] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [u64; Word::NUM_ELEMENTS] {
    fn from(value: Word) -> Self {
        value.into_elements().map(|felt| felt.as_canonical_u64())
    }
}

impl From<&Word> for [Felt; Word::NUM_ELEMENTS] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [Felt; Word::NUM_ELEMENTS] {
    fn from(value: Word) -> Self {
        value.into_elements()
    }
}

impl From<&Word> for [u8; Word::SERIALIZED_SIZE] {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<Word> for [u8; Word::SERIALIZED_SIZE] {
    fn from(value: Word) -> Self {
        value.as_bytes()
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl From<&Word> for String {
    /// The returned string starts with `0x`.
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl From<Word> for String {
    /// The returned string starts with `0x`.
    fn from(value: Word) -> Self {
        value.to_hex()
    }
}

// CONVERSIONS: TO WORD
// ================================================================================================

impl From<&[bool; Word::NUM_ELEMENTS]> for Word {
    fn from(value: &[bool; Word::NUM_ELEMENTS]) -> Self {
        (*value).into()
    }
}

impl From<[bool; Word::NUM_ELEMENTS]> for Word {
    fn from(value: [bool; Word::NUM_ELEMENTS]) -> Self {
        [value[0] as u32, value[1] as u32, value[2] as u32, value[3] as u32].into()
    }
}

impl From<&[u8; Word::NUM_ELEMENTS]> for Word {
    fn from(value: &[u8; Word::NUM_ELEMENTS]) -> Self {
        (*value).into()
    }
}

impl From<[u8; Word::NUM_ELEMENTS]> for Word {
    fn from(value: [u8; Word::NUM_ELEMENTS]) -> Self {
        Self::new([
            Felt::from_u8(value[0]),
            Felt::from_u8(value[1]),
            Felt::from_u8(value[2]),
            Felt::from_u8(value[3]),
        ])
    }
}

impl From<&[u16; Word::NUM_ELEMENTS]> for Word {
    fn from(value: &[u16; Word::NUM_ELEMENTS]) -> Self {
        (*value).into()
    }
}

impl From<[u16; Word::NUM_ELEMENTS]> for Word {
    fn from(value: [u16; Word::NUM_ELEMENTS]) -> Self {
        Self::new([
            Felt::from_u16(value[0]),
            Felt::from_u16(value[1]),
            Felt::from_u16(value[2]),
            Felt::from_u16(value[3]),
        ])
    }
}

impl From<&[u32; Word::NUM_ELEMENTS]> for Word {
    fn from(value: &[u32; Word::NUM_ELEMENTS]) -> Self {
        (*value).into()
    }
}

impl From<[u32; Word::NUM_ELEMENTS]> for Word {
    fn from(value: [u32; Word::NUM_ELEMENTS]) -> Self {
        Self::new([
            Felt::from_u32(value[0]),
            Felt::from_u32(value[1]),
            Felt::from_u32(value[2]),
            Felt::from_u32(value[3]),
        ])
    }
}

impl TryFrom<&[u64; Word::NUM_ELEMENTS]> for Word {
    type Error = WordError;

    fn try_from(value: &[u64; Word::NUM_ELEMENTS]) -> Result<Self, WordError> {
        (*value).try_into()
    }
}

impl TryFrom<[u64; Word::NUM_ELEMENTS]> for Word {
    type Error = WordError;

    fn try_from(value: [u64; Word::NUM_ELEMENTS]) -> Result<Self, WordError> {
        let err = || WordError::InvalidFieldElement("value >= field modulus".into());
        Ok(Self::new([
            Felt::from_canonical_checked(value[0]).ok_or_else(err)?,
            Felt::from_canonical_checked(value[1]).ok_or_else(err)?,
            Felt::from_canonical_checked(value[2]).ok_or_else(err)?,
            Felt::from_canonical_checked(value[3]).ok_or_else(err)?,
        ]))
    }
}

impl From<&[Felt; Word::NUM_ELEMENTS]> for Word {
    fn from(value: &[Felt; Word::NUM_ELEMENTS]) -> Self {
        Self::new(*value)
    }
}

impl From<[Felt; Word::NUM_ELEMENTS]> for Word {
    fn from(value: [Felt; Word::NUM_ELEMENTS]) -> Self {
        Self::new(value)
    }
}

impl TryFrom<&[u8; Word::SERIALIZED_SIZE]> for Word {
    type Error = WordError;

    fn try_from(value: &[u8; Word::SERIALIZED_SIZE]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<[u8; Word::SERIALIZED_SIZE]> for Word {
    type Error = WordError;

    fn try_from(value: [u8; Word::SERIALIZED_SIZE]) -> Result<Self, Self::Error> {
        // Note: the input length is known, the conversion from slice to array must succeed so the
        // `unwrap`s below are safe
        let a = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let c = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let d = u64::from_le_bytes(value[24..32].try_into().unwrap());

        let err = || WordError::InvalidFieldElement("value >= field modulus".into());
        let a: Felt = Felt::from_canonical_checked(a).ok_or_else(err)?;
        let b: Felt = Felt::from_canonical_checked(b).ok_or_else(err)?;
        let c: Felt = Felt::from_canonical_checked(c).ok_or_else(err)?;
        let d: Felt = Felt::from_canonical_checked(d).ok_or_else(err)?;

        Ok(Self::new([a, b, c, d]))
    }
}

impl TryFrom<&[u8]> for Word {
    type Error = WordError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; Word::SERIALIZED_SIZE] = value.try_into().map_err(|_| {
            WordError::InvalidInputLength("bytes", Word::SERIALIZED_SIZE, value.len())
        })?;
        value.try_into()
    }
}

impl TryFrom<&[Felt]> for Word {
    type Error = WordError;

    fn try_from(value: &[Felt]) -> Result<Self, Self::Error> {
        let value: [Felt; Word::NUM_ELEMENTS] = value.try_into().map_err(|_| {
            WordError::InvalidInputLength("elements", Word::NUM_ELEMENTS, value.len())
        })?;
        Ok(value.into())
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl TryFrom<&str> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        crate::utils::hex_to_bytes::<{ Word::SERIALIZED_SIZE }>(value)
            .map_err(WordError::HexParse)
            .and_then(Word::try_from)
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl TryFrom<String> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl TryFrom<&String> for Word {
    type Error = WordError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

#[cfg(not(all(target_family = "wasm", miden)))]
impl Serializable for Word {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

#[cfg(not(all(target_family = "wasm", miden)))]
impl Deserializable for Word {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut inner: [Felt; Word::NUM_ELEMENTS] = [Felt::ZERO; Word::NUM_ELEMENTS];
        for inner in inner.iter_mut() {
            let e = source.read_u64()?;
            if e >= Felt::ORDER {
                return Err(DeserializationError::InvalidValue(String::from(
                    "value not in the appropriate range",
                )));
            }
            *inner = Felt::new(e);
        }

        Ok(Self::new(inner))
    }

    fn min_serialized_size() -> usize {
        Self::SERIALIZED_SIZE
    }
}

// ITERATORS
// ================================================================================================
impl IntoIterator for Word {
    type Item = Felt;
    type IntoIter = <[Felt; 4] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.into_elements().into_iter()
    }
}

// MACROS
// ================================================================================================

/// Construct a new [Word](super::Word) from a hex value.
///
/// Expects a '0x' prefixed hex string followed by up to 64 hex digits.
#[cfg(not(all(target_family = "wasm", miden)))]
#[macro_export]
macro_rules! word {
    ($hex:expr) => {{
        let word: Word = match $crate::word::Word::parse($hex) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        word
    }};
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(all(any(test, feature = "testing"), not(all(target_family = "wasm", miden))))]
mod arbitrary {
    use proptest::prelude::*;

    use super::{Felt, Word};

    impl Arbitrary for Word {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop::array::uniform4(any::<Felt>()).prop_map(Word::new).no_shrink().boxed()
        }
    }
}
