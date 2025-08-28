#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

mod de;
mod ser;
#[cfg(test)]
mod tests;
mod varint;

use alloc::string::{String, ToString};
use core::fmt;

use smallvec::SmallVec;

pub use self::{
    de::{from_bytes, from_bytes_with_limits},
    ser::to_bytes,
};

/// The magic byte sequence used to identify BITE-encoded byte streams
const MAGIC: &[u8] = b"BITE\0";

/// The current BITE version identifier
const VERSION: u8 = 1;

pub type Result<T> = core::result::Result<T, Error>;

/// Errors which can occur during serialization/deserialization
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid magic number")]
    InvalidMagic,
    #[error("invalid version number: expected {VERSION}, got {0}")]
    InvalidVersion(u8),
    #[error("unexpected end of file")]
    UnexpectedEof,
    #[error("corrupted string table")]
    StringTableCorrupted,
    #[error("corrupted map")]
    MapCorrupted,
    #[error("limit exceeded: {limit_type} limit of {value} exceeds {max}")]
    LimitExceeded {
        limit_type: &'static str,
        value: u64,
        max: usize,
    },
    #[error("invalid type tag: {0} is not a recognized type tag")]
    InvalidTypeTag(u8),
    #[error("unexpected type: expected {}, got {actual}", format_csv(expected))]
    UnexpectedType {
        actual: Type,
        expected: SmallVec<[Type; 1]>,
    },
    #[error("invalid index into string table: {0} is out of bounds")]
    InvalidStringId(usize),
    #[error("invalid variable-length encoded integer: must be 64-bits or less")]
    InvalidVarint,
    #[error("invalid utf-8 string: {0}")]
    InvalidUtf8(#[from] core::str::Utf8Error),
    #[error("invalid utf-8 grapheme/codepoint")]
    InvalidUtf8Char,
    #[error("unrecognized enum variant: {0}")]
    InvalidEnumVariant(u32),
    #[error("{0}")]
    Custom(String),
}

fn format_csv<T: fmt::Display>(values: &[T]) -> String {
    use core::fmt::Write;

    let mut csv = String::new();
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            csv.push_str(", ");
        }
        write!(&mut csv, "{value}").unwrap();
    }
    csv
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Custom(msg.to_string())
    }
}

/// Configurable limits to impose during serialization/deserialization
#[derive(Debug, Clone)]
pub struct Limits {
    /// The maximum number of bytes in a string
    pub max_string_length: usize,
    /// The maximum number of elements in a sequence
    pub max_sequence_length: usize,
    /// The maximum number of entries in a map
    pub max_map_entries: usize,
    /// The maximum depth of the object tree
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        const DEFAULT_LIMIT: usize = u32::MAX as usize;
        Self {
            max_string_length: DEFAULT_LIMIT,
            max_sequence_length: DEFAULT_LIMIT,
            max_map_entries: DEFAULT_LIMIT,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    False = 0,
    True = 1,
    None = 2,
    Some = 3,
    Int = 4,
    SInt = 5,
    I8 = 6,
    U8 = 7,
    F32 = 8,
    F64 = 9,
    Char = 10,
    Bytes = 11,
    Str = 12,
    Seq = 13,
    Map = 14,
    UnitVariant = 15,
    NewtypeVariant = 16,
    StructVariant = 17,
    TupleVariant = 18,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::False | Self::True => f.write_str("bool"),
            Self::None | Self::Some => f.write_str("option"),
            Self::Int => f.write_str("unsigned variable-length integer"),
            Self::SInt => f.write_str("signed variable-length integer"),
            Self::I8 => f.write_str("i8"),
            Self::U8 => f.write_str("u8"),
            Self::F32 => f.write_str("f32"),
            Self::F64 => f.write_str("f64"),
            Self::Char => f.write_str("char"),
            Self::Bytes => f.write_str("bytes"),
            Self::Str => f.write_str("string"),
            Self::Seq => f.write_str("sequence"),
            Self::Map => f.write_str("map"),
            Self::UnitVariant => f.write_str("unit variant"),
            Self::NewtypeVariant => f.write_str("newtype variant"),
            Self::StructVariant => f.write_str("struct variant"),
            Self::TupleVariant => f.write_str("tuple variant"),
        }
    }
}

impl TryFrom<u8> for Type {
    type Error = Error;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        if value > Self::TupleVariant.tag() {
            return Err(Error::InvalidTypeTag(value));
        }

        Ok(unsafe { core::mem::transmute::<u8, Type>(value) })
    }
}

impl Type {
    pub const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}
