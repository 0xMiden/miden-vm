#[cfg(feature = "serde")]
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

// TARGET TYPE
// ================================================================================================

/// The type of a specific target provided by the current project
///
/// This describes how a package produced from this project can be used (e.g. as an account
/// component, a note script, etc.).
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
#[non_exhaustive]
#[repr(u8)]
pub enum TargetType {
    /// A generic code library
    #[default]
    Library = 0,
    /// An executable program
    Executable = 1,
    /// A kernel library
    Kernel = 2,
    /// An account component
    AccountComponent = 3,
    /// A note script
    NoteScript = 4,
    /// A transaction script
    TransactionScript = 5,
}

impl TargetType {
    /// Returns true if the target is an executable artifact
    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::Executable)
    }

    /// Returns true if the target is a library-like artifact
    pub const fn is_library(&self) -> bool {
        !self.is_executable()
    }

    /// Returns the string representation of this package kind.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Executable => "executable",
            Self::Kernel => "kernel",
            Self::AccountComponent => "account-component",
            Self::NoteScript => "note-script",
            Self::TransactionScript => "transaction-script",
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl TryFrom<u8> for TargetType {
    type Error = InvalidTargetTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Library),
            1 => Ok(Self::Executable),
            2 => Ok(Self::Kernel),
            3 => Ok(Self::AccountComponent),
            4 => Ok(Self::NoteScript),
            5 => Ok(Self::TransactionScript),
            _ => Err(InvalidTargetTypeError::Tag(value)),
        }
    }
}

impl From<TargetType> for u8 {
    #[inline(always)]
    fn from(kind: TargetType) -> Self {
        kind as u8
    }
}

impl fmt::Display for TargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for TargetType {
    type Err = InvalidTargetTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lib" | "library" => Ok(Self::Library),
            "bin" | "program" | "executable" => Ok(Self::Executable),
            "kernel" => Ok(Self::Kernel),
            "account" | "account-component" => Ok(Self::AccountComponent),
            "note" | "note-script" => Ok(Self::NoteScript),
            "tx-script" | "transaction-script" => Ok(Self::TransactionScript),
            s => Err(InvalidTargetTypeError::Name(s.to_string().into_boxed_str())),
        }
    }
}

// SERIALIZATION
// ================================================================================================

#[cfg(feature = "serde")]
impl Serialize for TargetType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            serializer.serialize_u8(*self as u8)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for TargetType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse::<TargetType>().map_err(|err| DeError::custom(err.to_string()))
        } else {
            let tag = u8::deserialize(deserializer)?;
            Self::try_from(tag).map_err(|err| DeError::custom(err.to_string()))
        }
    }
}

// ERROR
// ================================================================================================

/// Error returned when trying to convert an integer/string to a valid [TargetType]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidTargetTypeError {
    /// Invalid project type tag (binary representation)
    Tag(u8),
    /// Invalid project type name (human-readable representation)
    Name(Box<str>),
}

impl fmt::Display for InvalidTargetTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tag(tag) => write!(f, "invalid target type tag: {tag}"),
            Self::Name(name) => write!(f, "invalid target type: '{name}'"),
        }
    }
}
