#[cfg(feature = "serde")]
use alloc::{
    format,
    string::{String, ToString},
};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

// PACKAGE KIND
// ================================================================================================

/// The kind of project that produced this package.
///
/// This helps consumers of the package understand how to use it (e.g., as an account component,
/// a note script, a transaction script, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
#[non_exhaustive]
#[repr(u8)]
pub enum PackageKind {
    /// A generic code library package.
    Library = 0,
    /// An executable program package.
    Executable = 1,
    /// An account component package.
    AccountComponent = 2,
    /// A note script package.
    NoteScript = 3,
    /// A transaction script package.
    TransactionScript = 4,
}

impl PackageKind {
    /// Returns the string representation of this package kind.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Executable => "executable",
            Self::AccountComponent => "account-component",
            Self::NoteScript => "note-script",
            Self::TransactionScript => "transaction-script",
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl TryFrom<u8> for PackageKind {
    type Error = InvalidPackageKindError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Library),
            1 => Ok(Self::Executable),
            2 => Ok(Self::AccountComponent),
            3 => Ok(Self::NoteScript),
            4 => Ok(Self::TransactionScript),
            _ => Err(InvalidPackageKindError(value)),
        }
    }
}

impl From<PackageKind> for u8 {
    fn from(kind: PackageKind) -> Self {
        kind as u8
    }
}

impl fmt::Display for PackageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// SERIALIZATION
// ================================================================================================

#[cfg(feature = "serde")]
impl Serialize for PackageKind {
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
impl<'de> Deserialize<'de> for PackageKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            match s.as_str() {
                "library" => Ok(Self::Library),
                "executable" => Ok(Self::Executable),
                "account-component" => Ok(Self::AccountComponent),
                "note-script" => Ok(Self::NoteScript),
                "transaction-script" => Ok(Self::TransactionScript),
                _ => Err(DeError::custom(format!("invalid package kind: {}", s))),
            }
        } else {
            let tag = u8::deserialize(deserializer)?;
            Self::try_from(tag).map_err(|e| DeError::custom(e.to_string()))
        }
    }
}

// ERROR
// ================================================================================================

/// Error returned when trying to convert an invalid u8 to a [PackageKind].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPackageKindError(pub u8);

impl fmt::Display for InvalidPackageKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid package kind tag: {}", self.0)
    }
}
