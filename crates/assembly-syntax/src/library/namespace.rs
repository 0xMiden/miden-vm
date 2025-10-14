// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{string::ToString, sync::Arc};
use core::{
    fmt,
    str::{self, FromStr},
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::Span;
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{LibraryPath, ast::Ident};

// LIBRARY NAMESPACE
// ================================================================================================

/// Represents an error when parsing or validating a library namespace
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum LibraryNamespaceError {
    #[error("invalid library namespace name: cannot be empty")]
    #[diagnostic()]
    Empty,
    #[error("invalid library namespace name: too many characters")]
    #[diagnostic()]
    Length,
    #[error(
        "invalid character in library namespace: expected lowercase ascii-alphanumeric character or '_'"
    )]
    #[diagnostic()]
    InvalidChars,
    #[error("invalid library namespace name: must start with lowercase ascii-alphabetic character")]
    #[diagnostic()]
    InvalidStart,
}

/// Represents the root component of a library path, akin to a Rust crate name
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[cfg_attr(
    all(feature = "serde", feature = "arbitrary", test),
    miden_serde_test_macros::serde_test
)]
pub enum LibraryNamespace {
    /// A reserved namespace for kernel modules
    Kernel = 0,
    /// A reserved namespace for executable modules
    Exec,
    /// A reserved namespace assigned to anonymous libraries with no path
    #[default]
    Anon,
    /// A user-defined namespace
    User(Arc<str>),
}

// ------------------------------------------------------------------------------------------------
/// Constants
impl LibraryNamespace {
    /// Namespaces must be 255 bytes or less
    pub const MAX_LENGTH: usize = u8::MAX as usize;

    /// Base kernel path.
    pub const KERNEL_PATH: &'static str = "$kernel";

    /// Path for an executable module.
    pub const EXEC_PATH: &'static str = "$exec";

    /// Path for a module without library path.
    pub const ANON_PATH: &'static str = "$anon";
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl LibraryNamespace {
    /// Construct a new [LibraryNamespace] from `source`
    pub fn new<S>(source: S) -> Result<Self, LibraryNamespaceError>
    where
        S: AsRef<str>,
    {
        source.as_ref().parse()
    }

    /// Construct a new [LibraryNamespace] from a previously-validated [Ident].
    ///
    /// NOTE: The caller must ensure that the given identifier is a valid namespace name.
    pub fn from_ident_unchecked(name: Ident) -> Self {
        match name.as_str() {
            Self::KERNEL_PATH => Self::Kernel,
            Self::EXEC_PATH => Self::Exec,
            Self::ANON_PATH => Self::Anon,
            _ => Self::User(name.into_inner()),
        }
    }

    /// Parse a [LibraryNamespace] by taking the prefix of the given path string, and returning
    /// the namespace and remaining string if successful.
    pub fn strip_path_prefix(path: &str) -> Result<(Self, &str), LibraryNamespaceError> {
        match path.split_once("::") {
            Some((ns, rest)) => ns.parse().map(|ns| (ns, rest)),
            None => path.parse().map(|ns| (ns, "")),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl LibraryNamespace {
    /// Returns true if this namespace is a reserved namespace.
    pub fn is_reserved(&self) -> bool {
        !matches!(self, Self::User(_))
    }

    /// Checks if `source` is a valid [LibraryNamespace]
    ///
    /// The rules for valid library namespaces are:
    ///
    /// * Must be lowercase
    /// * Must start with an ASCII alphabetic character, with the exception of reserved special
    ///   namespaces
    /// * May only contain alphanumeric unicode characters, or a character from the ASCII graphic
    ///   set, see [char::is_ascii_graphic].
    pub fn validate(source: impl AsRef<str>) -> Result<(), LibraryNamespaceError> {
        let source = source.as_ref();
        if source.is_empty() {
            return Err(LibraryNamespaceError::Empty);
        }
        if matches!(source, Self::KERNEL_PATH | Self::EXEC_PATH | Self::ANON_PATH) {
            return Ok(());
        }
        if source.len() > Self::MAX_LENGTH {
            return Err(LibraryNamespaceError::Length);
        }
        if !source.starts_with(|c: char| c.is_ascii_lowercase() && c.is_ascii_alphabetic()) {
            return Err(LibraryNamespaceError::InvalidStart);
        }
        if !source.chars().all(|c| c.is_ascii_graphic() || c.is_alphanumeric()) {
            return Err(LibraryNamespaceError::InvalidChars);
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
/// Conversions
impl LibraryNamespace {
    /// Get the string representation of this namespace.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Kernel => Self::KERNEL_PATH,
            Self::Exec => Self::EXEC_PATH,
            Self::Anon => Self::ANON_PATH,
            Self::User(path) => path,
        }
    }

    /// Get an [`Arc<str>`] representing this namespace.
    pub fn as_refcounted_str(&self) -> Arc<str> {
        match self {
            Self::User(path) => path.clone(),
            other => Arc::from(other.as_str().to_string().into_boxed_str()),
        }
    }

    /// Create a [LibraryPath] representing this [LibraryNamespace].
    pub fn to_path(&self) -> LibraryPath {
        LibraryPath::from(self.clone())
    }

    /// Create an [Ident] representing this namespace.
    pub fn to_ident(&self) -> Ident {
        Ident::from_raw_parts(Span::unknown(self.as_refcounted_str()))
    }

    #[cfg(feature = "serde")]
    const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

impl core::ops::Deref for LibraryNamespace {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for LibraryNamespace {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for LibraryNamespace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LibraryNamespace {
    type Err = LibraryNamespaceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::KERNEL_PATH => Ok(Self::Kernel),
            Self::EXEC_PATH => Ok(Self::Exec),
            Self::ANON_PATH => Ok(Self::Anon),
            other => {
                Self::validate(other)?;
                Ok(Self::User(Arc::from(other.to_string().into_boxed_str())))
            },
        }
    }
}

impl TryFrom<Ident> for LibraryNamespace {
    type Error = LibraryNamespaceError;
    fn try_from(ident: Ident) -> Result<Self, Self::Error> {
        match ident.as_str() {
            Self::KERNEL_PATH => Ok(Self::Kernel),
            Self::EXEC_PATH => Ok(Self::Exec),
            Self::ANON_PATH => Ok(Self::Anon),
            other => Self::new(other),
        }
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for LibraryNamespace {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Catch any situations where a namespace was incorrectly constructed
        let bytes = self.as_bytes();
        assert!(bytes.len() <= u8::MAX as usize, "namespace too long");

        target.write_u8(bytes.len() as u8);
        target.write_bytes(bytes);
    }
}

impl Deserializable for LibraryNamespace {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_bytes = source.read_u8()? as usize;
        let name = source.read_slice(num_bytes)?;
        let name =
            str::from_utf8(name).map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
        Self::new(name).map_err(|e| DeserializationError::InvalidValue(e.to_string()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LibraryNamespace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::Kernel => serializer.serialize_str(Self::KERNEL_PATH),
                Self::Exec => serializer.serialize_str(Self::EXEC_PATH),
                Self::Anon => serializer.serialize_str(Self::ANON_PATH),
                Self::User(ns) => serializer.serialize_str(ns),
            }
        } else {
            use serde::ser::SerializeTupleVariant;
            let tag = self.tag() as u32;
            match self {
                Self::Kernel => {
                    serializer.serialize_unit_variant("LibraryNamespace", tag, "Kernel")
                },
                Self::Exec => serializer.serialize_unit_variant("LibraryNamespace", tag, "Exec"),
                Self::Anon => serializer.serialize_unit_variant("LibraryNamespace", tag, "Anon"),
                Self::User(custom) => {
                    let mut tuple =
                        serializer.serialize_tuple_variant("LibraryNamespace", tag, "User", 1)?;
                    tuple.serialize_field(&custom.as_ref())?;
                    tuple.end()
                },
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LibraryNamespace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Unexpected};

        if deserializer.is_human_readable() {
            let name = <&'de str as serde::Deserialize>::deserialize(deserializer)?;
            match name {
                Self::KERNEL_PATH => Ok(Self::Kernel),
                Self::EXEC_PATH => Ok(Self::Exec),
                Self::ANON_PATH => Ok(Self::Anon),
                other => Self::new(other).map_err(serde::de::Error::custom),
            }
        } else {
            const KERNEL: u8 = LibraryNamespace::Kernel.tag();
            const EXEC: u8 = LibraryNamespace::Exec.tag();
            const ANON: u8 = LibraryNamespace::Anon.tag();
            const USER: u8 = ANON + 1;

            serde_untagged::UntaggedEnumVisitor::new()
                .expecting("a valid section id")
                .string(|s| Self::from_str(s).map_err(serde::de::Error::custom))
                .u8(|tag| match tag {
                    KERNEL => Ok(Self::Kernel),
                    EXEC => Ok(Self::Exec),
                    ANON => Ok(Self::Anon),
                    USER => {
                        Err(serde::de::Error::custom("expected a user-defined library namespace"))
                    },
                    other => Err(serde::de::Error::invalid_value(
                        Unexpected::Unsigned(other as u64),
                        &"a valid library namespace variant",
                    )),
                })
                .seq(|mut seq| {
                    let tag = seq.next_element::<u8>()?.ok_or_else(|| {
                        serde::de::Error::invalid_length(0, &"a valid library namespace variant")
                    })?;
                    match tag {
                        KERNEL => Ok(Self::Kernel),
                        EXEC => Ok(Self::Exec),
                        ANON => Ok(Self::Anon),
                        USER => seq
                            .next_element::<&str>()?
                            .ok_or_else(|| {
                                serde::de::Error::invalid_length(
                                    1,
                                    &"a user-defined library namespace",
                                )
                            })
                            .and_then(|s| Self::new(s).map_err(serde::de::Error::custom)),
                        other => Err(serde::de::Error::invalid_value(
                            Unexpected::Unsigned(other as u64),
                            &"a valid library namespace variant",
                        )),
                    }
                })
                .deserialize(deserializer)
        }
    }
}

#[cfg(all(feature = "std", any(test, feature = "arbitrary")))]
impl proptest::prelude::Arbitrary for LibraryNamespace {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        prop_oneof![
            Just(LibraryNamespace::Kernel),
            Just(LibraryNamespace::Exec),
            Just(LibraryNamespace::Anon),
            prop::string::string_regex(r"[a-z][a-z0-9_]*")
                .unwrap()
                .prop_map(|s| { LibraryNamespace::User(Arc::from(s)) }),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
