use alloc::{string::ToString, sync::Arc};
use core::{
    fmt,
    str::{self, FromStr},
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::{
    LibraryPath, Span,
    ast::Ident,
    diagnostics::{Diagnostic, miette},
};

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
