mod components;
#[allow(clippy::module_inception)]
mod path;
mod path_buf;

pub use self::{
    components::{Iter, PathComponent},
    path::Path,
    path_buf::PathBuf,
};
use crate::diagnostics::{Diagnostic, miette};

/// Represents errors that can occur when creating, parsing, or manipulating [Path]s
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("invalid item path: cannot be empty")]
    Empty,
    #[error("invalid item path component: cannot be empty")]
    EmptyComponent,
    #[error("invalid item path component: {0}")]
    InvalidComponent(crate::ast::IdentError),
    #[error("invalid item path: contains invalid utf8 byte sequences")]
    InvalidUtf8,
    #[error(transparent)]
    InvalidNamespace(NamespaceError),
    #[error("cannot join a path with reserved name to other paths")]
    UnsupportedJoin,
    #[error("'::' delimiter found where path component was expected")]
    UnexpectedDelimiter,
    #[error("path is missing a '::' delimiter between quoted/unquoted components")]
    MissingPathSeparator,
    #[error("quoted path component is missing a closing '\"'")]
    UnclosedQuotedComponent,
}

/// Represents an error when parsing or validating a library namespace
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum NamespaceError {
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

/// This trait abstracts over the concept of matching a prefix pattern against a path
pub trait StartsWith<Prefix: ?Sized> {
    /// Returns true if the current path, sans root component, starts with `prefix`
    fn starts_with(&self, prefix: &Prefix) -> bool;

    /// Returns true if the current path, including root component, starts with `prefix`
    fn starts_with_exactly(&self, prefix: &Prefix) -> bool;
}

/// Serialize a [Path]
#[cfg(feature = "serde")]
pub fn serialize<P, S>(path: P, serializer: S) -> Result<S::Ok, S::Error>
where
    P: AsRef<Path>,
    S: serde::Serializer,
{
    use serde::Serialize;
    path.as_ref().serialize(serializer)
}

/// Deserialize a [Path]
#[cfg(feature = "serde")]
pub fn deserialize<'de, P, D>(deserializer: D) -> Result<P, D::Error>
where
    PathBuf: Into<P>,
    D: serde::Deserializer<'de>,
{
    let path = <PathBuf as serde::Deserialize>::deserialize(deserializer)?;
    Ok(path.into())
}
