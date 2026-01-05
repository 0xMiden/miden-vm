use alloc::string::{String, ToString};
use core::{
    fmt,
    ops::Deref,
    str::{self, FromStr},
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use super::{Path, PathError};
use crate::ast::Ident;

// ITEM PATH
// ================================================================================================

/// Path to an item in a library, i.e. module, procedure, constant or type.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct PathBuf {
    pub(super) inner: String,
}

impl Deref for PathBuf {
    type Target = Path;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl AsRef<Path> for PathBuf {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        Path::new(&self.inner)
    }
}

impl AsRef<str> for PathBuf {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl<'a> From<&'a Path> for PathBuf {
    #[inline(always)]
    fn from(path: &'a Path) -> Self {
        path.to_path_buf()
    }
}

/// Constructors
impl PathBuf {
    /// Get an empty [PathBuf] with `capacity` bytes allocated for the underlying path storage
    pub fn with_capacity(capacity: usize) -> Self {
        Self { inner: String::with_capacity(capacity) }
    }

    /// Returns a new path created from the provided source.
    ///
    /// A path consists of at list of components separated by `::` delimiter. A path must contain
    /// at least one component.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The path is empty.
    /// * Any component of the path is empty.
    /// * Any component is not a valid identifier (quoted or unquoted) in Miden Assembly syntax,
    ///   i.e. starts with an ASCII alphabetic character, contains only printable ASCII characters,
    ///   except for `::`, which must only be used as a path separator.
    pub fn new<S>(source: &S) -> Result<Self, PathError>
    where
        S: AsRef<str> + ?Sized,
    {
        let source = source.as_ref();

        let validated = Path::validate(source)?;

        // Ensure we canonicalize paths that are de-facto absolute to use the root prefix
        let mut buf = PathBuf::with_capacity(validated.byte_len());
        if validated.is_absolute() && !validated.as_str().starts_with("::") {
            buf.inner.push_str("::");
        }
        buf.inner.push_str(validated.as_str());

        Ok(buf)
    }

    /// Create an absolute [Path] from a pre-validated string
    pub fn absolute<S>(source: &S) -> Self
    where
        S: AsRef<str> + ?Sized,
    {
        let source = source.as_ref();
        Path::new(source).to_absolute().into_owned()
    }

    /// Create a relative [Path] from a pre-validated string
    pub fn relative<S>(source: &S) -> Self
    where
        S: AsRef<str> + ?Sized,
    {
        let source = source.as_ref();
        match source.strip_prefix("::") {
            Some(rest) => Self { inner: rest.to_string() },
            None => Self { inner: source.to_string() },
        }
    }

    /// Get a [Path] corresponding to the this [PathBuf]
    #[inline]
    pub fn as_path(&self) -> &Path {
        self.as_ref()
    }

    /// Convert this mutable [PathBuf] into an owned, read-only [`alloc::boxed::Box<Path>`]
    pub fn into_boxed_path(self) -> alloc::boxed::Box<Path> {
        let inner = self.inner.into_boxed_str();
        let inner = alloc::boxed::Box::into_raw(inner);
        // SAFETY: This cast is safe because *mut Path is equivalent to *mut str
        unsafe { alloc::boxed::Box::from_raw(inner as *mut Path) }
    }
}

/// Mutation
impl PathBuf {
    /// Overrides the parent prefix of this path.
    ///
    /// The parent prefix is the part of the path consisting of all components but the last one.
    ///
    /// If there is only a single component in `self`, this function is equivalent to appending
    /// `self` to `parent`.
    pub fn set_parent<P>(&mut self, parent: &P)
    where
        P: AsRef<Path> + ?Sized,
    {
        let parent = parent.as_ref();
        match self.split_last() {
            Some((last, _)) => {
                let parent = parent.as_str();
                let mut buf = String::with_capacity(last.len() + parent.len() + 2);
                if !parent.is_empty() {
                    buf.push_str(parent);
                    buf.push_str("::");
                }
                buf.push_str(last);
                self.inner = buf;
            },
            None => {
                self.inner.clear();
                self.inner.push_str(parent.as_str());
            },
        }
    }

    /// Extends `self` with `path`
    ///
    /// If `path` is absolute, it replaces the current path.
    ///
    /// This function ensures that the joined path correctly delimits each path component.
    pub fn push<P>(&mut self, path: &P)
    where
        P: AsRef<Path> + ?Sized,
    {
        let path = path.as_ref();

        if path.is_empty() {
            return;
        }

        if path.is_absolute() {
            self.inner.clear();
            // Handle special symbols which are de-facto absolute by making the root prefix explicit
            if !path.as_str().starts_with("::") {
                self.inner.push_str("::");
            }
            self.inner.push_str(path.as_str());
            return;
        }

        if self.is_empty() {
            self.inner.push_str(path.as_str());
            return;
        }

        for component in path.components() {
            self.inner.push_str("::");
            let component = component.unwrap();
            self.inner.push_str(component.as_str());
        }
    }

    /// Truncates `self` to [`Path::parent`].
    ///
    /// Returns `false` if `self.parent()` is `None`, otherwise `true`.
    pub fn pop(&mut self) -> bool {
        match self.parent() {
            Some(parent) => {
                let buf = parent.as_str().to_string();
                self.inner = buf;
                true
            },
            None => false,
        }
    }
}

impl<'a> core::ops::AddAssign<&'a Path> for PathBuf {
    fn add_assign(&mut self, rhs: &'a Path) {
        self.push(rhs);
    }
}

impl<'a> core::ops::AddAssign<&'a str> for PathBuf {
    fn add_assign(&mut self, rhs: &'a str) {
        self.push(rhs);
    }
}

impl<'a> core::ops::AddAssign<&'a Ident> for PathBuf {
    fn add_assign(&mut self, rhs: &'a Ident) {
        self.push(rhs.as_str());
    }
}

impl<'a> core::ops::AddAssign<&'a crate::ast::ProcedureName> for PathBuf {
    fn add_assign(&mut self, rhs: &'a crate::ast::ProcedureName) {
        self.push(rhs.as_str());
    }
}

impl<'a> TryFrom<&'a str> for PathBuf {
    type Error = PathError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        PathBuf::new(value)
    }
}

impl TryFrom<String> for PathBuf {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Path::validate(&value)?;
        Ok(PathBuf { inner: value })
    }
}

impl From<Ident> for PathBuf {
    fn from(component: Ident) -> Self {
        PathBuf { inner: component.as_str().to_string() }
    }
}

impl From<PathBuf> for String {
    fn from(path: PathBuf) -> Self {
        path.inner
    }
}

impl From<PathBuf> for alloc::sync::Arc<Path> {
    fn from(value: PathBuf) -> Self {
        value.into_boxed_path().into()
    }
}

impl From<alloc::borrow::Cow<'_, Path>> for PathBuf {
    fn from(value: alloc::borrow::Cow<'_, Path>) -> Self {
        value.into_owned()
    }
}

impl FromStr for PathBuf {
    type Err = PathError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serializable for PathBuf {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_path().write_into(target);
    }
}

impl Serializable for Path {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.byte_len().try_into().expect("invalid path: too long"));
        target.write_bytes(self.as_str().as_bytes());
    }
}

impl Deserializable for PathBuf {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u16()? as usize;
        let path = source.read_slice(len)?;
        let path =
            str::from_utf8(path).map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
        Self::new(path).map_err(|e| DeserializationError::InvalidValue(e.to_string()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PathBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.inner.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PathBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = <&'de str as serde::Deserialize<'de>>::deserialize(deserializer)?;

        PathBuf::new(inner).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_path(), f)
    }
}

// TESTS
// ================================================================================================

/// Tests
#[cfg(test)]
mod tests {

    use miden_core::assert_matches;

    use super::{PathBuf, PathError};
    use crate::{Path, ast::IdentError};

    #[test]
    fn single_component_path() {
        let path = PathBuf::new("foo").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 1);
        assert_eq!(path.last(), Some("foo"));
        assert_eq!(path.first(), Some("foo"));
    }

    #[test]
    fn relative_path_two_components() {
        let path = PathBuf::new("foo::bar").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 2);
        assert_eq!(path.last(), Some("bar"));
        assert_eq!(path.first(), Some("foo"));
    }

    #[test]
    fn relative_path_three_components() {
        let path = PathBuf::new("foo::bar::baz").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 3);
        assert_eq!(path.last(), Some("baz"));
        assert_eq!(path.first(), Some("foo"));
        assert_eq!(path.parent().map(|p| p.as_str()), Some("foo::bar"));
    }

    #[test]
    fn single_quoted_component() {
        let path = PathBuf::new("\"miden:base/account@0.1.0\"").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 1);
        assert_eq!(path.last(), Some("miden:base/account@0.1.0"));
        assert_eq!(path.first(), Some("miden:base/account@0.1.0"));
    }

    #[test]
    fn trailing_quoted_component() {
        let path = PathBuf::new("foo::\"miden:base/account@0.1.0\"").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 2);
        assert_eq!(path.last(), Some("miden:base/account@0.1.0"));
        assert_eq!(path.first(), Some("foo"));
    }

    #[test]
    fn interspersed_quoted_component() {
        let path = PathBuf::new("foo::\"miden:base/account@0.1.0\"::item").unwrap();
        assert!(!path.is_absolute());
        assert_eq!(path.components().count(), 3);
        assert_eq!(path.last(), Some("item"));
        assert_eq!(path.first(), Some("foo"));
        assert_eq!(path.parent().map(|p| p.as_str()), Some("foo::\"miden:base/account@0.1.0\""));
    }

    #[test]
    fn exec_path() {
        let path = PathBuf::new("$exec::bar::baz").unwrap();
        assert!(path.is_absolute());
        assert_eq!(path.components().count(), 4);
        assert_eq!(path.last(), Some("baz"));
        assert_eq!(path.first(), Some("$exec"));
    }

    #[test]
    fn kernel_path() {
        let path = PathBuf::new("$kernel::bar::baz").unwrap();
        std::dbg!(&path);
        assert!(path.is_absolute());
        assert_eq!(path.components().count(), 4);
        assert_eq!(path.last(), Some("baz"));
        assert_eq!(path.first(), Some("$kernel"));
    }

    #[test]
    fn invalid_path_empty() {
        let result = Path::validate("");
        assert_matches!(result, Err(PathError::Empty));
    }

    #[test]
    fn invalid_path_empty_component() {
        let result = Path::validate("::");
        assert_matches!(result, Err(PathError::EmptyComponent));
    }

    #[test]
    fn invalid_path_trailing_delimiter() {
        let result = Path::validate("foo::");
        assert_matches!(result, Err(PathError::InvalidComponent(IdentError::Empty)));
    }

    #[test]
    fn invalid_path_invalid_character() {
        let result = Path::validate("#foo::bar");
        assert_matches!(result, Err(PathError::InvalidComponent(IdentError::InvalidChars { .. })));
    }
}
