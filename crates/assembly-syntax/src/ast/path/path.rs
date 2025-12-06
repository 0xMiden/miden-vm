use alloc::{
    borrow::{Borrow, Cow, ToOwned},
    string::{String, ToString},
};
use core::fmt;

use super::{Iter, PathBuf, PathComponent, PathError, StartsWith};
use crate::ast::Ident;

/// A borrowed reference to a subset of a path, e.g. another [Path] or a [PathBuf]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Path {
    /// A view into the selected components of the path, i.e. the parts delimited by `::`
    inner: str,
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Path {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for &'de Path {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = <&'de str as serde::Deserialize<'de>>::deserialize(deserializer)?;

        Ok(Path::new(inner))
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;
    #[inline]
    fn to_owned(&self) -> PathBuf {
        self.to_path_buf()
    }
    #[inline]
    fn clone_into(&self, target: &mut Self::Owned) {
        self.inner.clone_into(&mut target.inner)
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<str> for Path {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl AsRef<Path> for str {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        unsafe { &*(self as *const str as *const Path) }
    }
}

impl AsRef<Path> for Ident {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        self.as_str().as_ref()
    }
}

impl AsRef<Path> for crate::ast::ProcedureName {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        let ident: &Ident = self.as_ref();
        ident.as_str().as_ref()
    }
}

impl AsRef<Path> for crate::ast::QualifiedProcedureName {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<Path> for Path {
    #[inline(always)]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl From<&Path> for alloc::sync::Arc<Path> {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

/// Conversions
impl Path {
    /// Path components  must be 255 bytes or less
    pub const MAX_COMPONENT_LENGTH: usize = u8::MAX as usize;

    /// An empty path for use as a default value, placeholder, comparisons, etc.
    pub const EMPTY: &Path = unsafe { &*("" as *const str as *const Path) };

    /// Base kernel path.
    pub const KERNEL_PATH: &str = "$kernel";
    pub const ABSOLUTE_KERNEL_PATH: &str = "::$kernel";
    pub const KERNEL: &Path =
        unsafe { &*(Self::ABSOLUTE_KERNEL_PATH as *const str as *const Path) };

    /// Path for an executable module.
    pub const EXEC_PATH: &str = "$exec";
    pub const ABSOLUTE_EXEC_PATH: &str = "::$exec";
    pub const EXEC: &Path = unsafe { &*(Self::ABSOLUTE_EXEC_PATH as *const str as *const Path) };

    pub fn new<S: AsRef<str> + ?Sized>(path: &S) -> &Path {
        // SAFETY: The representation of Path is equivalent to str
        unsafe { &*(path.as_ref() as *const str as *const Path) }
    }

    pub fn from_mut(path: &mut str) -> &mut Path {
        // SAFETY: The representation of Path is equivalent to str
        unsafe { &mut *(path as *mut str as *mut Path) }
    }

    /// Verify that `path` meets all the requirements for a valid [Path]
    pub fn validate(path: &str) -> Result<&Path, PathError> {
        match path {
            "" => return Err(PathError::Empty),
            "::" => return Err(PathError::EmptyComponent),
            _ => (),
        }

        for result in Iter::new(path) {
            result?;
        }

        Ok(Path::new(path))
    }

    /// Get a [Path] corresponding to [Self::KERNEL_PATH]
    pub const fn kernel_path() -> &'static Path {
        Path::KERNEL
    }

    /// Get a [Path] corresponding to [Self::EXEC_PATH]
    pub const fn exec_path() -> &'static Path {
        Path::EXEC
    }

    #[inline]
    pub const fn as_str(&self) -> &str {
        &self.inner
    }

    #[inline]
    pub fn as_mut_str(&mut self) -> &mut str {
        &mut self.inner
    }

    /// Get an [Ident] that is equivalent to this [Path], so long as the path has only a single
    /// component.
    ///
    /// Returns `None` if the path cannot be losslessly represented as a single component.
    pub fn as_ident(&self) -> Option<Ident> {
        let mut components = self.components().filter_map(|c| c.ok());
        match components.next()? {
            component @ PathComponent::Normal(_) => {
                if components.next().is_none() {
                    component.to_ident()
                } else {
                    None
                }
            },
            PathComponent::Root => None,
        }
    }

    /// Convert this [Path] to an owned [PathBuf]
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf { inner: self.inner.to_string() }
    }
}

/// Accesssors
impl Path {
    /// Returns true if this path is empty (i.e. has no components)
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty() || &self.inner == "::"
    }

    /// Returns the number of components in the path
    pub fn len(&self) -> usize {
        self.components().count()
    }

    /// Return the size of the path in [char]s when displayed as a string
    pub fn char_len(&self) -> usize {
        self.inner.chars().count()
    }

    /// Return the size of the path in bytes when displayed as a string
    #[inline]
    pub fn byte_len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if this path is an absolute path
    pub fn is_absolute(&self) -> bool {
        matches!(
            self.components().next(),
            Some(Ok(PathComponent::Root))
                | Some(Ok(PathComponent::Normal(Self::KERNEL_PATH | Self::EXEC_PATH))),
        )
    }

    /// Make this path absolute, if not already
    ///
    /// NOTE: This does not _resolve_ the path, it simply ensures the path has the root prefix
    pub fn to_absolute(&self) -> Cow<'_, Path> {
        if self.is_absolute() {
            Cow::Borrowed(self)
        } else {
            let mut inner = String::with_capacity(self.byte_len() + 2);
            inner.push_str("::");
            inner.push_str(&self.inner);
            Cow::Owned(PathBuf { inner })
        }
    }

    /// Strip the root prefix from this path, if it has one.
    pub fn to_relative(&self) -> &Path {
        match self.inner.strip_prefix("::") {
            Some(rest) => Path::new(rest),
            None => self,
        }
    }

    /// Returns the [Path] without its final component, if there is one.
    ///
    /// This means it may return an empty [Path] for relative paths with a single component.
    ///
    /// Returns `None` if the path terminates with the root prefix, or if it is empty.
    pub fn parent(&self) -> Option<&Path> {
        let mut components = self.components();
        match components.next_back()?.ok()? {
            PathComponent::Root => None,
            _ => Some(components.as_path()),
        }
    }

    /// Returns an iterator over all components of the path.
    pub fn components(&self) -> Iter<'_> {
        Iter::new(&self.inner)
    }

    /// Get the first non-root component of this path as a `str`
    ///
    /// Returns `None` if the path is empty, or consists only of the root prefix.
    pub fn first(&self) -> Option<&str> {
        self.split_first().map(|(first, _)| first)
    }

    /// Get the first non-root component of this path as a `str`
    ///
    /// Returns `None` if the path is empty, or consists only of the root prefix.
    pub fn last(&self) -> Option<&str> {
        self.split_last().map(|(last, _)| last)
    }

    /// Splits this path on the first non-root component, returning it and a new [Path] of the
    /// remaining components.
    ///
    /// Returns `None` if there are no components to split
    pub fn split_first(&self) -> Option<(&str, &Path)> {
        let mut components = self.components();
        match components.next()?.ok()? {
            PathComponent::Root => {
                let first = components.next().and_then(|c| c.ok()).map(|c| c.as_str())?;
                Some((first, components.as_path()))
            },
            PathComponent::Normal(first) => Some((first, components.as_path())),
        }
    }

    /// Splits this path on the last component, returning it and a new [Path] of the remaining
    /// components.
    ///
    /// Returns `None` if there are no components to split
    pub fn split_last(&self) -> Option<(&str, &Path)> {
        let mut components = self.components();
        match components.next_back()?.ok()? {
            PathComponent::Root => None,
            PathComponent::Normal(last) => Some((last, components.as_path())),
        }
    }

    /// Returns true if this path is for the root kernel module.
    pub fn is_kernel_path(&self) -> bool {
        match self.inner.strip_prefix("::") {
            Some(Self::KERNEL_PATH) => true,
            Some(_) => false,
            None => &self.inner == Self::KERNEL_PATH,
        }
    }

    /// Returns true if this path is for the root kernel module or an item in it
    pub fn is_in_kernel(&self) -> bool {
        if self.is_kernel_path() {
            return true;
        }

        match self.split_last() {
            Some((_, prefix)) => Self::KERNEL == prefix,
            None => false,
        }
    }

    /// Returns true if this path is for an executable module.
    pub fn is_exec_path(&self) -> bool {
        match self.inner.strip_prefix("::") {
            Some(Self::EXEC_PATH) => true,
            Some(_) => false,
            None => &self.inner == Self::EXEC_PATH,
        }
    }

    /// Returns true if the current path, sans root component, starts with `prefix`
    #[inline]
    pub fn starts_with<Prefix>(&self, prefix: &Prefix) -> bool
    where
        Prefix: ?Sized,
        Self: StartsWith<Prefix>,
    {
        <Self as StartsWith<Prefix>>::starts_with(self, prefix)
    }

    /// Returns true if the current path, including root component, starts with `prefix`
    #[inline]
    pub fn starts_with_exactly<Prefix>(&self, prefix: &Prefix) -> bool
    where
        Prefix: ?Sized,
        Self: StartsWith<Prefix>,
    {
        <Self as StartsWith<Prefix>>::starts_with_exactly(self, prefix)
    }

    /// Create an owned [PathBuf] with `path` adjoined to `self`.
    ///
    /// If `path` is absolute, it replaces the current path.
    ///
    /// See [PathBuf::push] for more details on what it means to adjoin a path.
    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        let path = path.as_ref();

        if path.is_empty() {
            return self.to_path_buf();
        }

        if self.is_empty() || path.is_absolute() {
            return path.to_path_buf();
        }

        let mut buf = self.to_path_buf();
        buf.push(path);

        buf
    }
}

impl StartsWith<str> for Path {
    fn starts_with(&self, prefix: &str) -> bool {
        if prefix.is_empty() {
            return true;
        }
        if prefix.starts_with("::") {
            self.inner.starts_with(prefix)
        } else {
            match self.inner.strip_prefix("::") {
                Some(rest) => rest.starts_with(prefix),
                None => self.inner.starts_with(prefix),
            }
        }
    }

    #[inline]
    fn starts_with_exactly(&self, prefix: &str) -> bool {
        self.inner.starts_with(prefix)
    }
}

impl StartsWith<Path> for Path {
    fn starts_with(&self, prefix: &Path) -> bool {
        <Self as StartsWith<str>>::starts_with(self, prefix.as_str())
    }

    #[inline]
    fn starts_with_exactly(&self, prefix: &Path) -> bool {
        <Self as StartsWith<str>>::starts_with_exactly(self, prefix.as_str())
    }
}

impl PartialEq<str> for Path {
    fn eq(&self, other: &str) -> bool {
        &self.inner == other
    }
}

impl PartialEq<PathBuf> for Path {
    fn eq(&self, other: &PathBuf) -> bool {
        &self.inner == other.inner.as_str()
    }
}

impl PartialEq<&PathBuf> for Path {
    fn eq(&self, other: &&PathBuf) -> bool {
        &self.inner == other.inner.as_str()
    }
}

impl PartialEq<Path> for PathBuf {
    fn eq(&self, other: &Path) -> bool {
        self.inner.as_str() == &other.inner
    }
}

impl PartialEq<&Path> for Path {
    fn eq(&self, other: &&Path) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<alloc::boxed::Box<Path>> for Path {
    fn eq(&self, other: &alloc::boxed::Box<Path>) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<alloc::rc::Rc<Path>> for Path {
    fn eq(&self, other: &alloc::rc::Rc<Path>) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<alloc::sync::Arc<Path>> for Path {
    fn eq(&self, other: &alloc::sync::Arc<Path>) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<alloc::borrow::Cow<'_, Path>> for Path {
    fn eq(&self, other: &alloc::borrow::Cow<'_, Path>) -> bool {
        self.inner == other.as_ref().inner
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}
