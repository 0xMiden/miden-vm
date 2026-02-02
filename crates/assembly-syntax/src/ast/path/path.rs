use alloc::{
    borrow::{Borrow, Cow, ToOwned},
    string::ToString,
};
use core::fmt;

use super::{Iter, Join, PathBuf, PathComponent, PathError, StartsWith};
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
        use serde::de::Visitor;

        struct PathVisitor;

        impl<'de> Visitor<'de> for PathVisitor {
            type Value = &'de Path;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a borrowed Path")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Path::validate(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(PathVisitor)
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
            "" | "\"\"" => return Err(PathError::Empty),
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

    /// Convert an [Ident] to an equivalent [Path] or [PathBuf], depending on whether the identifier
    /// would require quoting as a path.
    pub fn from_ident(ident: &Ident) -> Cow<'_, Path> {
        let ident = ident.as_str();
        if Ident::requires_quoting(ident) {
            let mut buf = PathBuf::with_capacity(ident.len() + 2);
            buf.push_component(ident);
            Cow::Owned(buf)
        } else {
            Cow::Borrowed(Path::new(ident))
        }
    }
}

/// Accesssors
impl Path {
    /// Returns true if this path is empty (i.e. has no components)
    pub fn is_empty(&self) -> bool {
        matches!(&self.inner, "" | "::" | "\"\"")
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
        matches!(self.components().next(), Some(Ok(PathComponent::Root)))
    }

    /// Make this path absolute, if not already
    ///
    /// NOTE: This does not _resolve_ the path, it simply ensures the path has the root prefix
    pub fn to_absolute(&self) -> Cow<'_, Path> {
        if self.is_absolute() {
            Cow::Borrowed(self)
        } else {
            let mut buf = PathBuf::with_capacity(self.byte_len() + 2);
            buf.push_component("::");
            buf.extend_with_components(self.components()).expect("invalid path");
            Cow::Owned(buf)
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
            first @ PathComponent::Normal(_) => Some((first.as_str(), components.as_path())),
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
            last @ PathComponent::Normal(_) => Some((last.as_str(), components.as_path())),
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
            Some((_, prefix)) => prefix.is_kernel_path(),
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

    /// Returns true if this path is for the executable module or an item in it
    pub fn is_in_exec(&self) -> bool {
        if self.is_exec_path() {
            return true;
        }

        match self.split_last() {
            Some((_, prefix)) => prefix.is_exec_path(),
            None => false,
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

    /// Strips `prefix` from `self`, or returns `None` if `self` does not start with `prefix`.
    ///
    /// NOTE: Prefixes must be exact, i.e. if you call `path.strip_prefix(prefix)` and `path` is
    /// relative but `prefix` is absolute, then this will return `None`. The same is true if `path`
    /// is absolute and `prefix` is relative.
    pub fn strip_prefix<'a>(&'a self, prefix: &Self) -> Option<&'a Self> {
        let mut components = self.components();
        for prefix_component in prefix.components() {
            let prefix_component = prefix_component.expect("invalid prefix path");
            match (components.next(), prefix_component) {
                (Some(Ok(PathComponent::Root)), PathComponent::Root) => (),
                (Some(Ok(c @ PathComponent::Normal(_))), pc @ PathComponent::Normal(_)) => {
                    if c.as_str() != pc.as_str() {
                        return None;
                    }
                },
                (Some(Ok(_) | Err(_)) | None, _) => return None,
            }
        }
        Some(components.as_path())
    }

    /// Create an owned [PathBuf] with `path` adjoined to `self`.
    ///
    /// If `path` is absolute, it replaces the current path.
    ///
    /// The semantics of how `other` is joined to `self` in the resulting path depends on the
    /// implementation of [Join] used. The implementation for [Path] and [PathBuf] joins all
    /// components of `other` to self`; while the implementation for [prim@str], string-like values,
    /// and identifiers/symbols joins just a single component. You must be careful to ensure that
    /// if you are passing a string here, that you specifically want to join it as a single
    /// component, or the resulting path may be different than you expect. It is recommended that
    /// you use `Path::new(&string)` if you want to be explicit about treating a string-like value
    /// as a multi-component path.
    #[inline]
    pub fn join<P>(&self, other: &P) -> PathBuf
    where
        P: ?Sized,
        Path: Join<P>,
    {
        <Path as Join<P>>::join(self, other)
    }

    /// Canonicalize this path by ensuring that all components are in canonical form.
    ///
    /// Canonical form dictates that:
    ///
    /// * A component is quoted only if it requires quoting, and unquoted otherwise
    /// * Is made absolute if relative and the first component is $kernel or $exec
    ///
    /// Returns `Err` if the path is invalid
    pub fn canonicalize(&self) -> Result<PathBuf, PathError> {
        let mut buf = PathBuf::with_capacity(self.byte_len());
        buf.extend_with_components(self.components())?;
        Ok(buf)
    }
}

impl StartsWith<str> for Path {
    fn starts_with(&self, prefix: &str) -> bool {
        let this = self.to_relative();
        <Path as StartsWith<str>>::starts_with_exactly(this, prefix)
    }

    #[inline]
    fn starts_with_exactly(&self, prefix: &str) -> bool {
        match prefix {
            "" => true,
            "::" => self.is_absolute(),
            prefix => {
                let mut components = self.components();
                let prefix = if let Some(prefix) = prefix.strip_prefix("::") {
                    let is_absolute =
                        components.next().is_some_and(|c| matches!(c, Ok(PathComponent::Root)));
                    if !is_absolute {
                        return false;
                    }
                    prefix
                } else {
                    prefix
                };
                components.next().is_some_and(
                    |c| matches!(c, Ok(c @ PathComponent::Normal(_)) if c.as_str() == prefix),
                )
            },
        }
    }
}

impl StartsWith<Path> for Path {
    fn starts_with(&self, prefix: &Path) -> bool {
        let this = self.to_relative();
        let prefix = prefix.to_relative();
        <Path as StartsWith<Path>>::starts_with_exactly(this, prefix)
    }

    #[inline]
    fn starts_with_exactly(&self, prefix: &Path) -> bool {
        let mut components = self.components();
        for prefix_component in prefix.components() {
            let prefix_component = prefix_component.expect("invalid prefix path");
            match (components.next(), prefix_component) {
                (Some(Ok(PathComponent::Root)), PathComponent::Root) => continue,
                (Some(Ok(c @ PathComponent::Normal(_))), pc @ PathComponent::Normal(_)) => {
                    if c.as_str() != pc.as_str() {
                        return false;
                    }
                },
                (Some(Ok(_) | Err(_)) | None, _) => return false,
            }
        }
        true
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_path_identity() -> Result<(), PathError> {
        let path = Path::new("foo::bar");
        let canonicalized = path.canonicalize()?;

        assert_eq!(canonicalized.as_path(), path);
        Ok(())
    }

    #[test]
    fn test_canonicalize_path_kernel_is_absolute() -> Result<(), PathError> {
        let path = Path::new("$kernel::bar");
        let canonicalized = path.canonicalize()?;

        let expected = Path::new("::$kernel::bar");
        assert_eq!(canonicalized.as_path(), expected);
        Ok(())
    }

    #[test]
    fn test_canonicalize_path_exec_is_absolute() -> Result<(), PathError> {
        let path = Path::new("$exec::$main");
        let canonicalized = path.canonicalize()?;

        let expected = Path::new("::$exec::$main");
        assert_eq!(canonicalized.as_path(), expected);
        Ok(())
    }

    #[test]
    fn test_canonicalize_path_remove_unnecessary_quoting() -> Result<(), PathError> {
        let path = Path::new("foo::\"bar\"");
        let canonicalized = path.canonicalize()?;

        let expected = Path::new("foo::bar");
        assert_eq!(canonicalized.as_path(), expected);
        Ok(())
    }

    #[test]
    fn test_canonicalize_path_preserve_necessary_quoting() -> Result<(), PathError> {
        let path = Path::new("foo::\"bar::baz\"");
        let canonicalized = path.canonicalize()?;

        assert_eq!(canonicalized.as_path(), path);
        Ok(())
    }

    #[test]
    fn test_canonicalize_path_add_required_quoting_to_components_without_delimiter()
    -> Result<(), PathError> {
        let path = Path::new("foo::$bar");
        let canonicalized = path.canonicalize()?;

        let expected = Path::new("foo::\"$bar\"");
        assert_eq!(canonicalized.as_path(), expected);
        Ok(())
    }
}
