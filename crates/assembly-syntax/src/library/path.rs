use alloc::{
    borrow::Cow,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt,
    str::{self, FromStr},
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::Span;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use smallvec::smallvec;

use crate::{
    LibraryNamespace,
    ast::{Ident, IdentError},
};

/// Represents errors that can occur when creating, parsing, or manipulating [LibraryPath]s
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("invalid library path: cannot be empty")]
    Empty,
    #[error("invalid library path component: cannot be empty")]
    EmptyComponent,
    #[error("invalid library path component: {0}")]
    InvalidComponent(crate::ast::IdentError),
    #[error("invalid library path: contains invalid utf8 byte sequences")]
    InvalidUtf8,
    #[error(transparent)]
    InvalidNamespace(crate::library::LibraryNamespaceError),
    #[error("cannot join a path with reserved name to other paths")]
    UnsupportedJoin,
}

// LIBRARY PATH COMPONENT
// ================================================================================================

/// Represents a component of a [LibraryPath] in [LibraryPath::components]
pub enum LibraryPathComponent<'a> {
    /// The first component of the path, and the namespace of the path
    Namespace(&'a LibraryNamespace),
    /// A non-namespace component of the path
    Normal(&'a Ident),
}

impl<'a> LibraryPathComponent<'a> {
    /// Get this component as a [prim@str]
    #[inline(always)]
    pub fn as_str(&self) -> &'a str {
        match self {
            Self::Namespace(ns) => ns.as_str(),
            Self::Normal(id) => id.as_str(),
        }
    }

    /// Get this component as an [Ident]
    #[inline]
    pub fn to_ident(&self) -> Ident {
        match self {
            Self::Namespace(ns) => ns.to_ident(),
            Self::Normal(id) => Ident::clone(id),
        }
    }
}

impl Eq for LibraryPathComponent<'_> {}

impl PartialEq for LibraryPathComponent<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Namespace(a), Self::Namespace(b)) => a == b,
            (Self::Normal(a), Self::Normal(b)) => a == b,
            _ => false,
        }
    }
}

impl PartialEq<str> for LibraryPathComponent<'_> {
    fn eq(&self, other: &str) -> bool {
        self.as_ref().eq(other)
    }
}

impl AsRef<str> for LibraryPathComponent<'_> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Namespace(ns) => ns.as_str(),
            Self::Normal(ident) => ident.as_str(),
        }
    }
}

impl fmt::Display for LibraryPathComponent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl From<LibraryPathComponent<'_>> for Ident {
    #[inline]
    fn from(component: LibraryPathComponent<'_>) -> Self {
        component.to_ident()
    }
}

/// This is a convenience type alias for a smallvec of [Ident]
type Components = smallvec::SmallVec<[Ident; 1]>;

// LIBRARY PATH
// ================================================================================================

/// Path to a module or a procedure.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub struct LibraryPath {
    inner: Arc<LibraryPathInner>,
}

/// The data of a [LibraryPath] is allocated on the heap to make a [LibraryPath] the size of a
/// pointer, rather than the size of 4 pointers. This makes them cheap to clone and move around.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct LibraryPathInner {
    /// The namespace of this library path
    ns: LibraryNamespace,
    /// The individual components of the path, i.e. the parts delimited by `::`
    components: Components,
}

impl LibraryPath {
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
    /// * The path prefix represents an invalid namespace, see [LibraryNamespace] for details.
    /// * Any component of the path is empty.
    /// * Any component is not a valid identifier (quoted or unquoted) in Miden Assembly syntax,
    ///   i.e. starts with an ASCII alphabetic character, contains only printable ASCII characters,
    ///   except for `::`, which must only be used as a path separator.
    pub fn new(source: impl AsRef<str>) -> Result<Self, PathError> {
        let source = source.as_ref();
        if source.is_empty() {
            return Err(PathError::Empty);
        }

        // Parse namespace
        let mut parts = source.split("::");
        let ns = parts
            .next()
            .ok_or(PathError::Empty)
            .and_then(|part| LibraryNamespace::new(part).map_err(PathError::InvalidNamespace))?;

        // Parse components
        let mut components = Components::default();
        parts.map(Ident::new).try_for_each(|part| {
            part.map_err(PathError::InvalidComponent).map(|c| components.push(c))
        })?;

        Ok(Self::make(ns, components))
    }

    /// Create a [LibraryPath] from pre-validated components
    pub fn new_from_components<I>(ns: LibraryNamespace, components: I) -> Self
    where
        I: IntoIterator<Item = Ident>,
    {
        Self::make(ns, components.into_iter().collect())
    }

    #[inline]
    fn make(ns: LibraryNamespace, components: Components) -> Self {
        Self {
            inner: Arc::new(LibraryPathInner { ns, components }),
        }
    }
}

/// Path metadata
impl LibraryPath {
    /// Return the size of this path in [char]s when displayed as a string
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.components.iter().map(|c| c.len()).sum::<usize>()
            + self.inner.ns.as_str().len()
            + (self.inner.components.len() * 2)
    }

    /// Return the size in bytes of this path when displayed as a string
    pub fn byte_len(&self) -> usize {
        self.inner.components.iter().map(|c| c.len()).sum::<usize>()
            + self.inner.ns.as_str().len()
            + (self.inner.components.len() * 2)
    }

    /// Returns the full path of the Library as a string
    pub fn path(&self) -> Cow<'_, str> {
        if self.inner.components.is_empty() {
            Cow::Borrowed(self.inner.ns.as_str())
        } else {
            Cow::Owned(self.to_string())
        }
    }

    /// Return the namespace component of this path
    pub fn namespace(&self) -> &LibraryNamespace {
        &self.inner.ns
    }

    /// Returns the last component of the path as a `str`
    pub fn last(&self) -> &str {
        self.last_component().as_str()
    }

    /// Returns the last component of the path.
    pub fn last_component(&self) -> LibraryPathComponent<'_> {
        self.inner
            .components
            .last()
            .map(LibraryPathComponent::Normal)
            .unwrap_or_else(|| LibraryPathComponent::Namespace(&self.inner.ns))
    }

    /// Returns the number of components in the path.
    ///
    /// This is guaranteed to return at least 1.
    pub fn num_components(&self) -> usize {
        self.inner.components.len() + 1
    }

    /// Returns an iterator over all components of the path.
    pub fn components(&self) -> impl Iterator<Item = LibraryPathComponent<'_>> + '_ {
        core::iter::once(LibraryPathComponent::Namespace(&self.inner.ns))
            .chain(self.inner.components.iter().map(LibraryPathComponent::Normal))
    }

    /// Returns true if this path is for a kernel module.
    pub fn is_kernel_path(&self) -> bool {
        matches!(self.inner.ns, LibraryNamespace::Kernel)
    }

    /// Returns true if this path is for an executable module.
    pub fn is_exec_path(&self) -> bool {
        matches!(self.inner.ns, LibraryNamespace::Exec)
    }

    /// Returns true if this path is for an anonymous module.
    pub fn is_anon_path(&self) -> bool {
        matches!(self.inner.ns, LibraryNamespace::Anon)
    }

    /// Returns true if `self` starts with `other`
    pub fn starts_with(&self, other: &LibraryPath) -> bool {
        let mut a = self.components();
        let mut b = other.components();
        loop {
            match (a.next(), b.next()) {
                // If we reach the end of `other`, it's a match
                (_, None) => break true,
                // If we reach the end of `self` first, it can't start with `other`
                (None, _) => break false,
                (Some(a), Some(b)) => {
                    // If the two components do not match, we have our answer
                    if a != b {
                        break false;
                    }
                },
            }
        }
    }
}

/// Mutation
impl LibraryPath {
    /// Override the current [LibraryNamespace] for this path.
    pub fn set_namespace(&mut self, ns: LibraryNamespace) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.ns = ns;
    }

    /// Appends the provided path to this path and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the join would produce an invalid path. For example, paths with
    /// reserved namespaces may not be joined to other paths.
    pub fn join(&self, other: &Self) -> Result<Self, PathError> {
        if other.inner.ns.is_reserved() {
            return Err(PathError::UnsupportedJoin);
        }

        let mut path = self.clone();
        {
            let inner = Arc::make_mut(&mut path.inner);
            inner.components.push(other.inner.ns.to_ident());
            inner.components.extend(other.inner.components.iter().cloned());
        }

        Ok(path)
    }

    /// Append the given component to this path.
    ///
    /// Returns an error if the component is not valid.
    pub fn push(&mut self, component: impl AsRef<str>) -> Result<(), PathError> {
        let component = component.as_ref().parse::<Ident>().map_err(PathError::InvalidComponent)?;
        self.push_ident(component);
        Ok(())
    }

    /// Append an [Ident] as a component to this path
    pub fn push_ident(&mut self, component: Ident) {
        let inner = Arc::make_mut(&mut self.inner);
        inner.components.push(component);
    }

    /// Appends the provided component to the end of this path and returns the result.
    ///
    /// Returns an error if the input string is not a valid component.
    pub fn append<S>(&self, component: S) -> Result<Self, PathError>
    where
        S: AsRef<str>,
    {
        let mut path = self.clone();
        path.push(component)?;
        Ok(path)
    }

    /// Appends the provided component to the end of this path and returns the result.
    ///
    /// Returns an error if the input string is not a valid component.
    pub fn append_ident(&self, component: Ident) -> Result<Self, PathError> {
        let mut path = self.clone();
        path.push_ident(component);
        Ok(path)
    }

    /// Adds the provided component to the front of this path and returns the result.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The input string is not a valid [LibraryNamespace]
    /// * The current namespace is a reserved identifier and therefore not a valid path component
    pub fn prepend<S>(&self, component: S) -> Result<Self, PathError>
    where
        S: AsRef<str>,
    {
        let ns = component
            .as_ref()
            .parse::<LibraryNamespace>()
            .map_err(PathError::InvalidNamespace)?;
        let component = self.inner.ns.to_ident();
        let mut components = smallvec![component];
        components.extend(self.inner.components.iter().cloned());
        Ok(Self::make(ns, components))
    }

    /// Pops the last non-namespace component in this path
    pub fn pop(&mut self) -> Option<Ident> {
        let inner = Arc::make_mut(&mut self.inner);
        inner.components.pop()
    }

    /// Returns a new path, representing the current one with the last non-namespace component
    /// removed.
    pub fn strip_last(&self) -> Option<Self> {
        match self.inner.components.len() {
            0 => None,
            1 => Some(Self::make(self.inner.ns.clone(), smallvec![])),
            _ => {
                let ns = self.inner.ns.clone();
                let mut components = self.inner.components.clone();
                components.pop();
                Some(Self::make(ns, components))
            },
        }
    }

    /// Checks if the given input string is a valid [LibraryPath], returning the number of
    /// components in the path.
    ///
    /// See the documentation of [LibraryPath::new] for details on what constitutes a valid path.
    pub fn validate<S>(source: S) -> Result<usize, PathError>
    where
        S: AsRef<str>,
    {
        let source = source.as_ref();

        let mut count = 0;
        let mut components = source.split("::");

        let ns = components.next().ok_or(PathError::Empty)?;
        LibraryNamespace::validate(ns).map_err(PathError::InvalidNamespace)?;
        count += 1;

        for component in components {
            validate_component(component)?;
            count += 1;
        }

        Ok(count)
    }

    /// Returns a new [LibraryPath] with the given component appended without any validation.
    ///
    /// The caller is expected to uphold the validity invariants of [LibraryPath].
    pub fn append_unchecked<S>(&self, component: S) -> Self
    where
        S: AsRef<str>,
    {
        let component = component.as_ref().to_string().into_boxed_str();
        let component = Ident::from_raw_parts(Span::unknown(Arc::from(component)));
        let mut path = self.clone();
        path.push_ident(component);
        path
    }
}

impl<'a> TryFrom<Vec<LibraryPathComponent<'a>>> for LibraryPath {
    type Error = PathError;
    fn try_from(iter: Vec<LibraryPathComponent<'a>>) -> Result<Self, Self::Error> {
        let mut iter = iter.into_iter();
        let ns = match iter.next() {
            None => return Err(PathError::Empty),
            Some(LibraryPathComponent::Namespace(ns)) => ns.clone(),
            Some(LibraryPathComponent::Normal(ident)) => {
                LibraryNamespace::try_from(ident.clone()).map_err(PathError::InvalidNamespace)?
            },
        };
        let mut components = Components::default();
        for component in iter {
            match component {
                LibraryPathComponent::Normal(ident) => components.push(ident.clone()),
                LibraryPathComponent::Namespace(LibraryNamespace::User(name)) => {
                    components.push(Ident::from_raw_parts(Span::unknown(name.clone())));
                },
                LibraryPathComponent::Namespace(_) => return Err(PathError::UnsupportedJoin),
            }
        }
        Ok(Self::make(ns, components))
    }
}

impl From<LibraryNamespace> for LibraryPath {
    fn from(ns: LibraryNamespace) -> Self {
        Self::make(ns, smallvec![])
    }
}

impl From<LibraryPath> for String {
    fn from(path: LibraryPath) -> Self {
        path.to_string()
    }
}

impl TryFrom<String> for LibraryPath {
    type Error = PathError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'a> TryFrom<&'a str> for LibraryPath {
    type Error = PathError;

    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for LibraryPath {
    type Err = PathError;

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serializable for LibraryPath {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let len = self.byte_len();

        target.write_u16(len as u16);
        target.write_bytes(self.inner.ns.as_str().as_bytes());
        for component in self.inner.components.iter() {
            target.write_bytes(b"::");
            target.write_bytes(component.as_str().as_bytes());
        }
    }
}

impl Deserializable for LibraryPath {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u16()? as usize;
        let path = source.read_slice(len)?;
        let path =
            str::from_utf8(path).map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;
        Self::new(path).map_err(|e| DeserializationError::InvalidValue(e.to_string()))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LibraryPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let name = format!("{}", self);
            serializer.serialize_str(&name)
        } else {
            self.inner.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LibraryPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let name = <&'de str as serde::Deserialize>::deserialize(deserializer)?;
            Self::new(name).map_err(serde::de::Error::custom)
        } else {
            let inner = <Arc<LibraryPathInner> as serde::Deserialize>::deserialize(deserializer)?;
            Ok(Self { inner })
        }
    }
}

impl fmt::Display for LibraryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.ns)?;
        for component in self.inner.components.iter() {
            write!(f, "::{component}")?;
        }
        Ok(())
    }
}

fn validate_component(component: &str) -> Result<(), PathError> {
    if component.is_empty() {
        Err(PathError::EmptyComponent)
    } else if component.len() > LibraryNamespace::MAX_LENGTH {
        Err(PathError::InvalidComponent(IdentError::InvalidLength {
            max: LibraryNamespace::MAX_LENGTH,
        }))
    } else {
        Ident::validate(component).map_err(PathError::InvalidComponent)
    }
}

// ARBITRARY IMPLEMENTATION
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for LibraryPath {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        let wasm_cm_style = LibraryPath::new_from_components(
            LibraryNamespace::Anon,
            [Ident::new("namespace-kebab:package-kebab/interface-kebab@1.0.0").unwrap()],
        );
        let path_len_2 = LibraryPath::new_from_components(
            LibraryNamespace::User("user_ns".into()),
            [Ident::new("user_module").unwrap()],
        );
        let path_len_3 = LibraryPath::new_from_components(
            LibraryNamespace::User("userns".into()),
            [Ident::new("user_path1").unwrap(), Ident::new("user_module").unwrap()],
        );
        prop_oneof![Just(wasm_cm_style), Just(path_len_2), Just(path_len_3)].boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// TESTS
// ================================================================================================

/// Tests
#[cfg(test)]
mod tests {

    use miden_core::{
        assert_matches,
        utils::{Deserializable, Serializable},
    };
    use proptest::prelude::*;

    use super::{super::LibraryNamespaceError, IdentError, LibraryPath, PathError};

    #[test]
    fn new_path() {
        let path = LibraryPath::new("foo").unwrap();
        assert_eq!(path.num_components(), 1);

        let path = LibraryPath::new("foo::bar").unwrap();
        assert_eq!(path.num_components(), 2);

        let path = LibraryPath::new("foo::bar::baz").unwrap();
        assert_eq!(path.num_components(), 3);

        let path = LibraryPath::new("miden:base/account@0.1.0").unwrap();
        assert_eq!(path.num_components(), 1);

        let path = LibraryPath::new("$exec::bar::baz").unwrap();
        assert_eq!(path.num_components(), 3);

        let path = LibraryPath::new("$kernel::bar::baz").unwrap();
        assert_eq!(path.num_components(), 3);
    }

    #[test]
    fn new_path_fail() {
        let path = LibraryPath::new("");
        assert_matches!(path, Err(PathError::Empty));

        let path = LibraryPath::new("::");
        assert_matches!(path, Err(PathError::InvalidNamespace(LibraryNamespaceError::Empty)));

        let path = LibraryPath::new("foo::");
        assert_matches!(path, Err(PathError::InvalidComponent(IdentError::Empty)));

        let path = LibraryPath::new("::foo");
        assert_matches!(path, Err(PathError::InvalidNamespace(LibraryNamespaceError::Empty)));

        let path = LibraryPath::new("#foo::bar");
        assert_matches!(
            path,
            Err(PathError::InvalidNamespace(LibraryNamespaceError::InvalidStart))
        );
    }

    proptest! {
        #[test]
        fn path_serialization_roundtrip(path in any::<LibraryPath>()) {
            let bytes = path.to_bytes();
            let deserialized = LibraryPath::read_from_bytes(&bytes).unwrap();
            assert_eq!(path, deserialized);
        }
    }
}
