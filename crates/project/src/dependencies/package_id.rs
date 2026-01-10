use alloc::{string::ToString, sync::Arc};
use core::{borrow::Borrow, fmt, ops::Deref};

use crate::Version;

/// Represents a specific instance of a package for a given version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionedPackageId {
    pub id: PackageId,
    pub version: Version,
}

impl fmt::Debug for VersionedPackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for VersionedPackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", &self.id, &self.version)
    }
}

/// A type that represents the unique identifier for packages in a [`super::PackageIndex`].
///
/// This is a simple newtype wrapper around an [`Arc<str>`] so that we can provide some ergonomic
/// conveniences, and allow migration to some other type in the future with minimal downstream
/// impact, if any.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PackageId(Arc<str>);

impl PartialEq<Arc<str>> for PackageId {
    fn eq(&self, other: &Arc<str>) -> bool {
        &self.0 == other
    }
}

impl PartialEq<PackageId> for Arc<str> {
    fn eq(&self, other: &PackageId) -> bool {
        self == &other.0
    }
}

impl From<PackageId> for Arc<str> {
    #[inline(always)]
    fn from(value: PackageId) -> Self {
        value.0
    }
}

impl From<&PackageId> for Arc<str> {
    fn from(value: &PackageId) -> Self {
        value.0.clone()
    }
}

impl Borrow<str> for PackageId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Borrow<Arc<str>> for PackageId {
    fn borrow(&self) -> &Arc<str> {
        &self.0
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for PackageId {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl AsRef<Arc<str>> for PackageId {
    #[inline(always)]
    fn as_ref(&self) -> &Arc<str> {
        &self.0
    }
}

impl Deref for PackageId {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl From<Arc<str>> for PackageId {
    fn from(value: Arc<str>) -> Self {
        Self(value)
    }
}

impl From<&str> for PackageId {
    fn from(value: &str) -> Self {
        Self(value.to_string().into_boxed_str().into())
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::prelude::Arbitrary for PackageId {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        prop::string::string_regex("[a-z][a-z0-9_-]+")
            .unwrap()
            .prop_map(|s| Self(Arc::from(s.into_boxed_str())))
            .boxed()
    }
}
