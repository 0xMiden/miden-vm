use alloc::{string::ToString, sync::Arc};
use core::{borrow::Borrow, fmt, ops::Deref};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A type that represents the unique identifier for packages in a registry.
///
/// This is a simple newtype wrapper around an [`Arc<str>`] so that we can provide some ergonomic
/// conveniences, and allow migration to some other type in the future with minimal downstream
/// impact, if any.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[repr(transparent)]
pub struct PackageId(Arc<str>);

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

impl From<alloc::string::String> for PackageId {
    fn from(value: alloc::string::String) -> Self {
        Self(value.into_boxed_str().into())
    }
}
