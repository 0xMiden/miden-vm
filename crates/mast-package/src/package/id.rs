use alloc::{string::ToString, sync::Arc};
use core::{borrow::Borrow, fmt, ops::Deref};

#[cfg(all(feature = "arbitrary", test))]
use miden_core::serde::{Deserializable, Serializable};
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
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
#[repr(transparent)]
pub struct PackageId(Arc<str>);

impl PackageId {
    #[inline(always)]
    pub fn into_inner(self) -> Arc<str> {
        self.0
    }
}

impl PartialEq<str> for PackageId {
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref() == other
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

impl From<alloc::string::String> for PackageId {
    fn from(value: alloc::string::String) -> Self {
        Self(value.into_boxed_str().into())
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for PackageId {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use alloc::string::String;

        use proptest::prelude::Strategy;

        let chars = proptest::char::range('a', 'z');
        proptest::collection::vec(chars, 4..32)
            .prop_map(|chars| Self(String::from_iter(chars).into_boxed_str().into()))
            .no_shrink()  // Pure random strings, no meaningful shrinking pattern
            .boxed()
    }
}

mod serialization {
    use miden_core::serde::*;

    use super::PackageId;

    impl Serializable for PackageId {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            // This is equivalent to String::write_into
            target.write_usize(self.0.len());
            target.write_bytes(self.0.as_bytes());
        }
    }

    impl Deserializable for PackageId {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            alloc::string::String::read_from(source).map(Self::from)
        }
    }
}
