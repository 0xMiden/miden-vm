use alloc::sync::Arc;

use miden_core::Word;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{PackageId, version::VersionSelection};
use crate::Linkage;

/// Represents a dependency that was resolved to a specific version
///
/// This is intended for use in dependency resolution, and for representing the set of dependencies
/// that a package was built against.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResolvedDependency {
    /// The name of the dependency
    pub name: Arc<str>,
    /// The resolved version information
    ///
    /// NOTE: When representing a version that was selected by the resolver, the digest of the
    /// associated package may be unknown. However, when representing the version of a dependency
    /// that a package was built against, the digest is guaranteed to be known, and so is expected
    /// to be always set when this struct is stored in a `miden_mast_package::Package`.
    pub version: VersionSelection,
}

impl From<(PackageId, VersionSelection)> for ResolvedDependency {
    fn from((name, version): (PackageId, VersionSelection)) -> Self {
        Self { name: name.into(), version }
    }
}

impl From<(&PackageId, &VersionSelection)> for ResolvedDependency {
    fn from((name, version): (&PackageId, &VersionSelection)) -> Self {
        Self {
            name: name.clone().into(),
            version: version.clone(),
        }
    }
}

impl ResolvedDependency {
    /// Get the digest of the resolved dependency version, if known.
    pub fn digest(&self) -> Option<&Word> {
        self.version.version.digest.as_ref().map(|word| word.inner())
    }

    /// Get the linkage to use for this dependency
    pub fn linkage(&self) -> Option<Linkage> {
        self.version.linkage
    }
}

#[cfg(feature = "resolver")]
impl From<&ResolvedDependency> for super::VersionSet {
    fn from(value: &ResolvedDependency) -> Self {
        super::VersionSet::singleton(value.version.clone())
    }
}

#[cfg(feature = "resolver")]
impl From<ResolvedDependency> for super::VersionSet {
    fn from(value: ResolvedDependency) -> Self {
        super::VersionSet::singleton(value.version)
    }
}

mod serialization {
    use miden_core::serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    };

    use crate::{Linkage, dependencies::version::VersionSelection};

    impl Serializable for super::ResolvedDependency {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            target.write_usize(self.name.len());
            target.write_bytes(self.name.as_bytes());
            self.version.version.write_into(target);
            if let Some(linkage) = self.version.linkage {
                target.write_bool(true);
                linkage.write_into(target);
            } else {
                target.write_bool(true);
            }
        }
    }

    impl Deserializable for super::ResolvedDependency {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            let len = source.read_usize()?;
            let name = source.read_string(len)?.into_boxed_str().into();
            let version = crate::Version::read_from(source)?;
            let linkage = if source.read_bool()? {
                Some(Linkage::read_from(source)?)
            } else {
                None
            };
            Ok(Self {
                name,
                version: VersionSelection { version, linkage },
            })
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for ResolvedDependency {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        let name = any::<PackageId>();
        let version = any::<crate::Version>();
        let linkage = any::<Option<Linkage>>();

        (name, version, linkage)
            .prop_map(|(name, version, linkage)| Self {
                name: name.into(),
                version: VersionSelection { version, linkage },
            })
            .boxed()
    }
}
