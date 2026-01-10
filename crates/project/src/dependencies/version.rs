use core::{borrow::Borrow, fmt, str::FromStr};

pub use miden_assembly_syntax::semver::{Error as SemVerError, Version as SemVer, VersionReq};
use miden_core::{LexicographicWord, Word};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::VersionRequirement;
use crate::Linkage;

/// The error type raised when attempting to parse a [Version] from a string.
#[derive(Debug, thiserror::Error)]
pub enum InvalidVersionError {
    #[error("invalid digest: {0}")]
    Digest(&'static str),
    #[error("invalid semantic version: {0}")]
    Version(SemVerError),
}

/// The representation of versioning information associated with packages in the package index.
///
/// This type provides the means by which dependency resolution can satisfy versioning constraints
/// on packages using either semantic version constraints or explicit package digests
/// simultaneously.
///
/// All packages have an associated semantic version. Packages which have been assembled to MAST,
/// also have an associated content digest. However, for the purposes of indexing and dependency
/// resolution, we cannot assume that all packages have a content digest (as they may not have been
/// assembled yet), and so this type is used to represent versions within the index/resolver so that
/// it can:
///
/// * Satisfy requirements for a package that has a specific digest
/// * Record multiple entries in the index for the same semantic version string, when multiple
///   assembled packages with that version are present, disambiguating using the content digest.
/// * Provide a total ordering for package versions that may or may not include a specific digest
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version {
    /// The semantic version information
    ///
    /// This is the canonical human-facing version for a package.
    pub version: SemVer,
    /// The content digest for this version, if known.
    ///
    /// This is the most precise version for a package, and is used to disambiguate multiple
    /// instances of a package with the same semantic version, but differing content.
    #[cfg_attr(feature = "serde", serde(with = "maybe_digest"))]
    pub digest: Option<LexicographicWord>,
}

/// Represents a specific version selection during dependency resolution.
///
/// This differs from just a [Version] in that it also carries the linkage requested by the
/// dependent, allowing us to propagate that information up the dependency tree.
///
/// Each node in the dependency tree controls the linkage of its direct dependents, and so may
/// override choices of transitive dependencies by making them direct and changing the linkage.
///
/// The equality, ordering, and hashing implementations for this type disregard the linkage, as it
/// is considered discardable metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VersionSelection {
    /// The selected version
    pub version: Version,
    /// The linkage requested by the dependent
    pub linkage: Option<Linkage>,
}

impl Eq for VersionSelection {}

impl PartialEq for VersionSelection {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl PartialOrd for VersionSelection {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VersionSelection {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.version.cmp(&other.version)
    }
}

impl core::hash::Hash for VersionSelection {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
    }
}

impl fmt::Display for VersionSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.version, f)
    }
}

impl<V> From<V> for VersionSelection
where
    V: Into<Version>,
{
    fn from(value: V) -> Self {
        Self { version: value.into(), linkage: None }
    }
}

#[cfg(feature = "serde")]
mod maybe_digest {
    use miden_core::LexicographicWord;
    use serde::*;

    pub fn serialize<S>(
        digest: &Option<LexicographicWord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        digest.map(|word| word.into_inner()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<LexicographicWord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<miden_core::Word>::deserialize(deserializer)? {
            Some(word) => Ok(Some(LexicographicWord::new(word))),
            None => Ok(None),
        }
    }
}

mod ser {
    use alloc::format;

    use miden_core::serde::{Deserializable, DeserializationError, Serializable};

    use super::*;

    impl Serializable for Version {
        fn write_into<W: miden_core::serde::ByteWriter>(&self, target: &mut W) {
            self.version.major.write_into(target);
            self.version.minor.write_into(target);
            self.version.patch.write_into(target);

            let pre = self.version.pre.as_str();
            target.write_usize(pre.len());
            target.write_bytes(pre.as_bytes());

            let build = self.version.build.as_str();
            target.write_usize(build.len());
            target.write_bytes(build.as_bytes());

            if let Some(digest) = self.digest {
                target.write_bool(true);
                digest.inner().write_into(target);
            } else {
                target.write_bool(false);
            }
        }
    }

    impl Deserializable for Version {
        fn read_from<R: miden_core::serde::ByteReader>(
            source: &mut R,
        ) -> Result<Self, DeserializationError> {
            let major = source.read_u64()?;
            let minor = source.read_u64()?;
            let patch = source.read_u64()?;

            let pre_len = source.read_usize()?;
            let pre =
                crate::semver::Prerelease::new(&source.read_string(pre_len)?).map_err(|err| {
                    DeserializationError::InvalidValue(format!("invalid prerelease: {err}"))
                })?;
            let build_len = source.read_usize()?;
            let build = crate::semver::BuildMetadata::new(&source.read_string(build_len)?)
                .map_err(|err| {
                    DeserializationError::InvalidValue(format!("invalid build metadata: {err}"))
                })?;

            let digest = if source.read_bool()? {
                Some(LexicographicWord::new(Word::read_from(source)?))
            } else {
                None
            };

            Ok(Self {
                version: SemVer {
                    pre,
                    build,
                    ..SemVer::new(major, minor, patch)
                },
                digest,
            })
        }
    }
}

impl core::hash::Hash for Version {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
        let digest = self.digest.as_ref().map(|word| *word.inner());
        digest.hash(state);
    }
}

impl Version {
    /// Construct a [Version] from its component parts.
    pub fn new(version: SemVer, digest: Word) -> Self {
        Self { version, digest: Some(digest.into()) }
    }

    /// Check if this version satisfies the given `requirement`.
    ///
    /// Version requirements are expressed as either a semantic version constraint OR a specific
    /// content digest.
    pub fn satisfies(&self, requirement: &VersionRequirement) -> bool {
        match requirement {
            VersionRequirement::Semantic(req) => req.matches(&self.version),
            VersionRequirement::Digest(req) => self
                .digest
                .as_ref()
                .is_some_and(|digest| &LexicographicWord::new(req.into_inner()) == digest),
        }
    }
}

impl FromStr for Version {
    type Err = InvalidVersionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('#') {
            Some((v, digest)) => {
                let v = v.parse::<SemVer>().map_err(InvalidVersionError::Version)?;
                let digest = Word::parse(digest).map_err(InvalidVersionError::Digest)?;
                Ok(Self::new(v, digest))
            },
            None => {
                let v = s.parse::<SemVer>().map_err(InvalidVersionError::Version)?;
                Ok(Self::from(v))
            },
        }
    }
}

impl From<SemVer> for Version {
    fn from(version: SemVer) -> Self {
        Self { version, digest: None }
    }
}

impl From<(SemVer, Word)> for Version {
    fn from(version: (SemVer, Word)) -> Self {
        let (version, word) = version;
        Self { version, digest: Some(word.into()) }
    }
}

impl Borrow<SemVer> for Version {
    #[inline(always)]
    fn borrow(&self) -> &SemVer {
        &self.version
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(digest) = self.digest.as_ref() {
            write!(f, "{}#{}", &self.version, digest.inner())
        } else {
            fmt::Display::fmt(&self.version, f)
        }
    }
}

impl Eq for Version {}
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        if self.version != other.version {
            return false;
        }
        if let Some(l) = self.digest.as_ref()
            && let Some(r) = other.digest.as_ref()
        {
            l == r
        } else {
            true
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        self.version.cmp_precedence(&other.version).then_with(|| {
            if let Some(l) = self.digest.as_ref()
                && let Some(r) = other.digest.as_ref()
            {
                l.cmp(r)
            } else {
                Ordering::Equal
            }
        })
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary {
    use alloc::format;
    use core::ops::Bound;

    use miden_core::Felt;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        dependencies::version_requirement::bounding_range,
        semver::{BuildMetadata, Prerelease},
    };

    impl Version {
        /// Generate an arbitrary [Version] which may or may not have a random digest set.
        pub fn any_version() -> impl Strategy<Value = Self> {
            any_version()
        }

        /// Generate an arbitrary [Version] with its digest set to `digest`
        pub fn any_version_with_digest(digest: Word) -> impl Strategy<Value = Self> {
            any_version_with_digest(digest)
        }

        /// Generate an arbitrary [Version] matching `requirement`
        pub fn any_version_matching(requirement: VersionReq) -> impl Strategy<Value = Self> {
            any_version_matching(requirement)
        }
    }

    impl Arbitrary for Version {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any_version().boxed()
        }
    }

    prop_compose! {
        fn maybe_pre(probability: f64)(
            counter in prop::option::weighted(probability, 0u32..8u32)
        ) -> Prerelease {
            counter.map(|count| {
                let pre = format!("pre{count}");
                Prerelease::new(&pre).unwrap()
            }).unwrap_or(Prerelease::EMPTY)
        }
    }

    prop_compose! {
        fn maybe_digest(probability: f64)(
            word in prop::option::weighted(probability, prop::array::uniform4(any::<u64>()))
        ) -> Option<LexicographicWord> {
            word.map(|word| LexicographicWord::new(Word::new([
                Felt::new(word[0]),
                Felt::new(word[1]),
                Felt::new(word[2]),
                Felt::new(word[3]),
            ])))
        }
    }

    prop_compose! {
        pub fn any_semver()(
            major in 0u64..20u64,
            minor in 0u64..100u64,
            patch in 0u64..100u64,
            pre in maybe_pre(0.1),
        ) -> SemVer {
            SemVer {
                major,
                minor,
                patch,
                pre,
                build: BuildMetadata::EMPTY,
            }
        }
    }

    prop_compose! {
        pub fn any_semver_matching_bounds(bounds: (Bound<SemVer>, Bound<SemVer>))(
            major in select_bounded(&bounds, |v| v.major),
            minor in select_bounded(&bounds, |v| v.minor),
            patch in select_bounded(&bounds, |v| v.patch),
        ) -> SemVer {
            SemVer {
                major,
                minor,
                patch,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            }
        }
    }

    prop_compose! {
        pub fn any_version()(version in any_semver(), digest in maybe_digest(0.5)) -> Version {
            Version {
                version,
                digest,
            }
        }
    }

    prop_compose! {
        pub fn any_version_with_digest(digest: Word)(version in any_semver()) -> Version {
            Version {
                version,
                digest: Some(LexicographicWord::new(digest)),
            }
        }
    }

    prop_compose! {
        pub fn any_version_matching(req: VersionReq)(version in any_semver_matching_bounds(bounding_range(&req))) -> Version {
            Version {
                version,
                digest: None,
            }
        }
    }

    fn select_bounded<F>(bounds: &(Bound<SemVer>, Bound<SemVer>), mapper: F) -> BoxedStrategy<u64>
    where
        F: Fn(&SemVer) -> u64,
    {
        use Bound::*;

        match bounds {
            (Unbounded, Unbounded) => any::<u64>().boxed(),
            (Unbounded, Included(v)) => (0u64..=mapper(v)).boxed(),
            (Unbounded, Excluded(v)) => (0u64..mapper(v)).boxed(),
            (Included(v), Unbounded) => (mapper(v)..).boxed(),
            (Included(v), Included(v2)) => (mapper(v)..=mapper(v2)).boxed(),
            (Included(v), Excluded(v2)) => (mapper(v)..mapper(v2)).boxed(),
            (Excluded(v), Unbounded) => ((mapper(v) + 1)..).boxed(),
            (Excluded(v), Included(v2)) => ((mapper(v) + 1)..=mapper(v2)).boxed(),
            (Excluded(v), Excluded(v2)) => ((mapper(v) + 1)..mapper(v2)).boxed(),
        }
    }
}
