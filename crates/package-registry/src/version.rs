use core::{borrow::Borrow, fmt, str::FromStr};

pub use miden_assembly_syntax::semver::{Error as SemVerError, Version as SemVer};
use miden_core::Word;
#[cfg(feature = "arbitrary")]
use miden_core::utils::hash_string_to_word;
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::VersionRequirement;

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
/// * Record the exact published identity of a canonical package artifact as `semver#digest`
/// * Provide a total ordering for package versions that may or may not include a specific digest
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct Version {
    /// The semantic version information
    ///
    /// This is the canonical human-facing version for a package.
    pub version: SemVer,
    /// The content digest for this version, if known.
    ///
    /// This is the most precise version for a package, and uniquely identifies the canonical
    /// published artifact associated with a semantic version.
    pub digest: Option<Word>,
}

#[cfg(feature = "serde")]
impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::string::ToString;

        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <alloc::string::String as Deserialize>::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl Version {
    /// Construct a [Version] from its component parts.
    pub fn new(version: SemVer, digest: Word) -> Self {
        Self { version, digest: Some(digest) }
    }

    /// Get a [Version] without an attached digest for comparison purposes
    pub fn without_digest(&self) -> Self {
        Self {
            version: self.version.clone(),
            digest: None,
        }
    }

    /// Get a [core::ops::Range] which can be used to select all available versions with the same
    /// semantic version, but with possibly-differing digests
    pub fn as_range(&self) -> core::ops::Range<Version> {
        let start = self.without_digest();
        let mut end = start.clone();
        end.version.patch += 1;

        start..end
    }

    /// Returns true if `self` and `other` are equivalent with regards to semantic versioning
    pub fn is_semantically_equivalent(&self, other: &Self) -> bool {
        self.version.cmp_precedence(&other.version).is_eq()
    }

    /// Check if this version satisfies the given `requirement`.
    ///
    /// Version requirements are expressed as either a semantic version constraint OR a specific
    /// content digest.
    pub fn satisfies(&self, requirement: &VersionRequirement) -> bool {
        match requirement {
            VersionRequirement::Semantic(req) => req.matches(&self.version),
            VersionRequirement::Digest(req) => {
                self.digest.as_ref().is_some_and(|digest| req.into_inner() == *digest)
            },
            VersionRequirement::Exact(req) => self == req,
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
        Self { version, digest: Some(word) }
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
            write!(f, "{}#{digest}", &self.version)
        } else {
            fmt::Display::fmt(&self.version, f)
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
            match (self.digest.as_ref(), other.digest.as_ref()) {
                (None, None) => Ordering::Equal,
                (Some(l), Some(r)) => l.cmp(r),
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
            }
        })
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for Version {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let semver = (0u64..=5, 0u64..=15, 0u64..=31).prop_map(|(major, minor, patch)| {
            format!("{major}.{minor}.{patch}")
                .parse::<SemVer>()
                .expect("generated semantic versions are valid")
        });
        let digest = proptest::option::of(
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..16).prop_map(|chars| {
                let material = chars.into_iter().collect::<alloc::string::String>();
                hash_string_to_word(material.as_str())
            }),
        );

        (semver, digest).prop_map(|(version, digest)| Self { version, digest }).boxed()
    }
}
