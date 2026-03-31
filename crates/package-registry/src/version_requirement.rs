use core::fmt;

use miden_assembly_syntax::debuginfo::Span;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::*;
use crate::{LexicographicWord, Word};

/// Represents a requirement on a specific version (or versions) of a dependency.
#[derive(Debug, Clone)]
pub enum VersionRequirement {
    /// A semantic versioning constraint, e.g. `~> 0.1`
    ///
    /// In general, this is meant to indicate that any version of a package that satisfies the
    /// version constraint can be used to resolve the dependency.
    ///
    /// This form of constraint also permits us to compile a dependency from source, so long as
    /// the semantic versioning constraint is satisfied.
    Semantic(Span<VersionReq>),
    /// The most precise and onerous form of versioning constraint.
    ///
    /// This requires that the dependency's package digest exactly matches the one provided here.
    ///
    /// Digest constraints also effectively require that the dependency already be compiled to a
    /// Miden package, as digests are derived from the MAST of a compiled package. This means that
    /// when the dependency is resolved, we must be able to find a `.masp` file with the expected
    /// digest.
    Digest(Span<Word>),
    /// Requires an exact assembled package version, including both semantic version and digest.
    Exact(Version),
}

impl VersionRequirement {
    /// Returns true if this version requirement is a semantic versioning requirement
    pub fn is_semantic_version(&self) -> bool {
        matches!(self, Self::Semantic(_))
    }

    /// Returns true if this version requirement requires an exact digest match
    pub fn is_digest(&self) -> bool {
        matches!(self, Self::Digest(_))
    }

    /// Returns true if this version requirement requires an exact assembled version match.
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

impl Eq for VersionRequirement {}

impl PartialEq for VersionRequirement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(l), Self::Exact(r)) => l == r,
            (Self::Digest(l), Self::Digest(r)) => {
                LexicographicWord::new(l.into_inner()) == LexicographicWord::new(r.into_inner())
            },
            (Self::Semantic(l), Self::Semantic(r)) => l == r,
            (Self::Semantic(_) | Self::Exact(_), Self::Digest(_))
            | (Self::Semantic(_), Self::Exact(_))
            | (Self::Digest(_), Self::Semantic(_) | Self::Exact(_))
            | (Self::Exact(_), Self::Semantic(_)) => false,
        }
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semantic(v) => fmt::Display::fmt(v, f),
            Self::Digest(word) => fmt::Display::fmt(word, f),
            Self::Exact(version) => {
                assert!(
                    version.digest.is_some(),
                    "exact requirements must include an artifact digest"
                );
                write!(f, "{version}")
            },
        }
    }
}

impl From<VersionReq> for VersionRequirement {
    fn from(version: VersionReq) -> Self {
        Self::Semantic(Span::unknown(version))
    }
}

impl From<Word> for VersionRequirement {
    fn from(digest: Word) -> Self {
        Self::Digest(Span::unknown(digest))
    }
}

impl From<Version> for VersionRequirement {
    fn from(value: Version) -> Self {
        if value.digest.is_none() {
            Self::Semantic(Span::unknown(format!("={}", &value.version).parse().unwrap()))
        } else {
            Self::Exact(value)
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for VersionRequirement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::string::ToString;
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for VersionRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::str::FromStr;

        let value = <alloc::string::String as Deserialize>::deserialize(deserializer)?;

        if value == "*" {
            return Ok(Self::from(VersionReq::STAR.clone()));
        }

        if let Some((version, digest)) = value.split_once('#') {
            let version = version.parse::<SemVer>().map_err(serde::de::Error::custom)?;
            let digest = Word::parse(digest).map_err(serde::de::Error::custom)?;
            return Ok(Self::Exact(Version::new(version, digest)));
        }

        if let Ok(digest) = Word::parse(&value) {
            return Ok(Self::from(digest));
        }

        let requirement = VersionReq::from_str(&value).map_err(serde::de::Error::custom)?;
        Ok(Self::from(requirement))
    }
}
