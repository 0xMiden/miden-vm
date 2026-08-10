use core::fmt;

use miden_assembly_syntax::debuginfo::Span;
#[cfg(feature = "arbitrary")]
use miden_core::utils::hash_string_to_word;
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use super::*;
use crate::Word;

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
            (Self::Digest(l), Self::Digest(r)) => l.into_inner() == r.into_inner(),
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
            Self::Semantic(Span::unknown(format!("={}", value.version).parse().unwrap()))
        } else {
            Self::Exact(value)
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for VersionRequirement {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let semantic =
            (0u64..=4, 0u64..=8, 0u64..=16, 0u8..=2).prop_map(|(major, minor, patch, kind)| {
                let req = match kind {
                    0 => format!("^{major}.{minor}.{patch}"),
                    1 => format!("~{major}.{minor}.{patch}"),
                    _ => format!("={major}.{minor}.{patch}"),
                }
                .parse::<VersionReq>()
                .expect("generated version requirements are valid");

                Self::Semantic(Span::unknown(req))
            });

        let digest =
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..16).prop_map(|chars| {
                let material = chars.into_iter().collect::<String>();
                let digest = hash_string_to_word(material.as_str());
                Self::Digest(Span::unknown(digest))
            });

        let exact = any::<Version>()
            .prop_filter("exact requirements must include a digest", |version| {
                version.digest.is_some()
            })
            .prop_map(Self::Exact);

        proptest::prop_oneof![Just(Self::from(VersionReq::STAR)), semantic, digest, exact,].boxed()
    }
}
