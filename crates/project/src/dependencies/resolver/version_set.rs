use core::fmt;
use std::collections::BTreeSet;

use miden_core::{LexicographicWord, Word};
use pubgrub::VersionSet as _;
use smallvec::{SmallVec, smallvec};

use super::pubgrub_compat::SemverPubgrub;
use crate::{SemVer, Version, VersionReq, VersionRequirement};

/// This type is an implementation detail of the dependency resolver provided by
/// [`super::PackageIndex`].
///
/// A [VersionSet], as implied by the name, provides set semantics for semantic versioning ranges
/// that may also be further constrained by specific content digests that are considered to be part
/// of the set.
///
/// * The empty set is represented as a range that cannot contain any version
/// * The complete (aka "full") set is represented as an unbounded range with
///   an empty content digest filter, equivalent to the semantic versioning constraint `*`
/// * Set intersection is performed by finding the overlap in the ranges of the two sets, and then
///   if either set has a content digest filter, only permitting content digests that are present
///   in both sets
/// * Set complement is performed by negating the range of versions included in the set. The
///   resulting set will always have an empty content digest filter.
/// * Set containment for a version `v` is determined as follows:
///   * If the semantic version component of `v` is covered by any range in the set, it is
///     provisionally considered to be contained in the set, IFF
///   * If the set specifies a content digest filter, then `v` must have a content digest component
///     that matches that filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSet {
    /// The range(s) of semantic versions that are included in the set
    range: SemverPubgrub,
    /// The content digest filter, represented as the set of content digests that are considered
    /// to be members of this set. When non-empty, the set _only_ includes versions that are
    /// considered contained in `range` _and_ have a content digest in `digests`.
    digests: SmallVec<[LexicographicWord; 1]>,
}

/// Represents an additional filter on the versions considered a member of a [VersionSet].
pub enum VersionSetFilter<'a> {
    /// Matches any version, regardless of content digest
    Any,
    /// Matches only versions which have a content digest in the given set of digests
    Digest(&'a [LexicographicWord]),
}

impl VersionSetFilter<'_> {
    /// Returns true if `version` passes this filter, i.e. would be included in the associated set.
    pub fn matches(&self, version: &Version) -> bool {
        match self {
            Self::Any => true,
            Self::Digest(digests) => {
                version.digest.as_ref().is_some_and(|digest| digests.contains(digest))
            },
        }
    }
}

impl VersionSet {
    /// Get the semantic version range(s) that are members of this set
    pub fn range(&self) -> &SemverPubgrub {
        &self.range
    }

    /// Get the filter applied to provisional members of this set when determining containment.
    pub fn filter(&self) -> VersionSetFilter<'_> {
        if self.digests.is_empty() {
            VersionSetFilter::Any
        } else {
            VersionSetFilter::Digest(&self.digests)
        }
    }
}

impl Default for VersionSet {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Word> for VersionSet {
    fn from(value: Word) -> Self {
        Self {
            range: SemverPubgrub::empty(),
            digests: smallvec![LexicographicWord::new(value)],
        }
    }
}

impl From<SemVer> for VersionSet {
    fn from(value: SemVer) -> Self {
        Self {
            range: SemverPubgrub::singleton(value),
            digests: smallvec![],
        }
    }
}

impl From<Version> for VersionSet {
    fn from(value: Version) -> Self {
        let Version { version, digest } = value;
        Self {
            range: SemverPubgrub::singleton(version),
            digests: SmallVec::from_iter(digest),
        }
    }
}

impl From<VersionReq> for VersionSet {
    fn from(value: VersionReq) -> Self {
        Self {
            range: SemverPubgrub::from(&value),
            digests: smallvec![],
        }
    }
}

impl From<&VersionReq> for VersionSet {
    fn from(value: &VersionReq) -> Self {
        Self {
            range: SemverPubgrub::from(value),
            digests: smallvec![],
        }
    }
}

impl From<VersionRequirement> for VersionSet {
    fn from(value: VersionRequirement) -> Self {
        match value {
            VersionRequirement::Digest(digest) => Self::from(digest.into_inner()),
            VersionRequirement::Semantic(req) => Self::from(req.inner()),
        }
    }
}

impl From<SemverPubgrub> for VersionSet {
    fn from(range: SemverPubgrub) -> Self {
        Self { range, digests: smallvec![] }
    }
}

impl fmt::Display for VersionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.digests.as_slice() {
            [] => write!(f, "{}", &self.range),
            [digest] => write!(f, "{} in {}", digest.inner(), &self.range),
            digests => {
                f.write_str("any of ")?;
                for (i, digest) in digests.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", &digest.inner())?;
                }
                write!(f, " in {}", &self.range)
            },
        }
    }
}

impl pubgrub::VersionSet for VersionSet {
    type V = Version;

    fn empty() -> Self {
        Self::from(SemverPubgrub::empty())
    }

    fn singleton(v: Self::V) -> Self {
        Self::from(v)
    }

    fn full() -> Self {
        Self::from(SemverPubgrub::full())
    }

    fn complement(&self) -> Self {
        Self::from(self.range.complement())
    }

    fn intersection(&self, other: &Self) -> Self {
        if self.digests.is_empty() && other.digests.is_empty() {
            return Self::from(self.range.intersection(&other.range));
        }

        let ldigests = BTreeSet::from_iter(self.digests.iter());
        let rdigests = BTreeSet::from_iter(other.digests.iter());
        let digests = ldigests.intersection(&rdigests).map(|d| **d).collect();
        let range = self.range.intersection(&other.range);
        Self { range, digests }
    }

    fn contains(&self, v: &Self::V) -> bool {
        if let Some(digest) = v.digest.as_ref() {
            self.digests.contains(digest)
        } else {
            self.range.contains(&v.version)
        }
    }
}
