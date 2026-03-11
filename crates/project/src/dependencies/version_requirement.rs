use core::fmt;

#[cfg(feature = "serde")]
use miden_assembly_syntax::debuginfo::SourceId;
use miden_assembly_syntax::debuginfo::Span;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::*;
#[cfg(feature = "serde")]
use crate::ast::parsing::SetSourceId;
use crate::{LexicographicWord, Word};

/// Represents a requirement on a specific version (or versions) of a dependency.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
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
}

#[cfg(feature = "serde")]
impl SetSourceId for VersionRequirement {
    fn set_source_id(&mut self, source_id: SourceId) {
        match self {
            Self::Semantic(version) => version.set_source_id(source_id),
            Self::Digest(digest) => digest.set_source_id(source_id),
        }
    }
}

impl Eq for VersionRequirement {}

impl PartialEq for VersionRequirement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Semantic(l), Self::Semantic(r)) => l == r,
            (Self::Semantic(_), Self::Digest(_)) | (Self::Digest(_), Self::Semantic(_)) => false,
            (Self::Digest(l), Self::Digest(r)) => {
                LexicographicWord::new(l.into_inner()) == LexicographicWord::new(r.into_inner())
            },
        }
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semantic(v) => fmt::Display::fmt(v, f),
            Self::Digest(word) => fmt::Display::fmt(word, f),
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
