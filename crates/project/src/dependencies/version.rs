#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use miden_assembly_syntax::debuginfo::{SourceId, Span};

pub use miden_assembly_syntax::semver::{Version, VersionReq};

use crate::Word;

/// Represents a constraint on the version of a dependency that should be resolved
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum VersionReqOrDigest {
    /// A semantic versioning constraint, e.g. `~> 0.1`
    ///
    /// In general, this is meant to indicate that any version of a package that satisfies the
    /// version constraint can be used to resolve the dependency.
    ///
    /// This form of constraint also permits us to compile a dependency from source, so long as
    /// the semantic versioning constraint is satisfied.
    Version(Span<VersionReq>),
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

impl From<VersionReq> for VersionReqOrDigest {
    fn from(version: VersionReq) -> Self {
        Self::Version(Span::unknown(version))
    }
}

impl From<Word> for VersionReqOrDigest {
    fn from(digest: Word) -> Self {
        Self::Digest(Span::unknown(digest))
    }
}

impl VersionReqOrDigest {
    /// Returns true if this version requirement is a semantic versioning requirement
    pub fn is_semantic_version(&self) -> bool {
        matches!(self, Self::Version(_))
    }

    /// Returns true if this version requirement requires an exact digest match
    pub fn is_digest(&self) -> bool {
        matches!(self, Self::Digest(_))
    }

    pub(crate) fn set_source_id(&mut self, id: SourceId) {
        match self {
            Self::Version(version) => version.set_source_id(id),
            Self::Digest(digest) => digest.set_source_id(id),
        }
    }
}
