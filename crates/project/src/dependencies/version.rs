use core::{borrow::Borrow, fmt, str::FromStr};

use miden_core::{LexicographicWord, Word};

pub use miden_assembly_syntax::semver::{Error as SemVerError, Version as SemVer, VersionReq};

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
/// * Record multiple entries in the index for the same semantic version string, when multiple
///   assembled packages with that version are present, disambiguating using the content digest.
/// * Provide a total ordering for package versions that may or may not include a specific digest
#[derive(Debug, Clone)]
pub struct Version {
    /// The semantic version information
    ///
    /// This is the canonical human-facing version for a package.
    pub version: SemVer,
    /// The content digest for this version, if known.
    ///
    /// This is the most precise version for a package, and is used to disambiguate multiple
    /// instances of a package with the same semantic version, but differing content.
    pub digest: Option<LexicographicWord>,
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
        match s.split_once('@') {
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
            write!(f, "{}@{}", &self.version, digest.inner())
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
