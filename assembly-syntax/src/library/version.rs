use core::{
    fmt,
    str::{self, FromStr},
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::diagnostics::{Diagnostic, miette};

/// Represents a _Semantic Versioning_ version string, without pre-releases.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The major version, incremented when breaking changes occur.
    pub major: u16,
    /// The minor version, incremented when new features or functionality is introduced.
    pub minor: u16,
    /// The patch version, incremented when non-breaking changes are made.
    pub patch: u16,
}

/// Construction
impl Version {
    /// Returns the current minimal version supported by the code in this crate.
    #[inline(always)]
    pub const fn min() -> Self {
        Self { major: 0, minor: 1, patch: 0 }
    }
}

/// Arithmetic
impl Version {
    /// Returns a new [Version] clamped to the major version
    ///
    /// This is useful for comparing two versions at major version granularity
    pub const fn to_nearest_major(self) -> Self {
        Self { minor: 0, patch: 0, ..self }
    }

    /// Returns a new [Version] clamped to the minor version
    ///
    /// This is useful for comparing two versions at minor version granularity
    pub const fn to_nearest_minor(self) -> Self {
        Self { patch: 0, ..self }
    }

    /// Return a new [Version] representing the next major version release
    pub const fn next_major(self) -> Self {
        Self {
            major: self.major + 1,
            minor: 0,
            patch: 0,
        }
    }

    /// Return a new [Version] representing the next minor version release
    pub const fn next_minor(self) -> Self {
        Self { minor: self.minor + 1, patch: 0, ..self }
    }

    /// Return a new [Version] representing the next patch release
    pub const fn next_patch(self) -> Self {
        Self { patch: self.patch + 1, ..self }
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::min()
    }
}
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
impl Serializable for Version {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.major);
        target.write_u16(self.minor);
        target.write_u16(self.patch);
    }
}
impl Deserializable for Version {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let major = source.read_u16()?;
        let minor = source.read_u16()?;
        let patch = source.read_u16()?;
        Ok(Self { major, minor, patch })
    }
}

/// Represents errors that occur when parsing a [Version]
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum VersionError {
    #[error("invalid version string: cannot be empty")]
    #[diagnostic()]
    Empty,
    #[error("invalid version string: missing minor component, expected MAJOR.MINOR.PATCH")]
    #[diagnostic()]
    MissingMinor,
    #[error("invalid version string: missing patch component, expected MAJOR.MINOR.PATCH")]
    #[diagnostic()]
    MissingPatch,
    #[error("invalid version string: could not parse major version: {0}")]
    #[diagnostic()]
    Major(core::num::ParseIntError),
    #[error("invalid version string: could not parse minor version: {0}")]
    #[diagnostic()]
    Minor(core::num::ParseIntError),
    #[error("invalid version string: could not parse patch version: {0}")]
    #[diagnostic()]
    Patch(core::num::ParseIntError),
    #[error(
        "invalid version string: unsupported pre-release version, \
        only MAJOR.MINOR.PATCH components are allowed"
    )]
    #[diagnostic()]
    Unsupported,
}

impl FromStr for Version {
    type Err = VersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut components = value.split('.');

        let major = components
            .next()
            .ok_or(VersionError::Empty)?
            .parse::<u16>()
            .map_err(VersionError::Major)?;
        let minor = components
            .next()
            .ok_or(VersionError::MissingMinor)?
            .parse::<u16>()
            .map_err(VersionError::Minor)?;
        let patch = components
            .next()
            .ok_or(VersionError::MissingPatch)?
            .parse::<u16>()
            .map_err(VersionError::Patch)?;

        if components.next().is_some() {
            Err(VersionError::Unsupported)
        } else {
            Ok(Self { major, minor, patch })
        }
    }
}
