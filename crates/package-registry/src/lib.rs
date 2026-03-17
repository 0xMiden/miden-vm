#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "resolver")]
mod resolver;
mod version;
mod version_requirement;

use alloc::{collections::BTreeMap, sync::Arc};

use miden_assembly_syntax::Report;
pub use miden_assembly_syntax::{
    debuginfo::Span,
    semver,
    semver::{Version as SemVer, VersionReq},
};
pub use miden_core::{LexicographicWord, Word};
use miden_mast_package::Package as MastPackage;
pub use miden_mast_package::PackageId;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "resolver")]
pub use self::resolver::{
    DependencyResolutionError, InMemoryPackageRegistry, PackagePriority, PackageResolver,
    VersionSet,
};
pub use self::{
    version::{InvalidVersionError, SemVerError, Version},
    version_requirement::VersionRequirement,
};

/// A type alias for an ordered map of package requirements.
pub type PackageRequirements = BTreeMap<PackageId, VersionRequirement>;

/// Metadata tracked for a specific package version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PackageRecord {
    /// The version associated with this package
    version: Version,
    /// An optional description of this package
    description: Option<Arc<str>>,
    /// The required dependencies of this package
    dependencies: PackageRequirements,
}

impl PackageRecord {
    /// Construct a new record with the provided dependency metadata.
    pub fn new(
        version: Version,
        dependencies: impl IntoIterator<Item = (PackageId, VersionRequirement)>,
    ) -> Self {
        Self {
            version,
            description: None,
            dependencies: dependencies.into_iter().collect(),
        }
    }

    /// Attach a description to this record.
    pub fn with_description(mut self, description: impl Into<Arc<str>>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Get the detailed version information for this record
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The semantic version of this package
    pub fn semantic_version(&self) -> &SemVer {
        &self.version.version
    }

    /// The digest of the MAST forest contained in this package
    pub fn digest(&self) -> Option<&Word> {
        self.version.digest.as_ref().map(|word| word.inner())
    }

    /// Returns the package description, if known.
    pub fn description(&self) -> Option<&Arc<str>> {
        self.description.as_ref()
    }

    /// Returns the dependency metadata for this package.
    pub fn dependencies(&self) -> &PackageRequirements {
        &self.dependencies
    }
}

/// A type alias for all known versions of a specific package.
pub type PackageVersions = BTreeMap<Version, PackageRecord>;

/// A read-only package registry interface used for querying package metadata and versions.
pub trait PackageRegistry {
    /// Return the versions known for `package`, if any.
    fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions>;

    /// Returns true if any version of `package` exists in the registry.
    fn is_available(&self, package: &PackageId) -> bool {
        self.available_versions(package).is_some()
    }

    /// Returns true if the specific `version` of `package` exists in the registry.
    fn is_version_available(&self, package: &PackageId, version: &Version) -> bool {
        self.available_versions(package)
            .map(|versions| versions.contains_key(version))
            .unwrap_or(false)
    }

    /// Return the metadata for `package` at `version`, if present.
    fn get_by_version(&self, package: &PackageId, version: &Version) -> Option<&PackageRecord> {
        self.available_versions(package).and_then(|versions| versions.get(version))
    }

    /// Return the metadata for `package` with `digest`, if present.
    fn get_by_digest(&self, package: &PackageId, digest: &Word) -> Option<&PackageRecord> {
        let digest = LexicographicWord::new(*digest);
        self.available_versions(package).and_then(|versions| {
            versions.iter().rev().find_map(|(version, record)| {
                if version.digest.is_some_and(|d| d == digest) {
                    Some(record)
                } else {
                    None
                }
            })
        })
    }

    /// Find the latest version of `package` that satisfies `requirement`.
    fn find_latest<'a>(
        &'a self,
        package: &PackageId,
        requirement: &VersionRequirement,
    ) -> Option<&'a PackageRecord> {
        self.available_versions(package).and_then(|versions| {
            versions.iter().rev().find_map(|(version, record)| {
                if version.satisfies(requirement) {
                    Some(record)
                } else {
                    None
                }
            })
        })
    }

    /// Register a package `name` with `version`, using the provided package metadata
    fn register(&mut self, name: PackageId, version: Version, record: PackageRecord);
}

/// A read-only package artifact provider used to load assembled packages by resolved version.
pub trait PackageProvider {
    /// Load the concrete package artifact for `package` at `version`.
    fn load_package(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Arc<MastPackage>, Report>;
}
