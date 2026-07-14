#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "resolver")]
mod resolver;
mod version;
mod version_requirement;

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::fmt;

use miden_assembly_syntax::Report;
pub use miden_assembly_syntax::{
    debuginfo::Span,
    semver,
    semver::{Version as SemVer, VersionReq},
};
pub use miden_core::Word;
use miden_mast_package::Package as MastPackage;
pub use miden_mast_package::PackageId;
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
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

/// Metadata tracked for a specific canonical package version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct PackageRecord {
    /// The exact published version associated with this package
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
        self.version.digest.as_ref()
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

#[cfg(feature = "arbitrary")]
impl Arbitrary for PackageRecord {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let description = proptest::option::of(
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..32)
                .prop_map(|chars| Arc::<str>::from(chars.into_iter().collect::<String>())),
        );
        let dependencies =
            proptest::collection::vec((any::<PackageId>(), any::<VersionRequirement>()), 0..4)
                .prop_map(|entries| entries.into_iter().collect::<BTreeMap<_, _>>());

        (any::<Version>(), description, dependencies)
            .prop_map(|(version, description, dependencies)| {
                let mut record = Self::new(version, dependencies);
                if let Some(description) = description {
                    record = record.with_description(description);
                }
                record
            })
            .boxed()
    }
}

/// A type alias for all known canonical semantic versions of a specific package.
///
/// Each semantic version maps to at most one canonical published artifact. The exact artifact
/// identity, including content digest, is stored in the corresponding [`PackageRecord`].
pub type PackageVersions = BTreeMap<SemVer, PackageRecord>;

/// A read-only package registry interface used for querying package metadata and versions.
pub trait PackageRegistry {
    /// Return the versions known for `package`, if any.
    fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions>;

    /// Returns true if any version of `package` exists in the registry.
    fn is_available(&self, package: &PackageId) -> bool {
        self.available_versions(package).is_some_and(|versions| !versions.is_empty())
    }

    /// Returns true if the specific `version` of `package` exists in the registry.
    fn is_version_available(&self, package: &PackageId, version: &Version) -> bool {
        self.get_by_version(package, version).is_some()
    }

    /// Returns true if the canonical semantic version of `package` exists in the registry.
    fn is_semver_available(&self, package: &PackageId, version: &SemVer) -> bool {
        self.get_by_semver(package, version).is_some()
    }

    /// Return the metadata for `package` at `version`, if present.
    fn get_by_version(&self, package: &PackageId, version: &Version) -> Option<&PackageRecord> {
        let record = self.available_versions(package)?.get(&version.version)?;
        match version.digest.as_ref() {
            Some(_) if record.version() == version => Some(record),
            Some(_) => None,
            None => Some(record),
        }
    }

    /// Return the canonical metadata for `package` at the given semantic version.
    fn get_by_semver(&self, package: &PackageId, version: &SemVer) -> Option<&PackageRecord> {
        self.available_versions(package)?.get(version)
    }

    /// Return the exact metadata for `package` at the given fully-qualified version.
    fn get_exact_version(&self, package: &PackageId, version: &Version) -> Option<&PackageRecord> {
        match version.digest.as_ref() {
            Some(_) => self.get_by_version(package, version),
            None => None,
        }
    }

    /// Return the metadata for `package` with `digest`, if present.
    fn get_by_digest(&self, package: &PackageId, digest: &Word) -> Option<&PackageRecord> {
        self.available_versions(package).and_then(|versions| {
            versions
                .values()
                .rev()
                .find(|record| record.version().digest.as_ref() == Some(digest))
        })
    }

    /// Find the latest version of `package` that satisfies `requirement`.
    fn find_latest<'a>(
        &'a self,
        package: &PackageId,
        requirement: &VersionRequirement,
    ) -> Option<&'a PackageRecord> {
        if let VersionRequirement::Exact(version) = requirement {
            return self.get_exact_version(package, version);
        }

        self.available_versions(package).and_then(|versions| {
            versions.values().rev().find(|record| record.version().satisfies(requirement))
        })
    }
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

/// A marker trait for types implementing both [PackageRegistry] and [PackageProvider], which make
/// them capable of both resolving packages and loading their associated artifacts.
///
/// This trait does not need to be directly implemented - it has a blanket impl for all types that
/// implement both [PackageRegistry] and [PackageProvider]
pub trait PackageRegistryAndProvider: PackageRegistry + PackageProvider {}

impl<T: ?Sized + PackageProvider + PackageRegistry> PackageRegistryAndProvider for T {}

/// A writable metadata index for package records.
pub trait PackageIndex: PackageRegistry {
    type Error: fmt::Display;

    /// Register the canonical metadata for `name`.
    ///
    /// Implementations must reject attempts to register a second canonical artifact for the same
    /// package semantic version.
    fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error>;
}

/// A writable package cache used to store assembled package artifacts resolved during assembly.
pub trait PackageCache: PackageRegistryAndProvider {
    type Error: fmt::Display;

    /// Cache `package`, returning the fully-qualified stored version.
    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error>;
}

/// A writable package store used to publish assembled package artifacts and index metadata.
pub trait PackageStore: PackageCache {
    /// Publish `package` to the store, returning the fully-qualified stored version.
    fn publish_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error>;
}

/// The error type returned by [NoPackageStore]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NoPackageStoreError(String);

/// A package store implementation which refuses publication and loading.
///
/// Cache writes are accepted as a no-op so callers which do not need a persistent package store can
/// still assemble source dependencies.
#[derive(Default)]
pub struct NoPackageStore;

impl PackageRegistry for NoPackageStore {
    fn available_versions(&self, _package: &PackageId) -> Option<&PackageVersions> {
        None
    }
}

impl PackageProvider for NoPackageStore {
    fn load_package(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Arc<MastPackage>, Report> {
        Err(Report::msg(format!("cannot load package {package}@{version}")))
    }
}

impl PackageCache for NoPackageStore {
    type Error = NoPackageStoreError;

    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        Ok(Version::new(package.version.clone(), package.digest()))
    }
}

impl PackageStore for NoPackageStore {
    fn publish_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        Err(NoPackageStoreError(format!(
            "cannot publish package {}@{}",
            package.name, package.version
        )))
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_assembly_syntax::ast::{Path as AstPath, PathBuf};
    use miden_core::{
        mast::{
            BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest, MastNodeExt, MastNodeId,
        },
        operations::Operation,
    };
    use miden_mast_package::{Package, PackageExport, ProcedureExport, TargetType};

    use super::*;

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut builder = DenseMastForestBuilder::new();
        let node_id = builder
            .push_node(BasicBlockNodeBuilder::new(vec![Operation::Add]))
            .expect("failed to build basic block");
        builder.mark_root(node_id);
        let (forest, remapping) = builder.finish_with_id_map().expect("failed to build forest");
        let node_id = remapping.get(node_id).expect("root node should be retained");
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().unwrap().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_package_exports(export: &str) -> (Arc<MastForest>, Vec<PackageExport>) {
        let (forest, node_id) = build_forest();
        let path = absolute_path(export);
        let export =
            ProcedureExport::new(Arc::clone(&path), Some(node_id), forest[node_id].digest(), None);

        (Arc::new(forest), vec![PackageExport::Procedure(export)])
    }

    #[test]
    fn no_package_store_cache_package_is_noop() {
        let (mast, exports) = build_package_exports("test::pkg::entry");
        let package = Arc::new(
            Package::create(
                PackageId::from("pkg"),
                "1.0.0".parse().unwrap(),
                TargetType::Library,
                mast,
                exports,
                [],
            )
            .expect("test package should be valid"),
        );
        let expected = Version::new(package.version.clone(), package.digest());

        let mut store = NoPackageStore;
        let cached = store
            .cache_package(Arc::clone(&package))
            .expect("no package store should accept cache writes as no-op");

        assert_eq!(cached, expected);
        assert!(store.available_versions(&package.name).is_none());
        store
            .load_package(&package.name, &cached)
            .expect_err("no package store should not persist cache writes");
        store
            .publish_package(package)
            .expect_err("no package store should still reject publication");
    }

    #[test]
    fn package_registry_is_available_requires_at_least_one_version() {
        struct EmptyVersionRegistry {
            versions: PackageVersions,
        }

        impl PackageRegistry for EmptyVersionRegistry {
            fn available_versions(&self, _package: &PackageId) -> Option<&PackageVersions> {
                Some(&self.versions)
            }
        }

        let registry = EmptyVersionRegistry { versions: BTreeMap::new() };

        assert!(!registry.is_available(&PackageId::from("pkg")));
    }
}
