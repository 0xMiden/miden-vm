use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_assembly_syntax::Report;
use miden_mast_package::Package as MastPackage;

use crate::{
    PackageCache, PackageId, PackageIndex, PackageProvider, PackageRecord, PackageRegistry,
    PackageStore, PackageVersions, SemVer, Version, VersionRequirement,
};

#[derive(Debug, thiserror::Error)]
pub enum InMemoryPackageStoreError {
    #[error("package '{package}' version '{version}' is already registered")]
    DuplicateSemanticVersion { package: PackageId, version: SemVer },
    #[error("package '{package}' depends on '{dependency}' without a semantic version")]
    MissingDependencyVersion {
        package: PackageId,
        dependency: PackageId,
    },
}

/// An in-memory package registry implementation used for tests, local tooling, and resolver state.
#[derive(Default)]
pub struct InMemoryPackageRegistry {
    packages: BTreeMap<PackageId, PackageVersions>,
    artifacts: BTreeMap<(PackageId, Version), Arc<MastPackage>>,
}

impl InMemoryPackageRegistry {
    /// Construct a registry from an existing package map.
    pub fn from_packages(packages: BTreeMap<PackageId, PackageVersions>) -> Self {
        Self { packages, artifacts: BTreeMap::default() }
    }

    /// Insert a new entry for `name` and `version`, creating a record from `dependencies`.
    pub fn insert<D, P, V>(
        &mut self,
        name: impl Into<PackageId>,
        version: Version,
        dependencies: D,
    ) -> Result<(), InMemoryPackageStoreError>
    where
        D: IntoIterator<Item = (P, V)>,
        P: Into<PackageId>,
        V: Into<VersionRequirement>,
    {
        let record_version = version;
        let record = PackageRecord::new(
            record_version,
            dependencies
                .into_iter()
                .map(|(name, requirement)| (name.into(), requirement.into())),
        );
        self.insert_record(name, record)
    }

    /// Insert the canonical metadata for `name`.
    pub fn insert_record(
        &mut self,
        name: impl Into<PackageId>,
        record: PackageRecord,
    ) -> Result<(), InMemoryPackageStoreError> {
        use alloc::collections::btree_map::Entry;

        let name = name.into();
        let semver = record.semantic_version().clone();
        match self.packages.entry(name) {
            Entry::Vacant(entry) => {
                let versions = BTreeMap::from_iter([(semver, record)]);
                entry.insert(versions);
                Ok(())
            },
            Entry::Occupied(mut entry) => {
                let versions = entry.get_mut();
                match versions.entry(semver.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(record);
                        Ok(())
                    },
                    Entry::Occupied(_) => {
                        let package = entry.key().clone();
                        Err(InMemoryPackageStoreError::DuplicateSemanticVersion {
                            package,
                            version: semver,
                        })
                    },
                }
            },
        }
    }

    /// Returns all packages recorded in this registry.
    pub fn packages(&self) -> &BTreeMap<PackageId, PackageVersions> {
        &self.packages
    }

    /// Returns all package artifacts recorded in this store.
    pub fn artifacts(&self) -> &BTreeMap<(PackageId, Version), Arc<MastPackage>> {
        &self.artifacts
    }
}

impl PackageRegistry for InMemoryPackageRegistry {
    fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
        self.packages.get(package)
    }
}

impl PackageIndex for InMemoryPackageRegistry {
    type Error = InMemoryPackageStoreError;

    fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
        self.insert_record(name, record)
    }
}

impl PackageProvider for InMemoryPackageRegistry {
    fn load_package(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Arc<MastPackage>, Report> {
        self.artifacts
            .get(&(package.clone(), version.clone()))
            .cloned()
            .ok_or_else(|| Report::msg(format!("cannot load package {package}@{version}")))
    }
}

impl PackageCache for InMemoryPackageRegistry {
    type Error = InMemoryPackageStoreError;

    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        let version = Version::new(package.version.clone(), package.digest());
        let dependencies = package.manifest.dependencies().map(|dependency| {
            let dependency_version = Version::new(dependency.version.clone(), dependency.digest);
            (dependency.name.clone(), VersionRequirement::Exact(dependency_version))
        });

        let record = match package.description.clone() {
            Some(description) => {
                PackageRecord::new(version.clone(), dependencies).with_description(description)
            },
            None => PackageRecord::new(version.clone(), dependencies),
        };

        if let Some(existing) = self.get_by_semver(&package.name, &package.version) {
            if existing.version() != &version || existing != &record {
                return Err(InMemoryPackageStoreError::DuplicateSemanticVersion {
                    package: package.name.clone(),
                    version: package.version.clone(),
                });
            }
            let artifact_key = (package.name.clone(), version.clone());
            if let Some(existing_package) = self.artifacts.get(&artifact_key) {
                if existing_package.as_ref() != package.as_ref() {
                    return Err(InMemoryPackageStoreError::DuplicateSemanticVersion {
                        package: package.name.clone(),
                        version: package.version.clone(),
                    });
                }
            } else {
                self.artifacts.insert(artifact_key, package);
            }
            return Ok(version);
        }

        self.insert_record(package.name.clone(), record)?;
        self.artifacts.insert((package.name.clone(), version.clone()), package);
        Ok(version)
    }
}

impl PackageStore for InMemoryPackageRegistry {
    fn publish_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        let version = Version::new(package.version.clone(), package.digest());
        if self.is_semver_available(&package.name, &package.version) {
            return Err(InMemoryPackageStoreError::DuplicateSemanticVersion {
                package: package.name.clone(),
                version: package.version.clone(),
            });
        }

        let dependencies = package
            .manifest
            .dependencies()
            .map(|dependency| {
                let dependency_version =
                    Version::new(dependency.version.clone(), dependency.digest);
                if !self.is_version_available(&dependency.name, &dependency_version) {
                    return Err(InMemoryPackageStoreError::MissingDependencyVersion {
                        package: package.name.clone(),
                        dependency: dependency.name.clone(),
                    });
                }
                Ok((dependency.name.clone(), VersionRequirement::Exact(dependency_version)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let record = match package.description.clone() {
            Some(description) => {
                PackageRecord::new(version.clone(), dependencies).with_description(description)
            },
            None => PackageRecord::new(version.clone(), dependencies),
        };
        self.insert_record(package.name.clone(), record)?;
        self.artifacts.insert((package.name.clone(), version.clone()), package);
        Ok(version)
    }
}

impl<'a, V, D> FromIterator<(&'a str, V)> for InMemoryPackageRegistry
where
    D: IntoIterator<Item = (&'a str, VersionRequirement)>,
    V: IntoIterator<Item = (Version, D)>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, V)>,
    {
        let mut index = Self::default();
        for (name, versions) in iter {
            let name = PackageId::from(name);
            for (version, deps) in versions {
                let deps = deps
                    .into_iter()
                    .map(|(name, requirement)| (PackageId::from(name), requirement));
                index
                    .insert(name.clone(), version, deps)
                    .expect("duplicate semantic version in registry fixture");
            }
        }
        index
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    use miden_assembly_syntax::{
        Library,
        ast::{Path as AstPath, PathBuf},
        library::{LibraryExport, ProcedureExport as LibraryProcedureExport},
    };
    use miden_core::{
        mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeId},
        operations::Operation,
    };
    use miden_mast_package::{Dependency, Package, Section, SectionId, TargetType};

    use super::*;

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_library(export: &str) -> Arc<Library> {
        let (forest, node_id) = build_forest();
        let path = absolute_path(export);
        let export = LibraryProcedureExport::new(node_id, Arc::clone(&path));

        let mut exports = BTreeMap::new();
        exports.insert(path, LibraryExport::Procedure(export));

        Arc::new(Library::new(Arc::new(forest), exports).expect("failed to build library"))
    }

    fn build_package<'a>(
        name: &str,
        version: &str,
        dependencies: impl IntoIterator<Item = (&'a str, &'a str, TargetType, miden_core::Word)>,
    ) -> Arc<MastPackage> {
        Package::from_library(
            name.into(),
            version.parse().unwrap(),
            TargetType::Library,
            build_library("test::pkg::entry"),
            dependencies.into_iter().map(|(name, version, kind, digest)| Dependency {
                name: name.into(),
                version: version.parse().unwrap(),
                kind,
                digest,
            }),
        )
        .into()
    }

    #[test]
    fn cache_rejects_different_artifact_for_existing_exact_version() {
        let mut registry = InMemoryPackageRegistry::default();
        let package = build_package("pkg", "1.0.0", []);
        let version = registry.cache_package(package.clone()).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        Arc::make_mut(&mut conflicting_package)
            .sections
            .push(Section::new(SectionId::custom("cache-test").unwrap(), Vec::from([1, 2, 3])));
        assert_eq!(
            Some(conflicting_package.digest()),
            version.digest.as_ref().map(|digest| *digest.inner())
        );

        let error = registry
            .cache_package(conflicting_package)
            .expect_err("cache should reject conflicting package artifacts");
        assert!(matches!(error, InMemoryPackageStoreError::DuplicateSemanticVersion { .. }));

        let loaded = registry.load_package(&PackageId::from("pkg"), &version).unwrap();
        assert_eq!(loaded.as_ref(), package.as_ref());
    }
}
