use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly_syntax::Report;
use miden_core::{
    serde::{Deserializable, Serializable},
    utils::DisplayHex,
};
use miden_mast_package::Package as MastPackage;
use miden_package_registry::{
    InMemoryPackageRegistry, PackageId, PackageIndex, PackageProvider, PackageRecord,
    PackageRegistry, PackageStore, PackageVersions, Version, VersionRequirement,
};
use serde::{Deserialize, Serialize};

/// The error raised when operations on a [LocalPackageRegistry] fail
#[derive(Debug, thiserror::Error)]
pub enum LocalRegistryError {
    #[error("missing required environment variable '{var}'")]
    MissingEnv { var: &'static str },
    #[error("failed to read registry index: {0}")]
    IndexRead(#[source] std::io::Error),
    #[error("failed to seek in registry index stream: {0}")]
    IndexSeek(#[source] std::io::Error),
    #[error("failed to lock registry index for reading: {0}")]
    IndexReadLock(#[source] fs::TryLockError),
    #[error("failed to write registry index: {0}")]
    IndexWrite(#[source] std::io::Error),
    #[error("failed to lock registry index for writing: {0}")]
    IndexWriteLock(#[source] fs::TryLockError),
    #[error(
        "failed to write registry index: the index was modified by another process, please try again"
    )]
    WriteToStaleIndex,
    #[error("failed to parse registry index: {0}")]
    IndexParse(#[from] toml::de::Error),
    #[error("failed to serialize registry index: {0}")]
    IndexSerialize(#[from] toml::ser::Error),
    #[error("failed to decode package artifact '{path}': {error}")]
    PackageDecode { path: PathBuf, error: String },
    #[error("package artifact '{path}' is missing semantic version metadata")]
    MissingPackageVersion { path: PathBuf },
    #[error("package '{package}' version '{version}' is already registered")]
    DuplicateSemanticVersion {
        package: PackageId,
        version: miden_package_registry::SemVer,
    },
    #[error("package '{package}' with version '{version}' is not present in the registry")]
    MissingPackage { package: PackageId, version: Version },
    #[error("package '{package}' version '{version}' has no artifact digest")]
    MissingArtifactDigest { package: PackageId, version: Version },
    #[error("package artifact for '{package}' version '{version}' was not found at '{path}'")]
    MissingArtifact {
        package: PackageId,
        version: Version,
        path: PathBuf,
    },
    #[error(
        "package '{package}' depends on unpublished package '{dependency}' with version '{version}'"
    )]
    MissingDependency {
        package: PackageId,
        dependency: PackageId,
        version: Version,
    },
}

/// A [PackageRegistry] implementation that uses the local filesystem for storage of:
///
/// * The package index, as a TOML manifest, written to `$MIDEN_SYSROOT/etc/registry/index.toml`
/// * The package artifacts (i.e. `.masp` files) of registered packages, stored under
///   `$MIDEN_SYSROOT/lib`.
///
/// The index is associated with a specific toolchain for now, as it makes integration into
/// `midenup` easier, and we're still at a stage where having a clean slate when switching
/// to a new toolchain prevents confusing errors.
///
/// TODO(pauls): In the future, we should move the registry to a toolchain-agnostic location, and
/// make registry operations global.
pub struct LocalPackageRegistry {
    index_path: PathBuf,
    artifact_dir: PathBuf,
    index: InMemoryPackageRegistry,
    index_checksum: [u8; 32],
}

/// The metadata about a package produced when listing or describing a package in the index
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageSummary {
    /// The package identifier/name
    pub name: PackageId,
    /// The package semantic version and digest
    pub version: Version,
    /// The package description
    pub description: Option<Arc<str>>,
    /// The version requirements for dependencies of this package
    pub dependencies: BTreeMap<PackageId, VersionRequirement>,
    /// The location of the assembled artifact on disk.
    ///
    /// If `None`, the package has been registered virtually, and so has no location on disk.
    pub artifact_path: Option<PathBuf>,
}

/// A succinct summary of a package, produced when it is published to the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPackage {
    pub name: PackageId,
    pub version: Version,
    pub artifact_path: PathBuf,
}

/// The representation of the on-disk package index
#[derive(Default, Serialize, Deserialize)]
struct PersistedIndex {
    #[serde(default)]
    packages: BTreeMap<PackageId, PackageVersions>,
}

impl Default for LocalPackageRegistry {
    fn default() -> Self {
        Self::load_from_env().expect("could not create a default instance of the package registry")
    }
}

impl LocalPackageRegistry {
    /// Create a new [LocalPackageRegistry], by deriving the index and artifact storage locations
    /// from the `$MIDEN_SYSROOT` environment variable.
    ///
    /// This produces an error if the environment variable is unset, or the index fails to load.
    pub fn load_from_env() -> Result<Self, LocalRegistryError> {
        let sysroot = PathBuf::from(
            env::var_os("MIDEN_SYSROOT")
                .ok_or(LocalRegistryError::MissingEnv { var: "MIDEN_SYSROOT" })?,
        );

        let index_path = sysroot.join("etc").join("registry").join("index.toml");
        let artifact_dir = sysroot.join("lib");
        Self::load(index_path, artifact_dir)
    }

    /// Create a new [LocalPackageRegistry], specifying the locations of the registry index, and
    /// artifact storage.
    ///
    /// Requirements:
    ///
    /// * The `index_path` must be a file path to the index manifest, which is a TOML file.
    /// * The `artifact_dir` must be a directory path.
    ///
    /// This produces an error if the paths are invalid, or the index fails to load.
    pub fn load(index_path: PathBuf, artifact_dir: PathBuf) -> Result<Self, LocalRegistryError> {
        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent).map_err(LocalRegistryError::IndexWrite)?;
        }
        fs::create_dir_all(&artifact_dir).map_err(LocalRegistryError::IndexWrite)?;

        let index_checksum: [u8; 32];
        let index = if index_path.exists() {
            let mut contents = String::with_capacity(4 * 1024);
            #[allow(clippy::verbose_file_reads)]
            {
                let mut file =
                    fs::File::open(&index_path).map_err(LocalRegistryError::IndexRead)?;
                // Acquire a non-exclusive lock on the file for reading, but return an error if
                // there is an outstanding exclusive lock on the file already.
                //
                // This will fail if a handle to the index file has an exclusive lock on it for
                // writing, see `save` for details.
                //
                // Multiple readers can hold this type of lock simultaneously, but a shared lock
                // cannot be acquired in the presence of an exclusive lock, and vice versa.
                file.try_lock_shared().map_err(LocalRegistryError::IndexReadLock)?;
                file.read_to_string(&mut contents).map_err(LocalRegistryError::IndexRead)?;
            }
            std::println!("=== index file contents ==\n{contents}\n=== end of file contents ==");
            let contents = contents.trim();
            index_checksum =
                *miden_core::crypto::hash::Sha256::hash(contents.as_bytes()).as_bytes();
            if contents.is_empty() {
                InMemoryPackageRegistry::default()
            } else {
                let persisted = toml::from_str::<PersistedIndex>(contents)?;
                InMemoryPackageRegistry::from_packages(persisted.packages)
            }
        } else {
            index_checksum = *miden_core::crypto::hash::Sha256::hash(&[]).as_bytes();
            InMemoryPackageRegistry::default()
        };

        Ok(Self {
            index_path,
            artifact_dir,
            index,
            index_checksum,
        })
    }

    /// Publish the Miden package found at `package_path`.
    ///
    /// The provided path must be a path to a `.masp` file (or at least a file containing a valid
    /// Miden package).
    ///
    /// Returns an error if the package cannot be found, is invalid, or cannot be written to the
    /// artifact store of the registry.
    pub fn publish(
        &mut self,
        package_path: impl AsRef<Path>,
    ) -> Result<PublishedPackage, LocalRegistryError> {
        let package_path = package_path.as_ref();
        let bytes = fs::read(package_path).map_err(LocalRegistryError::IndexRead)?;
        let package = MastPackage::read_from_bytes(&bytes).map_err(|error| {
            LocalRegistryError::PackageDecode {
                path: package_path.to_path_buf(),
                error: error.to_string(),
            }
        })?;

        self.publish_package_with_bytes(Arc::new(package), bytes)
    }

    /// List all of the packages indexed by this registry
    pub fn list(&self) -> Vec<PackageSummary> {
        self.index
            .packages()
            .iter()
            .flat_map(|(name, versions)| {
                versions.values().map(|record| {
                    self.package_summary(name.clone(), record.version().clone(), record)
                })
            })
            .collect()
    }

    /// Get the package summary for the given package and version.
    ///
    /// If no version is specified, the latest version will be returned.
    ///
    /// If the package is not indexed, or the specified version cannot be found, this returns `None`
    pub fn show(&self, package: &PackageId, version: Option<&Version>) -> Option<PackageSummary> {
        let (version, record) = match version {
            Some(version) => self
                .index
                .get_by_version(package, version)
                .map(|record| (record.version().clone(), record))?,
            None => self
                .index
                .available_versions(package)?
                .values()
                .next_back()
                .map(|record| (record.version().clone(), record))?,
        };

        Some(self.package_summary(package.clone(), version, record))
    }

    /// Get the path in the artifact store for `version`
    pub fn artifact_path(&self, version: &Version) -> Option<PathBuf> {
        version.digest.as_ref().map(|digest| self.artifact_path_for_digest(*digest))
    }

    /// Loads the given version of `package` from the artifact store.
    ///
    /// Returns an error if the artifact cannot be loaded, or is unknown to the registry.
    pub fn load_package(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Arc<MastPackage>, LocalRegistryError> {
        self.index.get_by_version(package, version).ok_or_else(|| {
            LocalRegistryError::MissingPackage {
                package: package.clone(),
                version: version.clone(),
            }
        })?;

        let path = self.artifact_path(version).ok_or_else(|| {
            LocalRegistryError::MissingArtifactDigest {
                package: package.clone(),
                version: version.clone(),
            }
        })?;
        if !path.exists() {
            return Err(LocalRegistryError::MissingArtifact {
                package: package.clone(),
                version: version.clone(),
                path,
            });
        }

        let bytes = fs::read(&path).map_err(LocalRegistryError::IndexRead)?;
        let package = MastPackage::read_from_bytes(&bytes).map_err(|error| {
            LocalRegistryError::PackageDecode {
                path: path.clone(),
                error: error.to_string(),
            }
        })?;
        Ok(Arc::new(package))
    }

    /// Persist the state of the index to disk
    fn save(&mut self) -> Result<(), LocalRegistryError> {
        let persisted = PersistedIndex { packages: self.index.packages().clone() };
        let contents = toml::to_string_pretty(&persisted)?;
        let mut file = fs::File::options()
            .read(true)
            .write(true)
            .truncate(false)
            .create(true)
            .open(&self.index_path)
            .map_err(LocalRegistryError::IndexWrite)?;
        // Acquire an exclusive lock for writing the index file, and return an error if we cannot
        // obtain one due to any other outstanding lock on the file.
        //
        // This will fail if another write is being performed on the same file, or if the index is
        // currently being loaded by another process.
        //
        // See `load` for the non-exclusive lock obtained for reads
        file.try_lock().map_err(LocalRegistryError::IndexWriteLock)?;

        // Validate that the contents of the persisted index have not changed under us, by
        // recomputing the checksum of its contents and comparing to when we last loaded the index.
        #[allow(clippy::verbose_file_reads)]
        {
            let mut prev_contents = Vec::with_capacity(1024);
            file.read_to_end(&mut prev_contents).map_err(LocalRegistryError::IndexRead)?;
            let checksum = miden_core::crypto::hash::Sha256::hash(prev_contents.trim_ascii());
            if &self.index_checksum != checksum.as_bytes() {
                return Err(LocalRegistryError::WriteToStaleIndex);
            }
        }

        // Compute the new checksum of the updated index contents before we write, but do not
        // update the in-memory state until we've successfully persisted the index
        let new_checksum = miden_core::crypto::hash::Sha256::hash(contents.as_bytes().trim_ascii());

        // Truncate the file to ensure that if the new index is smaller than the old one, that
        // we don't end up with a corrupted index.
        file.rewind().map_err(LocalRegistryError::IndexSeek)?;
        file.set_len(0).map_err(LocalRegistryError::IndexWrite)?;
        file.write_all(contents.as_bytes()).map_err(LocalRegistryError::IndexWrite)?;

        // Update the index checksum for the next write
        self.index_checksum = *new_checksum.as_bytes();

        Ok(())
    }

    /// Derive the path in the artifact store for a package with `digest`
    ///
    /// The file name of the resulting path is the hexadecimal encoding of the digest, with the
    /// `.masp` extension.
    fn artifact_path_for_digest(&self, digest: miden_core::Word) -> PathBuf {
        let filename = format!("0x{}.masp", DisplayHex::new(&digest.as_bytes()));
        self.artifact_dir.join(filename)
    }

    /// Construct the [PackageSummary] for the given package version
    fn package_summary(
        &self,
        name: PackageId,
        version: Version,
        record: &PackageRecord,
    ) -> PackageSummary {
        PackageSummary {
            artifact_path: self.artifact_path(&version),
            dependencies: record
                .dependencies()
                .iter()
                .map(|(dependency, requirement)| (dependency.clone(), requirement.clone()))
                .collect(),
            description: record.description().cloned(),
            name,
            version,
        }
    }

    /// Publish `package`, with `bytes` representing the serialized form of `package` which
    /// determines its provenance, i.e. if we deserialized `package` from `bytes`, then `bytes`
    /// is those exact bytes, not the bytes we would get by serializing `package`, which might
    /// differ from the original bytes.
    fn publish_package_with_bytes(
        &mut self,
        package: Arc<MastPackage>,
        bytes: Vec<u8>,
    ) -> Result<PublishedPackage, LocalRegistryError> {
        let digest = package.digest();
        let version = Version::new(package.version.clone(), digest);
        let mut dependencies = Vec::new();
        for dependency in package.manifest.dependencies() {
            let dependency_name = dependency.id().clone();
            let dependency_version = Version::new(dependency.version.clone(), dependency.digest);
            let requirement = VersionRequirement::Exact(dependency_version.clone());
            if self.index.get_exact_version(&dependency_name, &dependency_version).is_none() {
                return Err(LocalRegistryError::MissingDependency {
                    package: package.name.clone(),
                    dependency: dependency_name,
                    version: dependency_version,
                });
            }

            dependencies.push((dependency_name, requirement));
        }

        let record = match package.description.clone() {
            Some(description) => {
                PackageRecord::new(version.clone(), dependencies).with_description(description)
            },
            None => PackageRecord::new(version.clone(), dependencies),
        };

        // Write the package artifact to the registry
        let artifact_path = self.artifact_path_for_digest(digest);
        fs::write(&artifact_path, bytes).map_err(LocalRegistryError::IndexWrite)?;

        // Record the new package to the in-memory registry index
        self.register(package.name.clone(), record)?;

        // Persist the updated registry index
        self.save()?;

        Ok(PublishedPackage {
            name: package.name.clone(),
            version,
            artifact_path,
        })
    }
}

impl PackageRegistry for LocalPackageRegistry {
    fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
        self.index.available_versions(package)
    }
}

impl PackageIndex for LocalPackageRegistry {
    type Error = LocalRegistryError;

    fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
        let semver = record.semantic_version().clone();
        self.index.insert_record(name.clone(), record).map_err(|_error| {
            LocalRegistryError::DuplicateSemanticVersion { package: name, version: semver }
        })
    }
}

impl PackageProvider for LocalPackageRegistry {
    fn load_package(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Arc<MastPackage>, Report> {
        Self::load_package(self, package, version).map_err(|error| Report::msg(error.to_string()))
    }
}

impl PackageStore for LocalPackageRegistry {
    type Error = LocalRegistryError;

    fn publish_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        let bytes = package.to_bytes();
        self.publish_package_with_bytes(package, bytes)
            .map(|published| published.version)
    }
}

#[cfg(test)]
mod tests {
    use miden_mast_package::{Dependency, Package, TargetType};
    use tempfile::TempDir;

    use super::*;

    fn build_package<'a>(
        name: &str,
        version: &str,
        dependencies: impl IntoIterator<Item = (&'a str, &'a str, TargetType, miden_core::Word)>,
    ) -> Box<Package> {
        Package::generate(
            name.into(),
            version.parse().unwrap(),
            TargetType::Library,
            dependencies.into_iter().map(|(name, version, kind, digest)| Dependency {
                name: name.into(),
                version: version.parse().unwrap(),
                kind,
                digest,
            }),
        )
    }

    fn load_registry(tempdir: &TempDir) -> LocalPackageRegistry {
        let index_path = tempdir.path().join("midenup").join("registry").join("index.toml");
        let artifact_dir = tempdir.path().join("sysroot").join("lib");
        LocalPackageRegistry::load(index_path, artifact_dir).expect("failed to load registry")
    }

    #[test]
    fn publish_persists_artifact_and_index() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let dep_path = tempdir.path().join("dep.masp");
        let dep = build_package("dep", "1.0.0", []);
        dep.write_to_file(&dep_path).unwrap();
        registry.publish(&dep_path).expect("failed to publish dependency");

        let package_path = tempdir.path().join("pkg.masp");
        let package =
            build_package("pkg", "2.0.0", [("dep", "1.0.0", TargetType::Library, dep.digest())]);
        package.write_to_file(&package_path).unwrap();

        let published = registry.publish(&package_path).expect("failed to publish package");
        let artifact = &published.artifact_path;
        assert!(artifact.exists());

        let reloaded = load_registry(&tempdir);
        let listed = reloaded.list();
        assert_eq!(listed.len(), 2);

        let shown = reloaded.show(&PackageId::from("pkg"), None).expect("missing package");
        assert_eq!(shown.version.version, "2.0.0".parse().unwrap());
        assert_eq!(shown.dependencies.len(), 1);
        assert_eq!(shown.dependencies.keys().next().unwrap(), &PackageId::from("dep"));
        assert_eq!(
            shown.dependencies.values().next().unwrap().to_string(),
            format!("1.0.0#{}", dep.digest())
        );
    }

    #[test]
    fn publish_rejects_missing_dependencies() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        let package = build_package(
            "pkg",
            "1.0.0",
            [(
                "dep",
                "1.0.0",
                TargetType::Library,
                miden_core::utils::hash_string_to_word("dep"),
            )],
        );
        package.write_to_file(&package_path).unwrap();

        let error = registry.publish(&package_path).expect_err("publish should fail");
        assert!(matches!(error, LocalRegistryError::MissingDependency { .. }));
    }

    #[test]
    fn list_and_show_include_multiple_versions() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let first_path = tempdir.path().join("pkg-1.masp");
        let second_path = tempdir.path().join("pkg-2.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&first_path).unwrap();
        build_package("pkg", "2.0.0", []).write_to_file(&second_path).unwrap();

        registry.publish(&first_path).unwrap();
        registry.publish(&second_path).unwrap();

        let listed = registry.list();
        assert_eq!(listed.len(), 2);

        let latest = registry.show(&PackageId::from("pkg"), None).unwrap();
        assert_eq!(latest.version.version, "2.0.0".parse().unwrap());

        let exact =
            registry.show(&PackageId::from("pkg"), Some(&"1.0.0".parse().unwrap())).unwrap();
        assert_eq!(exact.version.version, "1.0.0".parse().unwrap());
    }

    #[test]
    fn publish_rejects_duplicate_semantic_versions() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let first_path = tempdir.path().join("pkg-1.masp");
        let second_path = tempdir.path().join("pkg-2.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&first_path).unwrap();
        build_package("pkg", "1.0.0", []).write_to_file(&second_path).unwrap();

        registry.publish(&first_path).unwrap();
        let error = registry.publish(&second_path).expect_err("duplicate semver should fail");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
    }

    #[test]
    fn publish_rejects_duplicate_semantic_versions_for_identical_bytes() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();

        registry.publish(&package_path).unwrap();
        let error = registry
            .publish(&package_path)
            .expect_err("duplicate semver should fail even for identical bytes");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
    }

    #[test]
    #[should_panic = "stale registry write failed"]
    fn publish_rejects_writes_to_a_stale_index() {
        let tempdir = TempDir::new().unwrap();
        let mut first_registry = load_registry(&tempdir);
        let mut stale_registry = load_registry(&tempdir);

        let first_path = tempdir.path().join("a.masp");
        let second_path = tempdir.path().join("longer-package-name.masp");
        build_package("a", "1.0.0", []).write_to_file(&first_path).unwrap();
        build_package("longer-package-name", "1.0.0", [])
            .write_to_file(&second_path)
            .unwrap();

        // This write succeeds because the index is not yet stale, but this write will make it
        // stale
        first_registry.publish(&first_path).unwrap();
        // This write will fail because it's view of the index is now stale
        stale_registry.publish(&second_path).expect("stale registry write failed");

        let reloaded = load_registry(&tempdir);
        assert!(reloaded.show(&PackageId::from("a"), None).is_some());
        assert!(reloaded.show(&PackageId::from("longer-package-name"), None).is_some());
    }
}
