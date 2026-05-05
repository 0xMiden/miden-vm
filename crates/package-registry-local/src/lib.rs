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
    InMemoryPackageRegistry, PackageCache, PackageId, PackageIndex, PackageProvider, PackageRecord,
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
        "package artifact at '{path}' does not match requested package '{expected_package}' version '{expected_version}' (found '{actual_package}' version '{actual_version}')"
    )]
    ArtifactMismatch {
        path: PathBuf,
        expected_package: PackageId,
        expected_version: Box<Version>,
        actual_package: PackageId,
        actual_version: Box<Version>,
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

    /// Get the path in the artifact store for `package` at `version`
    pub fn artifact_path(&self, package: &PackageId, version: &Version) -> Option<PathBuf> {
        self.artifact_path_for_summary(package, version)
    }

    fn artifact_path_for_summary(&self, package: &PackageId, version: &Version) -> Option<PathBuf> {
        let digest = *version.digest.as_ref()?;
        let artifact_path = self.artifact_path_for_package(package, &version.version, digest);
        if artifact_path.exists() {
            return Some(artifact_path);
        }

        let legacy_path = self.legacy_artifact_path_for_digest(digest);
        if self.legacy_artifact_matches(package, version, &legacy_path) {
            Some(legacy_path)
        } else {
            Some(artifact_path)
        }
    }

    fn legacy_artifact_matches(&self, package: &PackageId, version: &Version, path: &Path) -> bool {
        let Ok(bytes) = fs::read(path) else {
            return false;
        };
        let Ok(loaded) = MastPackage::read_from_bytes(&bytes) else {
            return false;
        };
        let actual_version = Version::new(loaded.version.clone(), loaded.digest());
        loaded.name == *package && actual_version == *version
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

        let digest = version.digest.ok_or_else(|| LocalRegistryError::MissingArtifactDigest {
            package: package.clone(),
            version: version.clone(),
        })?;
        let path = self.artifact_path_for_package(package, &version.version, digest);
        let path = if path.exists() {
            path
        } else {
            let legacy_path = self.legacy_artifact_path_for_digest(digest);
            if legacy_path.exists() {
                legacy_path
            } else {
                return Err(LocalRegistryError::MissingArtifact {
                    package: package.clone(),
                    version: version.clone(),
                    path,
                });
            }
        };

        let bytes = fs::read(&path).map_err(LocalRegistryError::IndexRead)?;
        let loaded = MastPackage::read_from_bytes(&bytes).map_err(|error| {
            LocalRegistryError::PackageDecode {
                path: path.clone(),
                error: error.to_string(),
            }
        })?;

        let actual_version = Version::new(loaded.version.clone(), loaded.digest());
        if loaded.name != *package || actual_version != *version {
            return Err(LocalRegistryError::ArtifactMismatch {
                path,
                expected_package: package.clone(),
                expected_version: Box::new(version.clone()),
                actual_package: loaded.name,
                actual_version: Box::new(actual_version),
            });
        }

        Ok(Arc::new(loaded))
    }

    fn save_with_locked_operation(
        &mut self,
        operation: impl FnOnce() -> Result<(), LocalRegistryError>,
    ) -> Result<(), LocalRegistryError> {
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

        operation()?;

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

    fn register_and_save_with_locked_operation(
        &mut self,
        name: PackageId,
        record: PackageRecord,
        operation: impl FnOnce() -> Result<(), LocalRegistryError>,
    ) -> Result<(), LocalRegistryError> {
        let previous_packages = self.index.packages().clone();
        self.register(name, record)?;
        match self.save_with_locked_operation(operation) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.index = InMemoryPackageRegistry::from_packages(previous_packages);
                Err(error)
            },
        }
    }

    fn write_cache_artifact_from_legacy_or_bytes(
        artifact_path: &Path,
        legacy_path: &Path,
        package: &MastPackage,
        version: &Version,
        bytes: &[u8],
    ) -> Result<(), LocalRegistryError> {
        match fs::read(legacy_path) {
            Ok(existing_bytes) => match MastPackage::read_from_bytes(&existing_bytes) {
                Ok(existing_package) => {
                    let existing_version =
                        Version::new(existing_package.version.clone(), existing_package.digest());
                    if existing_package.name == package.name && existing_version == *version {
                        if &existing_package == package {
                            fs::write(artifact_path, existing_bytes)
                                .map_err(LocalRegistryError::IndexWrite)
                        } else {
                            Err(LocalRegistryError::DuplicateSemanticVersion {
                                package: package.name.clone(),
                                version: package.version.clone(),
                            })
                        }
                    } else {
                        fs::write(artifact_path, bytes).map_err(LocalRegistryError::IndexWrite)
                    }
                },
                Err(_) => fs::write(artifact_path, bytes).map_err(LocalRegistryError::IndexWrite),
            },
            Err(_) => fs::write(artifact_path, bytes).map_err(LocalRegistryError::IndexWrite),
        }
    }

    fn repair_cache_artifact(
        artifact_path: &Path,
        legacy_path: &Path,
        package: &MastPackage,
        version: &Version,
        bytes: &[u8],
    ) -> Result<(), LocalRegistryError> {
        match fs::read(artifact_path) {
            Ok(existing_bytes) => match MastPackage::read_from_bytes(&existing_bytes) {
                Ok(existing_package) if &existing_package == package => Ok(()),
                Ok(_) => Err(LocalRegistryError::DuplicateSemanticVersion {
                    package: package.name.clone(),
                    version: package.version.clone(),
                }),
                Err(_) => Self::write_cache_artifact_from_legacy_or_bytes(
                    artifact_path,
                    legacy_path,
                    package,
                    version,
                    bytes,
                ),
            },
            Err(_) => Self::write_cache_artifact_from_legacy_or_bytes(
                artifact_path,
                legacy_path,
                package,
                version,
                bytes,
            ),
        }
    }

    /// Derive the path in the artifact store for a package with `digest`
    ///
    /// The file name includes the package name and semantic version to avoid collisions between
    /// package identities that share the same underlying MAST digest.
    fn artifact_path_for_package(
        &self,
        package: &PackageId,
        version: &miden_package_registry::SemVer,
        digest: miden_core::Word,
    ) -> PathBuf {
        let package_id = DisplayHex(package.as_bytes());
        let semantic_version = version.to_string();
        let semantic_version = DisplayHex(semantic_version.as_bytes());
        let digest_bytes = digest.as_bytes();
        let digest = DisplayHex::new(&digest_bytes);
        let filename = format!("{package_id}-{semantic_version}-0x{digest}.masp");
        self.artifact_dir.join(filename)
    }

    /// Derive the artifact path used before filenames included package identity.
    fn legacy_artifact_path_for_digest(&self, digest: miden_core::Word) -> PathBuf {
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
            artifact_path: self.artifact_path_for_summary(&name, &version),
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

    fn record_for_package(
        package: &MastPackage,
        version: Version,
    ) -> (PackageRecord, Vec<(PackageId, Version, VersionRequirement)>) {
        let dependencies = package
            .manifest
            .dependencies()
            .map(|dependency| {
                let dependency_name = dependency.id().clone();
                let dependency_version =
                    Version::new(dependency.version.clone(), dependency.digest);
                (
                    dependency_name,
                    dependency_version.clone(),
                    VersionRequirement::Exact(dependency_version),
                )
            })
            .collect::<Vec<_>>();

        let record = match package.description.clone() {
            Some(description) => PackageRecord::new(
                version,
                dependencies
                    .iter()
                    .map(|(name, _version, requirement)| (name.clone(), requirement.clone())),
            )
            .with_description(description),
            None => PackageRecord::new(
                version,
                dependencies
                    .iter()
                    .map(|(name, _version, requirement)| (name.clone(), requirement.clone())),
            ),
        };

        (record, dependencies)
    }

    fn cache_package_with_bytes(
        &mut self,
        package: Arc<MastPackage>,
        bytes: Vec<u8>,
    ) -> Result<PublishedPackage, LocalRegistryError> {
        let digest = package.digest();
        let version = Version::new(package.version.clone(), digest);
        let (record, _dependencies) = Self::record_for_package(&package, version.clone());
        let artifact_path = self.artifact_path_for_package(&package.name, &package.version, digest);

        if let Some(existing) = self.index.get_by_semver(&package.name, &package.version) {
            if existing.version() != &version || existing != &record {
                return Err(LocalRegistryError::DuplicateSemanticVersion {
                    package: package.name.clone(),
                    version: package.version.clone(),
                });
            }

            let legacy_path = self.legacy_artifact_path_for_digest(digest);
            self.save_with_locked_operation(|| {
                Self::repair_cache_artifact(
                    &artifact_path,
                    &legacy_path,
                    package.as_ref(),
                    &version,
                    &bytes,
                )
            })?;
            return Ok(PublishedPackage {
                name: package.name.clone(),
                version,
                artifact_path,
            });
        }

        self.register_and_save_with_locked_operation(package.name.clone(), record, || {
            fs::write(&artifact_path, bytes).map_err(LocalRegistryError::IndexWrite)
        })?;

        Ok(PublishedPackage {
            name: package.name.clone(),
            version,
            artifact_path,
        })
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
        let (record, dependencies) = Self::record_for_package(&package, version.clone());

        for (dependency_name, dependency_version, _requirement) in dependencies.iter() {
            if self.index.get_exact_version(dependency_name, dependency_version).is_none() {
                return Err(LocalRegistryError::MissingDependency {
                    package: package.name.clone(),
                    dependency: dependency_name.clone(),
                    version: dependency_version.clone(),
                });
            }
        }

        // Write the package artifact to the registry
        let artifact_path = self.artifact_path_for_package(&package.name, &package.version, digest);
        if self.index.get_by_semver(&package.name, &package.version).is_some() {
            return Err(LocalRegistryError::DuplicateSemanticVersion {
                package: package.name.clone(),
                version: package.version.clone(),
            });
        }

        // Persist the updated registry index and artifact under the index write lock.
        self.register_and_save_with_locked_operation(package.name.clone(), record, || {
            fs::write(&artifact_path, bytes).map_err(LocalRegistryError::IndexWrite)
        })?;

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

impl PackageCache for LocalPackageRegistry {
    type Error = LocalRegistryError;

    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        let bytes = package.to_bytes();
        self.cache_package_with_bytes(package, bytes).map(|published| published.version)
    }
}

impl PackageStore for LocalPackageRegistry {
    fn publish_package(&mut self, package: Arc<MastPackage>) -> Result<Version, Self::Error> {
        let bytes = package.to_bytes();
        self.publish_package_with_bytes(package, bytes)
            .map(|published| published.version)
    }
}

#[cfg(test)]
mod tests {
    use miden_mast_package::{Dependency, Package, Section, SectionId, TargetType};
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
    fn cache_persists_packages_with_missing_dependencies() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let dependency_digest = miden_core::utils::hash_string_to_word("dep");
        let package = build_package(
            "pkg",
            "1.0.0",
            [("dep", "1.0.0", TargetType::Library, dependency_digest)],
        );
        let version = registry
            .cache_package(Arc::from(package))
            .expect("cache should accept unresolved dependencies");

        let reloaded = load_registry(&tempdir);
        let shown = reloaded
            .show(&PackageId::from("pkg"), Some(&version))
            .expect("cached package should be indexed");
        assert_eq!(shown.dependencies.len(), 1);
        assert!(reloaded.load_package(&PackageId::from("pkg"), &version).is_ok());
    }

    #[test]
    fn cache_rejects_different_artifact_for_existing_exact_version() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package
            .sections
            .push(Section::new(SectionId::custom("cache-test").unwrap(), Vec::from([1, 2, 3])));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);

        let error = registry
            .cache_package(Arc::from(conflicting_package))
            .expect_err("cache should reject conflicting package artifacts");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));

        let loaded = registry.load_package(&PackageId::from("pkg"), &published.version).unwrap();
        assert_eq!(loaded.manifest.dependencies().count(), 0);
        assert!(loaded.sections.is_empty());
    }

    #[test]
    fn stale_cache_does_not_overwrite_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut stale_registry = load_registry(&tempdir);
        let mut current_registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = current_registry.publish(&package_path).unwrap();
        let original_bytes = fs::read(&published.artifact_path).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package.sections.push(Section::new(
            SectionId::custom("stale-cache-test").unwrap(),
            Vec::from([1, 2, 3]),
        ));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);

        let error = stale_registry
            .cache_package(conflicting_package.into())
            .expect_err("stale cache should fail before writing artifact bytes");
        assert!(matches!(error, LocalRegistryError::WriteToStaleIndex));
        assert_eq!(fs::read(&published.artifact_path).unwrap(), original_bytes);
    }

    #[test]
    fn concurrent_cache_repair_does_not_overwrite_existing_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();
        fs::remove_file(&published.artifact_path).unwrap();

        let mut first_registry = load_registry(&tempdir);
        let mut second_registry = load_registry(&tempdir);
        let repaired_package = build_package("pkg", "1.0.0", []);
        let repaired_bytes = repaired_package.to_bytes();
        first_registry.cache_package(repaired_package.into()).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package.sections.push(Section::new(
            SectionId::custom("cache-repair-race-test").unwrap(),
            Vec::from([1, 2, 3]),
        ));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);
        let error = second_registry
            .cache_package(conflicting_package.into())
            .expect_err("cache repair should revalidate the artifact under the index lock");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
        assert_eq!(fs::read(&published.artifact_path).unwrap(), repaired_bytes);
    }

    #[test]
    fn cache_repair_checks_legacy_artifact_before_writing_qualified_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();
        let original_bytes = fs::read(&published.artifact_path).unwrap();
        let legacy_path =
            registry.legacy_artifact_path_for_digest(published.version.digest.unwrap());
        fs::rename(&published.artifact_path, &legacy_path).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package.sections.push(Section::new(
            SectionId::custom("legacy-cache-repair-test").unwrap(),
            Vec::from([1, 2, 3]),
        ));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);

        let error = registry
            .cache_package(conflicting_package.into())
            .expect_err("cache repair should reject conflicts with the legacy artifact");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
        assert!(!published.artifact_path.exists());
        assert_eq!(fs::read(&legacy_path).unwrap(), original_bytes);

        let loaded = registry.load_package(&PackageId::from("pkg"), &published.version).unwrap();
        assert!(loaded.sections.is_empty());
    }

    #[test]
    fn cache_repair_checks_legacy_artifact_before_replacing_corrupt_qualified_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();
        let original_bytes = fs::read(&published.artifact_path).unwrap();
        let legacy_path =
            registry.legacy_artifact_path_for_digest(published.version.digest.unwrap());
        fs::write(&legacy_path, &original_bytes).unwrap();
        fs::write(&published.artifact_path, b"not a package").unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package.sections.push(Section::new(
            SectionId::custom("legacy-cache-corrupt-qualified-test").unwrap(),
            Vec::from([1, 2, 3]),
        ));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);

        let error = registry
            .cache_package(conflicting_package.into())
            .expect_err("cache repair should reject conflicts with the legacy artifact");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
        assert_eq!(fs::read(&legacy_path).unwrap(), original_bytes);
        assert_eq!(fs::read(&published.artifact_path).unwrap(), b"not a package");
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
    fn publish_duplicate_semver_does_not_overwrite_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();
        let original_bytes = fs::read(&published.artifact_path).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package
            .sections
            .push(Section::new(SectionId::custom("publish-test").unwrap(), Vec::from([1, 2, 3])));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);
        let conflicting_path = tempdir.path().join("pkg-conflicting.masp");
        conflicting_package.write_to_file(&conflicting_path).unwrap();

        let error = registry
            .publish(&conflicting_path)
            .expect_err("duplicate semver should fail before writing artifact bytes");
        assert!(matches!(error, LocalRegistryError::DuplicateSemanticVersion { .. }));
        assert_eq!(fs::read(&published.artifact_path).unwrap(), original_bytes);

        let loaded = registry.load_package(&PackageId::from("pkg"), &published.version).unwrap();
        assert!(loaded.sections.is_empty());
    }

    #[test]
    fn stale_publish_duplicate_semver_does_not_overwrite_artifact() {
        let tempdir = TempDir::new().unwrap();
        let mut stale_registry = load_registry(&tempdir);
        let mut current_registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = current_registry.publish(&package_path).unwrap();
        let original_bytes = fs::read(&published.artifact_path).unwrap();

        let mut conflicting_package = build_package("pkg", "1.0.0", []);
        conflicting_package.sections.push(Section::new(
            SectionId::custom("stale-publish-test").unwrap(),
            Vec::from([1, 2, 3]),
        ));
        assert_eq!(Some(conflicting_package.digest()), published.version.digest);
        let conflicting_path = tempdir.path().join("pkg-conflicting.masp");
        conflicting_package.write_to_file(&conflicting_path).unwrap();

        let error = stale_registry
            .publish(&conflicting_path)
            .expect_err("stale publish should fail before writing artifact bytes");
        assert!(matches!(error, LocalRegistryError::WriteToStaleIndex));
        assert_eq!(fs::read(&published.artifact_path).unwrap(), original_bytes);
    }

    #[test]
    fn failed_publish_artifact_write_does_not_persist_index_on_later_save() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package = build_package("pkg", "1.0.0", []);
        let package_path = tempdir.path().join("pkg.masp");
        package.write_to_file(&package_path).unwrap();
        let artifact_path =
            registry.artifact_path_for_package(&package.name, &package.version, package.digest());
        fs::create_dir(&artifact_path).unwrap();

        let error = registry
            .publish(&package_path)
            .expect_err("artifact write should fail while the artifact path is a directory");
        assert!(matches!(error, LocalRegistryError::IndexWrite(_)));
        fs::remove_dir(&artifact_path).unwrap();

        let other_path = tempdir.path().join("other.masp");
        build_package("other", "1.0.0", []).write_to_file(&other_path).unwrap();
        registry.publish(&other_path).expect("later publish should succeed");

        let reloaded = load_registry(&tempdir);
        assert!(reloaded.show(&PackageId::from("pkg"), None).is_none());
        assert!(reloaded.show(&PackageId::from("other"), None).is_some());
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

    #[test]
    fn load_package_rejects_artifact_that_does_not_match_requested_identity() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package_path = tempdir.path().join("pkg.masp");
        build_package("pkg", "1.0.0", []).write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();

        build_package("other", "1.0.0", [])
            .write_to_file(&published.artifact_path)
            .unwrap();

        let error = registry
            .load_package(&PackageId::from("pkg"), &published.version)
            .expect_err("artifact mismatch should be rejected");
        assert!(matches!(error, LocalRegistryError::ArtifactMismatch { .. }));
    }

    #[test]
    fn load_package_accepts_legacy_digest_only_artifact_path() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let package = build_package("pkg", "1.0.0", []);
        let package_path = tempdir.path().join("pkg.masp");
        package.write_to_file(&package_path).unwrap();
        let published = registry.publish(&package_path).unwrap();
        let legacy_path =
            registry.legacy_artifact_path_for_digest(published.version.digest.unwrap());
        assert_ne!(published.artifact_path, legacy_path);
        fs::rename(&published.artifact_path, &legacy_path).unwrap();

        let shown = registry.show(&PackageId::from("pkg"), Some(&published.version)).unwrap();
        assert_eq!(shown.artifact_path.as_ref(), Some(&legacy_path));
        assert_eq!(
            registry.artifact_path(&PackageId::from("pkg"), &published.version),
            Some(legacy_path.clone())
        );
        let listed = registry.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].artifact_path.as_ref(), Some(&legacy_path));

        let loaded = registry.load_package(&PackageId::from("pkg"), &published.version).unwrap();
        assert_eq!(loaded.as_ref(), package.as_ref());
    }

    #[test]
    fn summaries_do_not_report_legacy_artifact_for_different_package_identity() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let first = build_package("first", "1.0.0", []);
        let second = build_package("second", "1.0.0", []);
        assert_eq!(first.digest(), second.digest());

        let first_path = tempdir.path().join("first.masp");
        let second_path = tempdir.path().join("second.masp");
        first.write_to_file(&first_path).unwrap();
        second.write_to_file(&second_path).unwrap();

        let first = registry.publish(&first_path).unwrap();
        let second = registry.publish(&second_path).unwrap();
        let legacy_path = registry.legacy_artifact_path_for_digest(first.version.digest.unwrap());
        fs::rename(&first.artifact_path, &legacy_path).unwrap();
        fs::remove_file(&second.artifact_path).unwrap();

        let first_summary = registry.show(&PackageId::from("first"), Some(&first.version)).unwrap();
        assert_eq!(first_summary.artifact_path.as_ref(), Some(&legacy_path));
        let second_summary =
            registry.show(&PackageId::from("second"), Some(&second.version)).unwrap();
        assert_eq!(second_summary.artifact_path.as_ref(), Some(&second.artifact_path));
    }

    #[test]
    fn artifact_paths_distinguish_packages_with_same_mast_digest() {
        let tempdir = TempDir::new().unwrap();
        let mut registry = load_registry(&tempdir);

        let first = build_package("first", "1.0.0", []);
        let second = build_package("second", "1.0.0", []);
        assert_eq!(first.digest(), second.digest());

        let first_path = tempdir.path().join("first.masp");
        let second_path = tempdir.path().join("second.masp");
        first.write_to_file(&first_path).unwrap();
        second.write_to_file(&second_path).unwrap();

        let first = registry.publish(&first_path).unwrap();
        let second = registry.publish(&second_path).unwrap();
        assert_ne!(first.artifact_path, second.artifact_path);

        let first_loaded =
            registry.load_package(&PackageId::from("first"), &first.version).unwrap();
        let second_loaded =
            registry.load_package(&PackageId::from("second"), &second.version).unwrap();
        assert_eq!(first_loaded.name, PackageId::from("first"));
        assert_eq!(second_loaded.name, PackageId::from("second"));
    }
}
