use core::cell::RefCell;
use std::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    vec::Vec,
};

use miden_core::LexicographicWord;
use miden_project::{PackageId, Version};
use rustc_hash::FxHashMap;

use super::*;

/// This is a default implementation of [PackageRegistry] that resolves packages as follows:
///
/// 1. Attempt to resolve the package using the in-memory index/cache.
/// 2. If we did not get a hit on the in-memory index, then attempt to locate the package file in
///    `$MIDEN_SYSROOT/lib` as `<name>-<version>.masp`. We will discuss below what happens when we
///    find a potential match here.
/// 3. If a package was not found in `$MIDEN_SYSROOT/lib`, look in one of the configured library
///    search paths. Here, we will match both `<name>-<version>.masp` and `<name>.masp`, order by
///    most recently modified, and then take the first match which has the expected name and
///    version.
///
/// When we resolve packages on disk, we first look for a matching `.masp` file, and then read the
/// package into memory and check that its name and version metadata match the request. If we have
/// a match, then we will add the package to the in-memory index of the registry.
#[derive(Default)]
pub struct LocalPackageRegistry {
    index: RefCell<Index>,
    /// The set of user-defined search paths which will be used to resolve packages that are not
    /// found under `$MIDEN_SYSROOT/lib`.
    search_paths: BTreeSet<Box<std::path::Path>>,
}

#[derive(Default)]
struct Index {
    /// An index that allows direct lookup of a package by its digest and no other information
    by_digest: FxHashMap<PackageDigest, Arc<Package>>,
    /// An index that indexes packages by name, and then by semantic version.
    ///
    /// This index is used in cases where a precise digest is not specified or known.
    by_pkgid_and_version: FxHashMap<PackageId, BTreeMap<miden_project::SemVer, Arc<Package>>>,
}

impl LocalPackageRegistry {
    /// Create a new, default instance of this package registry
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend the set of search paths that this registry will use to resolve packages on disk.
    pub fn with_search_paths<'a>(
        &mut self,
        search_paths: impl IntoIterator<Item = &'a std::path::Path>,
    ) -> &mut Self {
        self.search_paths
            .extend(search_paths.into_iter().map(|p| p.to_path_buf().into_boxed_path()));
        self
    }
}

impl Index {
    fn get_by_digest(&self, digest: &PackageDigest) -> Option<Arc<Package>> {
        self.by_digest.get(digest).cloned()
    }

    fn get_by_pkgid_and_version(
        &self,
        name: &PackageId,
        version: &Version,
    ) -> Option<Arc<Package>> {
        if let Some(digest) = version.digest.as_ref()
            && let Some(found) = self.get_by_digest(&PackageDigest(*digest))
            && name.eq(&found.name)
        {
            return Some(found);
        }

        let versions = self.by_pkgid_and_version.get(name)?;
        versions.get(&version.version).cloned()
    }
}

impl PackageRegistry for LocalPackageRegistry {
    fn register(&self, package: Arc<Package>) {
        let digest = PackageDigest(LexicographicWord::new(*package.digest()));
        let pkgid = PackageId::from(package.name.clone());
        let version = package.version.clone();

        let mut index = self.index.borrow_mut();
        index.by_digest.insert(digest, package.clone());
        index.by_pkgid_and_version.entry(pkgid).or_default().insert(version, package);
    }

    fn find(&self, id: PackageId, req: &VersionRequirement) -> Option<Arc<Package>> {
        let index = self.index.borrow();
        match req {
            VersionRequirement::Digest(digest) => {
                index.get_by_digest(&PackageDigest(LexicographicWord::new(digest.into_inner())))
            },
            VersionRequirement::Semantic(ver) => {
                let versions = index.by_pkgid_and_version.get(&id)?;
                for (version, package) in versions.iter().rev() {
                    if ver.matches(version) {
                        return Some(package.clone());
                    }
                }

                None
            },
        }
    }

    fn fetch(&self, id: &VersionedPackageId) -> Result<Arc<Package>, FetchPackageError> {
        if let Some(found) = self.index.borrow().get_by_pkgid_and_version(&id.id, &id.version) {
            return Ok(found);
        }

        let versioned_name = alloc::format!("{}-{}", &id.id, &id.version.version);
        let is_matching_package_file = |path: &std::path::Path, ty: &std::fs::FileType| -> bool {
            if !ty.is_file() {
                return false;
            }
            if path.extension().is_none_or(|ext| !ext.eq_ignore_ascii_case("masp")) {
                return false;
            }
            let Some(basename) = path.file_stem() else {
                return false;
            };
            let basename = basename.to_string_lossy();
            basename == *id.id || basename == versioned_name
        };

        if let Ok(sysroot_dir) = std::env::var("MIDEN_SYSROOT") {
            let lib_dir = std::path::Path::new(&sysroot_dir).join("lib");
            let matches =
                search_directory_for(&lib_dir, is_matching_package_file).unwrap_or_default();

            for matched in matches.iter() {
                let Some(package) = fetch_package_from_path(matched, id)? else {
                    continue;
                };
                self.register(package.clone());
                return Ok(package);
            }
        }

        for search_path in self.search_paths.iter() {
            let matches =
                search_directory_for(search_path, is_matching_package_file).unwrap_or_default();
            for matched in matches.iter() {
                let Some(package) = fetch_package_from_path(matched, id)? else {
                    continue;
                };
                self.register(package.clone());
                return Ok(package);
            }
        }

        Err(FetchPackageError::Unavailable(id.clone()))
    }
}

/// A simple newtype-wrapper around [LexicographicWord] to allow use in [FxHashMap]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
struct PackageDigest(LexicographicWord);

impl core::borrow::Borrow<LexicographicWord> for PackageDigest {
    #[inline(always)]
    fn borrow(&self) -> &LexicographicWord {
        &self.0
    }
}

impl core::hash::Hash for PackageDigest {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.inner().hash(state);
    }
}

/// Load a package from disk and return it if it matches `id`.
///
/// This returns `Err` only for I/O-related errors.
fn fetch_package_from_path(
    path: &std::path::Path,
    id: &VersionedPackageId,
) -> Result<Option<Arc<Package>>, FetchPackageError> {
    use std::io::Cursor;

    use miden_core::serde::Deserializable;

    let file = std::fs::read(path).map_err(|err| FetchPackageError::LoadFailed {
        package: id.clone(),
        reason: err.to_string(),
    })?;
    let mut reader = Cursor::new(file);
    let package = Package::read_from(&mut reader).map(Arc::new).map_err(|err| {
        FetchPackageError::LoadFailed {
            package: id.clone(),
            reason: err.to_string(),
        }
    })?;

    if package.name == id.id
        && (id
            .version
            .digest
            .is_some_and(|digest| digest == LexicographicWord::new(*package.digest()))
            || id.version.version == package.version)
    {
        Ok(Some(package))
    } else {
        Ok(None)
    }
}

/// Traverses the files in `dir` and collects all of the paths that match `predicate`.
///
/// Returns `Err` if `dir` cannot be read, in all other cases it returns `Ok` with a possibly-empty
/// vector.
///
/// In cases where a directory entry cannot be read, or its metadata is inaccessible, the entry is
/// skipped entirely.
fn search_directory_for<P>(
    dir: &std::path::Path,
    predicate: P,
) -> Result<Vec<std::path::PathBuf>, std::io::Error>
where
    P: Fn(&std::path::Path, &std::fs::FileType) -> bool,
{
    let reader = dir.read_dir()?;
    let mut matches = Vec::default();
    for entry in reader.filter_map(|entry| entry.ok()) {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if predicate(&path, &ft) {
            matches.push(path);
        }
    }

    Ok(matches)
}
