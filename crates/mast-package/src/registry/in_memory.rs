use alloc::{collections::BTreeMap, sync::Arc};
use core::cell::RefCell;

use miden_core::LexicographicWord;
use miden_project::Version;

use super::*;

/// This is a basic in-memory package index/registry that requires packages to be manually
/// registered with it to be resolvable.
#[derive(Default)]
pub struct InMemoryPackageRegistry {
    index: RefCell<Index>,
}

#[derive(Default)]
struct Index {
    /// An index that allows direct lookup of a package by its digest and no other information
    by_digest: BTreeMap<LexicographicWord, Arc<Package>>,
    /// An index that indexes packages by name, and then by semantic version.
    ///
    /// This index is used in cases where a precise digest is not specified or known.
    by_pkgid_and_version: BTreeMap<PackageId, BTreeMap<miden_project::SemVer, Arc<Package>>>,
}

impl PackageRegistry for InMemoryPackageRegistry {
    fn register(&self, package: Arc<Package>) {
        let mut index = self.index.borrow_mut();
        index
            .by_digest
            .insert(LexicographicWord::new(*package.digest()), package.clone());
        index
            .by_pkgid_and_version
            .entry(PackageId::from(package.name.clone()))
            .or_default()
            .insert(package.version.clone(), package);
    }

    fn find(&self, id: PackageId, req: &VersionRequirement) -> Option<Arc<Package>> {
        let index = self.index.borrow();
        match req {
            VersionRequirement::Digest(digest) => {
                index.get_by_digest(&LexicographicWord::new(digest.into_inner()))
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
        let index = self.index.borrow();
        if let Some(found) = index.get_by_pkgid_and_version(&id.id, &id.version) {
            Ok(found)
        } else if index.by_pkgid_and_version.contains_key(&id.id) {
            Err(FetchPackageError::NoMatchingVersion(id.clone()))
        } else {
            Err(FetchPackageError::Unavailable(id.clone()))
        }
    }
}

impl Index {
    fn get_by_digest(&self, digest: &LexicographicWord) -> Option<Arc<Package>> {
        self.by_digest.get(digest).cloned()
    }

    fn get_by_pkgid_and_version(
        &self,
        name: &PackageId,
        version: &Version,
    ) -> Option<Arc<Package>> {
        if let Some(digest) = version.digest.as_ref()
            && let Some(found) = self.get_by_digest(digest)
            && name.eq(&found.name)
        {
            return Some(found);
        }

        let versions = self.by_pkgid_and_version.get(name)?;
        versions.get(&version.version).cloned()
    }
}
