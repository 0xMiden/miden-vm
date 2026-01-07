use alloc::collections::BTreeMap;
use core::borrow::Borrow;

use pubgrub::VersionSet as _;

use super::*;
use crate::{Package, Version, VersionRequirement};

/// A type alias for an ordered map of packages and the set of versions that can satisfy the
/// requirement for that package.
pub type PackageRequirements = BTreeMap<PackageId, VersionSet>;

/// [PackageIndex] is used as an in-memory database of package information needed for dependency
/// resolution for Miden projects. It records and can provide information about:
///
/// * All packages for which there is at least one version available
/// * All versions of a package that are available
/// * The dependencies for each version of a package, and their version requirements.
///
/// Additionally, [PackageIndex] implements version selection and dependency resolution for packages
/// in the index. Since this functionality is central to any tooling around Miden projects, we
/// implement it here, rather than push the responsibility onto downstream crates.
///
/// This structure _does not_ provide any of the following:
///
/// * Package metadata beyond version and dependency requirements
/// * MAST of indexed packages
/// * A guarantee that indexed packages actually exist or that their sources/MAST can be obtained
///
/// It is up to downstream consumers of the index to construct it and populate it with packages
/// known to them, such that packages selected by [`PackageResolver::resolve`] can be resolved to
/// relevant artifacts, e.g. an assembled package, Miden project sources, etc.
#[derive(Default)]
pub struct PackageIndex {
    packages: BTreeMap<PackageId, BTreeMap<Version, PackageRequirements>>,
}

/// Construction
impl PackageIndex {
    /// Register `package` in the index.
    ///
    /// This is essentially a convenience wrapper around [`PackageIndex::insert`] for the common
    /// case of populating the index with package information loaded from a Miden project.
    pub fn register(&mut self, package: &Package) {
        let name = PackageId::from(package.name().into_inner());
        let version = package.version().into_inner().clone();
        let version = Version::from(version);
        let deps = package.dependencies().iter().map(|dep| {
            let name = PackageId::from(dep.name().clone());
            let req = match dep.required_version() {
                None => VersionSet::full(),
                Some(req) => VersionSet::from(req),
            };
            (name, req)
        });

        self.insert(name, version, deps);
    }

    /// Insert a new entry in the index for `name` and `version`, with `dependencies` providing the
    /// set of version constraints for the package dependencies.
    pub fn insert<D, P, V>(&mut self, name: impl Into<PackageId>, version: Version, dependencies: D)
    where
        D: IntoIterator<Item = (P, V)>,
        P: Into<PackageId>,
        V: Into<VersionSet>,
    {
        let name = name.into();
        let deps = dependencies.into_iter().map(|(k, v)| (k.into(), v.into())).collect();

        self.insert_or_refine(name, version, deps);
    }

    /// Add or update an entry in the index for `name` and `version`, as follows:
    ///
    /// * If there are no versions recorded for `name`, initialize the index for `name` with the
    ///   provided `version` and `deps.
    /// * If there are existing versions for `name`, but `version` is new, and an entry for
    ///   `version` with `deps`.
    /// * If there is an existing entry for `version`:
    ///   * Overwrite the previous dependency map with `deps` for the entry
    ///   * If the entry in the index does not have an associated package digest, but one was given
    ///     with `version`, then update the entry in the index to reflect the more precise version
    ///     data.
    ///   * If the entry in the index has an associated package digest, but `version` does not, then
    ///     ignore the insertion entirely, in order to preserve the dependencies that were recorded
    ///     with the more precise version.
    ///
    /// In effect, this method ensures that we only expand or refine the index.
    fn insert_or_refine(&mut self, name: PackageId, version: Version, deps: PackageRequirements) {
        use alloc::collections::btree_map::Entry;

        match self.packages.entry(name) {
            Entry::Vacant(entry) => {
                let versions = BTreeMap::from_iter([(version, deps)]);
                entry.insert(versions);
            },
            Entry::Occupied(mut entry) => {
                let versions = entry.get_mut();
                match versions.entry(version.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(deps);
                    },
                    Entry::Occupied(mut entry) => {
                        // Do not overwrite an existing entry if that entry has an associated
                        // package digest, so as to preserve the more precise version information.
                        if entry.key().digest.is_none() {
                            // If `version` has an associated package digest, then we need to
                            // recreate the entry in the index to ensure that the more precise
                            // version is used
                            if version.digest.is_some() {
                                let _ = entry.remove_entry();
                                versions.insert(version, deps);
                            } else {
                                // Otherwise, treat this like a normal `insert` and overwrite the
                                // dependencies associated with this version entry.
                                entry.insert(deps);
                            }
                        }
                    },
                }
            },
        }
    }
}

/// Queries
impl PackageIndex {
    /// Returns true if package `name` has any available versions in the index.
    #[inline(always)]
    pub fn is_available<Q>(&self, name: &Q) -> bool
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages.contains_key(name)
    }

    /// Returns true if package `name` with `version` is available in the index.
    #[inline(always)]
    pub fn is_version_available<Q>(&self, name: &Q, version: &Version) -> bool
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages
            .get(name)
            .map(|versions| versions.contains_key(version))
            .unwrap_or(false)
    }

    /// Search for a version of package `name` that matches `requirement`, and return its
    /// dependencies.
    ///
    /// The version selected by this method will be the latest one which satisfies `requirement`.
    #[inline(always)]
    pub fn find<Q>(
        &self,
        name: &Q,
        requirement: &VersionRequirement,
    ) -> Option<&PackageRequirements>
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages.get(name).and_then(|versions| {
            versions
                .iter()
                .rev()
                .filter_map(|(v, deps)| if v.satisfies(requirement) { Some(deps) } else { None })
                .next()
        })
    }

    /// Get the set of versions associated with `name` in the index.
    #[inline(always)]
    pub(crate) fn get<Q>(&self, name: &Q) -> Option<&BTreeMap<Version, PackageRequirements>>
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages.get(name)
    }

    /// Get an iterator over all versions of `package` available in the index, in descending order.
    ///
    /// NOTE: Descending order here is determined by the `Ord` implementation of [Version], which
    /// orders versions by their semantic versioning scheme, and disambiguates using package digests
    /// when known.
    pub fn available_versions<Q>(&self, package: &Q) -> impl Iterator<Item = &Version>
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages.get(package).into_iter().flat_map(|k| k.keys()).rev()
    }

    /// Get an iterator over all versions of `package` that satisfy `requirement.
    pub fn list_versions<'a, Q>(
        &'a self,
        package: &'a Q,
        requirement: &'a VersionRequirement,
    ) -> impl Iterator<Item = &'a Version> + 'a
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.available_versions(package).filter(|v| v.satisfies(requirement))
    }
}

impl<'a, V, D> FromIterator<(&'a str, V)> for PackageIndex
where
    D: IntoIterator<Item = (&'a str, VersionSet)>,
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
                let deps = deps.into_iter().map(|(name, vs)| (PackageId::from(name), vs));
                index.insert(name.clone(), version, deps);
            }
        }
        index
    }
}
