use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    sync::Arc,
    vec,
};
use core::borrow::Borrow;

use miden_assembly_syntax::{
    Report,
    debuginfo::{SourceManager, Uri},
    diagnostics::{LabeledSpan, Severity, diagnostic},
};
use pubgrub::VersionSet as _;

use crate::{
    DependencyVersionScheme, GitRevision, Package, PackageId, Version, VersionRequirement,
    VersionSet, VersionedPackageId,
};

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
#[derive(Default, Clone)]
pub struct PackageIndex {
    packages: BTreeMap<PackageId, BTreeMap<Version, PackageVersionInfo>>,
}

#[derive(Clone, Debug)]
pub struct PackageVersionInfo {
    pub version: Version,
    pub requirements: PackageRequirements,
    pub location: PackageLocation,
}

#[derive(Default, Debug, Clone)]
pub enum PackageLocation {
    /// The package is assumed to be available via the registry when needed
    #[default]
    Registry,
    /// The package has been loaded by the index, or provided to the index
    Source(Arc<Package>),
    /// The package is assumed to be available via `git` at the given repo and revision
    Git { repo: Uri, rev: GitRevision },
}

/// Construction
impl PackageIndex {
    /// Create a [PackageIndex] seeded from `package` in `workspace`.
    ///
    /// It is assumed that the caller has already verified that `package` is a member of
    /// `workspace`.
    pub fn extend_for_package_in_workspace(
        &mut self,
        package: Arc<Package>,
        workspace: &crate::Workspace,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<(), Report> {
        self.seed(
            workspace.members().iter().cloned().chain(core::iter::once(package)),
            source_manager,
        )?;
        Ok(())
    }

    /// Create a [PackageIndex] seeded from `package`.
    ///
    /// For packages that are members of a workspace, you should prefer
    /// [`Self::for_package_in_workspace`].
    pub fn extend_for_package(
        &mut self,
        package: Arc<Package>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<(), Report> {
        self.seed([package], source_manager)?;
        Ok(())
    }

    /// Register `package` in the index.
    ///
    /// This is essentially a convenience wrapper around [`PackageIndex::insert`] for the common
    /// case of populating the index with package information loaded from a Miden project.
    pub fn register(&mut self, package: Arc<Package>) {
        let name = PackageId::from(package.name().into_inner());
        let version = package.version().into_inner().clone();
        let version = Version::from(version);
        let scheme = PackageLocation::Source(package.clone());
        let deps = package.dependencies().iter().map(|dep| {
            let name = PackageId::from(dep.name().clone());
            let linkage = dep.linkage;
            let req = match dep.required_version() {
                None => VersionSet::full().with_linkage(linkage),
                Some(req) => VersionSet::from(req).with_linkage(linkage),
            };
            (name, req)
        });

        self.insert(name, version, deps, scheme);
    }

    fn seed(
        &mut self,
        roots: impl IntoIterator<Item = Arc<Package>>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<(), Report> {
        let mut worklist = VecDeque::with_capacity(8);
        worklist.extend(roots);

        let mut visited = alloc::collections::BTreeSet::<VersionedPackageId>::default();
        while let Some(root) = worklist.pop_front() {
            let vpkgid = VersionedPackageId {
                id: root.name().clone().into_inner().into(),
                version: Version {
                    version: root.version().into_inner().clone(),
                    digest: None,
                },
            };
            if visited.insert(vpkgid) {
                self.load_package_into_index(root, &mut worklist, &source_manager)?;
            }
        }

        Ok(())
    }

    fn load_package_into_index(
        &mut self,
        root: Arc<Package>,
        worklist: &mut VecDeque<Arc<crate::Package>>,
        source_manager: &dyn SourceManager,
    ) -> Result<(), Report> {
        self.register(root.clone());

        let root_dir = root.manifest_path().and_then(|p| p.parent());
        for dependency in root.dependencies().iter() {
            let (span, manifest_path) = match &dependency.version {
                DependencyVersionScheme::Path { path, .. } => match root_dir {
                    Some(root_dir) => {
                        (path.span(), root_dir.join(path.path()).join("miden-project.toml"))
                    },
                    None => continue,
                },
                DependencyVersionScheme::Workspace { member: path } => match root_dir {
                    Some(root_dir) => {
                        let workspace_dir = crate::workspace::locate(root_dir)?.unwrap();
                        let workspace_manifest =
                            workspace_dir.join(path.path()).join("miden-project.toml");
                        (path.span(), workspace_manifest)
                    },
                    None => continue,
                },
                _ => continue,
            };
            match crate::Project::load_from_file(&manifest_path, source_manager)? {
                crate::Project::Package(package) => {
                    worklist.push_back(package);
                },
                crate::Project::WorkspacePackage { package, workspace } => {
                    let members =
                        workspace.members().iter().cloned().chain(core::iter::once(package));
                    worklist.extend(members);
                },
                crate::Project::Workspace(_ws) => {
                    return Err(Report::from(diagnostic!(
                        severity = Severity::Error,
                        labels = vec![LabeledSpan::at(span, "invalid dependency path")],
                        "cannot load dependency '{}': expected package manifest, but got workspace manifest instead",
                        dependency.name()
                    )));
                },
            }
        }

        Ok(())
    }

    /// Insert a new entry in the index for `name` and `version`, with `dependencies` providing the
    /// set of version constraints for the package dependencies.
    pub fn insert<D, P, V>(
        &mut self,
        name: impl Into<PackageId>,
        version: Version,
        dependencies: D,
        scheme: PackageLocation,
    ) where
        D: IntoIterator<Item = (P, V)>,
        P: Into<PackageId>,
        V: Into<VersionSet>,
    {
        let name = name.into();
        let requirements = dependencies.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        let info = PackageVersionInfo { version, requirements, location: scheme };

        self.insert_or_refine(name, info);
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
    fn insert_or_refine(&mut self, name: PackageId, info: PackageVersionInfo) {
        use alloc::collections::btree_map::Entry;

        match self.packages.entry(name) {
            Entry::Vacant(entry) => {
                let version = info.version.clone();
                let versions = BTreeMap::from_iter([(version, info)]);
                entry.insert(versions);
            },
            Entry::Occupied(mut entry) => {
                let versions = entry.get_mut();
                match versions.entry(info.version.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(info);
                    },
                    Entry::Occupied(mut entry) => {
                        // Do not overwrite an existing entry if that entry has an associated
                        // package digest, so as to preserve the more precise version information.
                        if entry.key().digest.is_none() {
                            // If `version` has an associated package digest, then we need to
                            // recreate the entry in the index to ensure that the more precise
                            // version is used
                            if info.version.digest.is_some() {
                                let version = info.version.clone();
                                let _ = entry.remove_entry();
                                versions.insert(version, info);
                            } else {
                                // Otherwise, treat this like a normal `insert` and overwrite the
                                // dependencies associated with this version entry.
                                entry.insert(info);
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
    pub fn find<Q>(&self, name: &Q, requirement: &VersionRequirement) -> Option<&PackageVersionInfo>
    where
        PackageId: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.packages.get(name).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find_map(|(v, info)| if v.satisfies(requirement) { Some(info) } else { None })
        })
    }

    /// Get the set of versions associated with `name` in the index.
    pub fn get_exact(&self, package: &VersionedPackageId) -> Option<&PackageVersionInfo> {
        self.packages
            .get(&package.id)
            .and_then(|versions| versions.get(&package.version))
    }

    /// Get the set of versions associated with `name` in the index.
    #[inline(always)]
    pub(crate) fn get<Q>(&self, name: &Q) -> Option<&BTreeMap<Version, PackageVersionInfo>>
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
                index.insert(name.clone(), version, deps, PackageLocation::Registry);
            }
        }
        index
    }
}
