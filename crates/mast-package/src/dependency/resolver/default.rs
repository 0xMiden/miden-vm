use alloc::{collections::BTreeMap, sync::Arc};
use miden_core::LexicographicWord;
use miden_project::{PackageIndex, PackageResolver, VersionRequirement, VersionSet};

use crate::registry::PackageRegistry;

use super::*;

/// This is an implementation of [DependencyResolver] that maintains an in-memory index of
/// resolutions.
pub struct DefaultDependencyResolver {
    resolved: BTreeMap<LexicographicWord, Resolved>,
    index: PackageIndex,
    registry: Arc<dyn PackageRegistry>,
}

impl Default for DefaultDependencyResolver {
    #[cfg(feature = "std")]
    fn default() -> Self {
        let registry = Arc::<crate::registry::LocalPackageRegistry>::default();
        let index = PackageIndex::default();
        Self {
            resolved: BTreeMap::new(),
            index,
            registry,
        }
    }

    #[cfg(not(feature = "std"))]
    fn default() -> Self {
        let registry = Arc::<crate::registry::InMemoryPackageRegistry>::default();
        let index = PackageIndex::default();
        Self {
            resolved: BTreeMap::new(),
            index,
            registry,
        }
    }
}

impl DefaultDependencyResolver {
    pub fn new(registry: Arc<dyn PackageRegistry>) -> Self {
        Self {
            resolved: BTreeMap::new(),
            index: PackageIndex::default(),
            registry,
        }
    }

    pub fn add_resolution(&mut self, digest: Word, resolution: Resolved) {
        self.resolved.insert(LexicographicWord::new(digest), resolution);
    }
}

impl DependencyResolver for DefaultDependencyResolver {
    fn register_assembled_package(&self, package: Arc<Package>) {
        self.registry.register(package.clone());
        self.index.insert(
            package.name.clone(),
            Version::new(package.version.clone(), *package.digest()),
            package
                .dependencies()
                .iter()
                .map(|dep| (dep.name.clone(), VersionSet::singleton(dep.version.clone()))),
        );
        let dependency = ResolvedDependency {
            name: package.name.clone(),
            version: Version::new(package.version.clone(), *package.digest()),
        };
        self.add_resolution(*package.digest(), Resolved { dependency, package });
    }
    fn register_source_package(&self, package: &miden_project::Package) {
        self.index.register(package);
    }
    fn resolve(&self, dependency: &Dependency) -> Result<ResolvedDependency, Report> {
        let pkgid = PackageId::from(dependency.name().clone());
        let version = dependency.required_version().unwrap_or(VersionRequirement::any());

        self.registry.find(pkgid, &version)
    }

    fn resolve_to_package(&self, dependency: &Dependency) -> Result<Resolved, Report> {
        todo!()
    }

    fn resolved_to_package(&self, resolved: &ResolvedDependency) -> Result<Resolved, Report> {
        todo!()
    }
}
