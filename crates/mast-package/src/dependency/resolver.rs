use alloc::{collections::BTreeMap, sync::Arc};

use miden_assembly_syntax::Library;

use crate::{Dependency, Package, Word};

// DEPENDENCY RESOLUTION
// ================================================================================================

/// Resolved dependency
/// In the future, we intend to add Registry variant to describe dependencies to be loaded from the
/// registry.
#[derive(Debug, Clone)]
pub enum ResolvedDependency {
    /// Loaded dependency (library, package, etc.)
    Local(LocalResolvedDependency),
}

impl From<Arc<Library>> for ResolvedDependency {
    fn from(library: Arc<Library>) -> Self {
        Self::Local(LocalResolvedDependency::Library(library))
    }
}

impl From<Arc<Package>> for ResolvedDependency {
    fn from(package: Arc<Package>) -> Self {
        Self::Local(LocalResolvedDependency::Package(package))
    }
}

/// Resolved local(loaded) dependency
#[derive(Debug, Clone)]
pub enum LocalResolvedDependency {
    Library(Arc<Library>),
    Package(Arc<Package>),
}

impl From<Arc<Library>> for LocalResolvedDependency {
    fn from(library: Arc<Library>) -> Self {
        Self::Library(library)
    }
}

impl From<Arc<Package>> for LocalResolvedDependency {
    fn from(package: Arc<Package>) -> Self {
        Self::Package(package)
    }
}

// RESOLVER
// ================================================================================================

pub trait DependencyResolver {
    fn resolve(&self, dependency: &Dependency) -> Option<ResolvedDependency>;
}

#[derive(Debug, Default)]
pub struct MemDependencyResolverByDigest {
    resolved: BTreeMap<Word, ResolvedDependency>,
}

impl MemDependencyResolverByDigest {
    pub fn add(&mut self, digest: Word, resolution: ResolvedDependency) {
        self.resolved.insert(digest, resolution);
    }
}

impl DependencyResolver for MemDependencyResolverByDigest {
    fn resolve(&self, dependency: &Dependency) -> Option<ResolvedDependency> {
        self.resolved.get(&dependency.digest).cloned()
    }
}
