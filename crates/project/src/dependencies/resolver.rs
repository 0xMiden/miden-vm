pub use miden_package_registry::{PackageId, PackageRecord, PackageRegistry, PackageResolver};

use crate::{Package, Workspace};

/// Dependency resolution
impl Package {
    /// Register `self` in the given package registry using the dependency metadata from its manifest.
    pub fn register_with<R>(&self, registry: &mut R)
    where
        R: ?Sized + PackageRegistry,
    {
        let name = PackageId::from(self.name().into_inner());
        let version = miden_package_registry::Version::from(self.version().into_inner().clone());
        let record = PackageRecord::new(
            version.clone(),
            self.dependencies().iter().map(|dependency| {
                (PackageId::from(dependency.name().clone()), dependency.required_version())
            }),
        );
        let record = match self.description() {
            Some(description) => record.with_description(description),
            None => record,
        };

        registry.register(name, version, record);
    }

    /// Construct a resolver for `self` against the provided registry.
    pub fn resolver_for_package<'a, R>(&self, registry: &'a R) -> PackageResolver<'a, R>
    where
        R: ?Sized + PackageRegistry,
    {
        PackageResolver::for_package(
            self.name().into_inner().clone(),
            self.version().into_inner().clone(),
            registry,
        )
    }

    /// Construct a resolver for `self` in `workspace` against the provided registry.
    pub fn resolver_for_package_in_workspace<'a, R>(
        &self,
        workspace: &Workspace,
        registry: &'a R,
    ) -> PackageResolver<'a, R>
    where
        R: ?Sized + PackageRegistry,
    {
        PackageResolver::for_workspace(
            self.name().into_inner().clone(),
            self.version().into_inner().clone(),
            workspace.members().iter().map(|member| member.name().into_inner().clone()),
            registry,
        )
    }
}
