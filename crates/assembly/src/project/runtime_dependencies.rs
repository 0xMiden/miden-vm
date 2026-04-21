use alloc::{collections::BTreeMap, format, sync::Arc};

use miden_assembly_syntax::diagnostics::Report;
use miden_mast_package::{Dependency as PackageDependency, Package as MastPackage};
use miden_package_registry::PackageId;
use miden_project::Linkage;

use crate::project::ResolvedPackage;

// RUNTIME DEPENDENCIES
// ================================================================================================

#[derive(Default)]
pub(super) struct RuntimeDependencies {
    pub deps: BTreeMap<PackageId, PackageDependency>,
    pub kernel: Option<Arc<MastPackage>>,
}

impl RuntimeDependencies {
    pub fn merge_package(
        &mut self,
        dependency: ResolvedPackage,
        linkage: Linkage,
    ) -> Result<(), Report> {
        if dependency.package.is_kernel() {
            self.record_linked_kernel_dependency(dependency.package.clone())?;
        } else if let Some(kernel_package) = dependency.linked_kernel_package.clone() {
            self.record_linked_kernel_dependency(kernel_package)?;
        }

        // We record the dynamic/runtime dependencies of a package here.
        //
        // When linking against a package dynamically, both the package and its own dynamically-
        // linked dependencies are recorded in the manifest.
        //
        // When linking statically, only the dynamically-linked dependencies of the package are
        // recorded, not the statically-linked package, as it is by definition included in the
        // assembled package
        //
        // We _always_ record the kernel that a package is assembled against, regardless of
        // linkage, and propagate such dependencies up the dependency tree so as to require
        // that all packages that transitively depend on a kernel, depend on the same kernel.
        //
        // NOTE: If there are conflicting runtime dependencies on the same package, an error
        // will be raised. In the future, we may wish to relax this restriction, since such
        // dependencies are technically satisfiable.
        if matches!(linkage, Linkage::Dynamic) && !dependency.package.is_kernel() {
            self.merge_dependency(dependency.package.to_dependency())?;
        }
        for dep in dependency.package.manifest.dependencies() {
            self.merge_dependency(dep.clone())?;
        }

        Ok(())
    }

    pub fn record_linked_kernel_dependency(
        &mut self,
        package: Arc<MastPackage>,
    ) -> Result<(), Report> {
        debug_assert!(package.is_kernel());

        self.merge_dependency(package.to_dependency())?;

        match &self.kernel {
            Some(existing)
                if existing.name == package.name
                    && existing.version == package.version
                    && existing.digest() == package.digest() =>
            {
                Ok(())
            },
            Some(existing) => Err(Report::msg(format!(
                "conflicting linked kernel packages '{}@{}#{}' and '{}@{}#{}'",
                existing.name,
                existing.version,
                existing.digest(),
                package.name,
                package.version,
                package.digest()
            ))),
            None => {
                self.kernel = Some(package);
                Ok(())
            },
        }
    }

    fn merge_dependency(&mut self, dependency: PackageDependency) -> Result<(), Report> {
        match self.deps.get(&dependency.name) {
            Some(existing)
                if existing.version == dependency.version
                    && existing.kind == dependency.kind
                    && existing.digest == dependency.digest =>
            {
                Ok(())
            },
            Some(existing) => Err(Report::msg(format!(
                "conflicting runtime dependency '{}' resolved to versions '{}#{}' and '{}#{}'",
                dependency.name,
                existing.version,
                existing.digest,
                dependency.version,
                dependency.digest
            ))),
            None => {
                self.deps.insert(dependency.name.clone(), dependency);
                Ok(())
            },
        }
    }
}
