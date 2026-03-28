use alloc::{collections::BTreeMap, format, sync::Arc};

use miden_assembly_syntax::diagnostics::Report;
use miden_mast_package::{Dependency as PackageDependency, Package as MastPackage};
use miden_package_registry::PackageId;

// RUNTIME DEPENDENCIES
// ================================================================================================

#[derive(Default)]
pub(super) struct RuntimeDependencies {
    pub deps: BTreeMap<PackageId, PackageDependency>,
    pub kernel: Option<Arc<MastPackage>>,
}

impl RuntimeDependencies {
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

    pub fn merge_dependency(&mut self, dependency: PackageDependency) -> Result<(), Report> {
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
