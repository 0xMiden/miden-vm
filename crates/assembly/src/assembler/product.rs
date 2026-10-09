use miden_mast_package::{Dependency, debug_info::PackageDebugInfo};

use super::*;

pub struct AssemblyProduct {
    package: Box<Package>,
    kernel_package: Option<Arc<Package>>,
    debug_info: Box<PackageDebugInfo>,
}

impl AssemblyProduct {
    pub(super) fn new(
        package: Box<Package>,
        kernel: Option<Arc<Package>>,
        debug_info: Box<PackageDebugInfo>,
    ) -> Self {
        assert!(
            kernel.is_none() || !package.is_kernel(),
            "kernels cannot depend on another kernel"
        );
        Self {
            package,
            kernel_package: kernel,
            debug_info,
        }
    }

    #[cfg_attr(not(feature = "std"), expect(unused))]
    pub fn extend_dependencies(
        &mut self,
        deps: impl IntoIterator<Item = Dependency>,
    ) -> Result<(), Report> {
        for dep in deps {
            self.package.manifest.add_dependency(dep).map_err(Report::msg)?;
        }

        Ok(())
    }

    pub fn into_artifact(self, emit_debug_info: bool) -> Result<Box<Package>, Report> {
        let Self { mut package, kernel_package, debug_info } = self;
        // Section: embedded kernel package
        if package.is_program()
            && let Some(kernel_package) = kernel_package
        {
            package.sections.push(linked_kernel_package_section(kernel_package.as_ref()));
            if let Some(kernel_dep) =
                package.manifest.dependencies().find(|dep| dep.id() == &kernel_package.name)
            {
                if kernel_dep.digest != kernel_package.dependency_commitment()
                    || kernel_dep.kind != kernel_package.kind
                    || kernel_dep.version() != &kernel_package.version
                {
                    return Err(Report::msg(format!(
                        "unable to register kernel dependency: '{}' already exists as a dependency, but with different metadata than the actual kernel package",
                        kernel_package.name
                    )));
                }
            } else {
                package
                    .manifest
                    .add_dependency(Dependency {
                        name: kernel_package.name.clone(),
                        kind: kernel_package.kind,
                        version: kernel_package.version.clone(),
                        digest: kernel_package.dependency_commitment(),
                    })
                    .map_err(|err| {
                        Report::msg(format!("unable to register kernel dependency: {err}"))
                    })?;
            }
        }

        // Section: debug info
        if emit_debug_info {
            let bytes = debug_info.to_bytes_with_standard_limits().map_err(|error| {
                Report::msg(format!(
                    "assembled package debug info exceeds standard decoder limits: {error}; reduce imported debug metadata or disable debug-info emission"
                ))
            })?;
            package.sections.push(Section::new(SectionId::DEBUG_INFO, bytes));
        }

        Ok(package)
    }
}

fn linked_kernel_package_section(package: &Package) -> Section {
    Section::new(SectionId::KERNEL, package.to_bytes())
}

#[cfg(test)]
mod tests {
    use miden_mast_package::debug_info::{MAX_DEBUG_INFO_STRING_SIZE, PackageDebugInfoBuilder};

    use super::*;
    use crate::testing::TestContext;

    #[test]
    fn artifact_rejects_debug_info_beyond_standard_decoder_limits() {
        for emit_debug_info in [true, false] {
            let context = TestContext::default();
            let module = context.parse_module("begin push.42 end").unwrap();
            let mut product = Assembler::new(context.source_manager())
                .assemble_executable_modules("test".into(), module, [])
                .unwrap();
            let mut debug = PackageDebugInfoBuilder::from(product.debug_info);
            debug.add_string("x".repeat(MAX_DEBUG_INFO_STRING_SIZE + 1));
            product.debug_info = debug.build();
            let result = product.into_artifact(emit_debug_info);
            if emit_debug_info {
                let error = result.expect_err("unreadable debug info must fail assembly");
                let message = error.to_string();
                assert!(message.contains("standard decoder limits"), "{message}");
                assert!(message.contains("debug string size"), "{message}");
                assert!(message.contains("disable debug-info emission"), "{message}");
            } else {
                assert!(result.unwrap().debug_info().unwrap().is_none());
            }
        }
    }
}
