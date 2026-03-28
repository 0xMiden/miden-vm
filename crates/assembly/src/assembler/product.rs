use super::*;

pub struct AssemblyProduct {
    kind: TargetType,
    artifact: Arc<Library>,
    kernel: Option<Kernel>,
    manifest: PackageManifest,
    debug_info: Option<DebugInfoSections>,
}

impl AssemblyProduct {
    pub(super) fn new(
        kind: TargetType,
        artifact: Arc<Library>,
        kernel: Option<Kernel>,
        manifest: PackageManifest,
        debug_info: Option<DebugInfoSections>,
    ) -> Self {
        assert!(
            kernel.is_none() || kind != TargetType::Kernel,
            "kernels cannot depend on another kernel"
        );
        Self {
            kind,
            artifact,
            kernel,
            manifest,
            debug_info,
        }
    }

    #[cfg_attr(not(feature = "std"), expect(unused))]
    pub fn kind(&self) -> TargetType {
        self.kind
    }

    #[cfg_attr(not(feature = "std"), expect(unused))]
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    #[cfg_attr(not(feature = "std"), expect(unused))]
    pub fn debug_info(&self) -> Option<&DebugInfoSections> {
        self.debug_info.as_ref()
    }

    pub fn into_artifact(self) -> Arc<Library> {
        self.artifact
    }

    // TODO(pauls): This can be removed when we remove Library/KernelLibrary/Program
    pub fn into_program(self) -> Result<Program, Report> {
        assert_eq!(self.kind, TargetType::Executable);
        let entry = ast::Path::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME);
        let entrypoint = self.artifact.get_export_node_id(&entry);
        Ok(if let Some(kernel) = self.kernel {
            Program::with_kernel(self.artifact.mast_forest().clone(), entrypoint, kernel)
        } else {
            Program::new(self.artifact.mast_forest().clone(), entrypoint)
        })
    }

    // TODO(pauls): This can be removed when we remove Library/KernelLibrary/Program
    pub fn into_kernel_library(self) -> Result<KernelLibrary, Report> {
        assert_eq!(self.kind, TargetType::Kernel);
        KernelLibrary::try_from(self.artifact).map_err(|error| Report::msg(error.to_string()))
    }
}
