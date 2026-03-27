use super::*;

pub struct AssemblyProduct {
    // This is unused when the `std` feature is not present
    kind: TargetType,
    artifact: Arc<Library>,
    kernel: Option<Kernel>,
    // This is unused when the `std` feature is not present
    #[allow(unused)]
    manifest: PackageManifest,
}

impl AssemblyProduct {
    pub(super) fn new(
        kind: TargetType,
        artifact: Arc<Library>,
        kernel: Option<Kernel>,
        manifest: PackageManifest,
    ) -> Self {
        assert!(
            kernel.is_none() || kind != TargetType::Kernel,
            "kernels cannot depend on another kernel"
        );
        Self { kind, artifact, kernel, manifest }
    }

    #[cfg(feature = "std")]
    pub fn kind(&self) -> TargetType {
        self.kind
    }

    #[cfg(feature = "std")]
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
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
