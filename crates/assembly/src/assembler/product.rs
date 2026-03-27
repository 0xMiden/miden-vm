use super::*;

pub struct AssemblyProduct {
    // This is unused when the `std` feature is not present
    #[allow(unused)]
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

    pub fn into_program(self) -> Result<Program, Report> {
        let entry = ast::Path::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME);
        let entrypoint = self.artifact.get_export_node_id(&entry);
        Ok(if let Some(kernel) = self.kernel {
            Program::with_kernel(self.artifact.mast_forest().clone(), entrypoint, kernel)
        } else {
            Program::new(self.artifact.mast_forest().clone(), entrypoint)
        })
    }

    pub fn into_kernel_library(self) -> Result<KernelLibrary, Report> {
        KernelLibrary::try_from(self.artifact).map_err(|error| Report::msg(error.to_string()))
    }
}
