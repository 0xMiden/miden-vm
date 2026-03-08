use std::{boxed::Box, path::Path, sync::Arc};

use miden_assembly_syntax::{
    Path as MasmPath,
    debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt},
    diagnostics::Report,
};
use miden_core::assert_matches;

use crate::{DependencyVersionScheme, TargetType, Workspace};

struct TestContext {
    pub source_manager: Arc<dyn SourceManager>,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

impl TestContext {
    pub fn load_workspace(&self, path: impl AsRef<Path>) -> Result<Box<Workspace>, Report> {
        let path = path.as_ref();
        let source_file = self.source_manager.load_file(path).map_err(Report::msg)?;
        Workspace::load(source_file, &self.source_manager)
    }
}

#[test]
fn can_load_protocol_example_project() -> Result<(), Report> {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/protocol/miden-project.toml");
    let context = TestContext::default();
    let workspace = context.load_workspace(MANIFEST_PATH)?;

    assert_eq!(workspace.members().len(), 3);

    let core_project = workspace
        .get_member_by_name("miden-core")
        .expect("failed to locate 'miden-core' project");
    assert!(Arc::ptr_eq(
        &core_project,
        &workspace
            .get_member_by_relative_path("core")
            .expect("failed to locate 'miden-core' project by relative path")
    ));

    assert_eq!(core_project.targets().len(), 1);
    assert_eq!(core_project.targets()[0].ty, TargetType::Library);
    assert_eq!(&**core_project.targets()[0].namespace.inner(), MasmPath::new("::miden::core"));

    let kernel_project = workspace
        .get_member_by_name("miden-tx")
        .expect("failed to locate 'miden-tx' project");

    assert_eq!(kernel_project.targets().len(), 3);
    assert_eq!(kernel_project.targets()[0].ty, TargetType::Kernel);
    assert_eq!(&**kernel_project.targets()[0].name.inner(), "kernel");
    assert_eq!(&**kernel_project.targets()[0].namespace.inner(), MasmPath::kernel_path());

    assert_eq!(kernel_project.targets()[1].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.targets()[1].name.inner(), "entry");
    assert_eq!(&**kernel_project.targets()[1].namespace.inner(), MasmPath::exec_path());
    assert_eq!(kernel_project.targets()[1].requires.len(), 1);
    assert_eq!(&**kernel_project.targets()[1].requires[0].inner(), "kernel");

    assert_eq!(kernel_project.targets()[2].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.targets()[2].name.inner(), "entry-alt");
    assert_eq!(&**kernel_project.targets()[2].namespace.inner(), MasmPath::exec_path());
    assert_eq!(kernel_project.targets()[2].requires.len(), 1);
    assert_eq!(&**kernel_project.targets()[2].requires[0].inner(), "kernel");

    assert_eq!(kernel_project.dependencies().len(), 1);
    assert_eq!(&**kernel_project.dependencies()[0].name(), "miden-core");
    assert_matches!(kernel_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member } if member.path() == "core");

    let userspace_project = workspace
        .get_member_by_name("miden-protocol")
        .expect("failed to locate 'miden-protocol' project");

    assert_eq!(userspace_project.targets().len(), 1);
    assert_eq!(userspace_project.targets()[0].ty, TargetType::Library);
    assert_eq!(
        &**userspace_project.targets()[0].namespace.inner(),
        MasmPath::new("::miden::protocol")
    );

    assert_eq!(userspace_project.dependencies().len(), 2);
    assert_eq!(&**userspace_project.dependencies()[0].name(), "miden-core");
    assert_matches!(userspace_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member } if member.path() == "core");
    assert_eq!(&**userspace_project.dependencies()[1].name(), "miden-tx");
    assert_matches!(userspace_project.dependencies()[1].scheme(), DependencyVersionScheme::Workspace { member } if member.path() == "kernel");

    Ok(())
}
