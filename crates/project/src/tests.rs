use std::{boxed::Box, fs, path::Path, sync::Arc};

use miden_assembly_syntax::{
    Path as MasmPath,
    debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt},
    diagnostics::Report,
};
use miden_core::assert_matches;
use tempfile::TempDir;

use crate::{DependencyVersionScheme, Linkage, Project, TargetType, Workspace};

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
        .get_member_by_name("miden-utils")
        .expect("failed to locate 'miden-utils' project");
    assert!(Arc::ptr_eq(
        &core_project,
        &workspace
            .get_member_by_relative_path("utils")
            .expect("failed to locate 'miden-utils' project by relative path")
    ));

    let core_lib = core_project.library_target().unwrap();
    assert_eq!(core_lib.ty, TargetType::Library);
    assert_eq!(&**core_lib.name.inner(), "miden::utils");
    assert_eq!(&**core_lib.namespace.inner(), MasmPath::new("::miden::utils"));
    assert_eq!(core_project.executable_targets().len(), 0);

    let kernel_project = workspace
        .get_member_by_name("miden-tx")
        .expect("failed to locate 'miden-tx' project");

    let kernel_lib = kernel_project.library_target().unwrap();
    assert_eq!(kernel_lib.ty, TargetType::Kernel);
    assert_eq!(&**kernel_lib.name.inner(), "miden-tx");
    assert_eq!(&**kernel_lib.namespace.inner(), MasmPath::kernel_path());
    assert_eq!(kernel_project.executable_targets().len(), 2);

    assert_eq!(kernel_project.executable_targets()[0].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.executable_targets()[0].name.inner(), "entry");
    assert_eq!(
        &**kernel_project.executable_targets()[0].namespace.inner(),
        MasmPath::exec_path()
    );

    assert_eq!(kernel_project.executable_targets()[1].ty, TargetType::Executable);
    assert_eq!(&**kernel_project.executable_targets()[1].name.inner(), "entry-alt");
    assert_eq!(
        &**kernel_project.executable_targets()[1].namespace.inner(),
        MasmPath::exec_path()
    );

    assert_eq!(kernel_project.dependencies().len(), 1);
    assert_eq!(&**kernel_project.dependencies()[0].name(), "miden-utils");
    assert_matches!(kernel_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "utils");
    assert_eq!(kernel_project.dependencies()[0].linkage(), Linkage::Static);

    let userspace_project = workspace
        .get_member_by_name("miden-protocol")
        .expect("failed to locate 'miden-protocol' project");

    let userspace_lib = userspace_project.library_target().unwrap();
    assert_eq!(userspace_lib.ty, TargetType::Library);
    assert_eq!(&**userspace_lib.name.inner(), "miden::protocol");
    assert_eq!(&**userspace_lib.namespace.inner(), MasmPath::new("::miden::protocol"));
    assert_eq!(userspace_project.executable_targets().len(), 0);

    assert_eq!(userspace_project.dependencies().len(), 2);
    assert_eq!(&**userspace_project.dependencies()[0].name(), "miden-tx");
    assert_matches!(userspace_project.dependencies()[0].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "kernel");
    assert_eq!(&**userspace_project.dependencies()[1].name(), "miden-utils");
    assert_matches!(userspace_project.dependencies()[1].scheme(), DependencyVersionScheme::Workspace { member, .. } if member.path() == "utils");
    assert_eq!(userspace_project.dependencies()[1].linkage(), Linkage::Dynamic);

    Ok(())
}

#[test]
fn workspace_dev_override_is_used_for_child_profile_inheritance() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace-profile");
    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["app"]

[workspace.package]
version = "0.1.0"

[profile.dev]
debug = false
"#,
    )
    .unwrap();

    let app_manifest_path = app_dir.join("miden-project.toml");
    fs::write(
        &app_manifest_path,
        r#"[package]
name = "app"
version = "0.1.0"

[profile.child]
inherits = "dev"
"#,
    )
    .unwrap();

    let context = TestContext::default();
    let Project::WorkspacePackage { package, workspace: _ } =
        Project::load(&app_manifest_path, &context.source_manager)?
    else {
        panic!("expected workspace package")
    };
    let child = package.profiles().iter().find(|p| p.name().as_ref() == "child").unwrap();

    assert!(!child.should_emit_debug_info());

    Ok(())
}

#[test]
fn workspace_package_version_can_be_inherited_with_dotted_key_syntax() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace-version");
    let app_dir = root.join("app");
    fs::create_dir_all(&app_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["app"]

[workspace.package]
version = "0.1.0"
"#,
    )
    .unwrap();

    let app_manifest_path = app_dir.join("miden-project.toml");
    fs::write(
        &app_manifest_path,
        r#"[package]
name = "app"
version.workspace = true
"#,
    )
    .unwrap();

    let context = TestContext::default();
    let Project::WorkspacePackage { package, workspace: _ } =
        Project::load(&app_dir, &context.source_manager)?
    else {
        panic!("expected workspace package")
    };

    assert_eq!(format!("{}", package.version()), "0.1.0");

    Ok(())
}

#[test]
fn load_project_reference_keeps_non_member_workspace_paths_authoritative() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let member_dir = root.join("member");
    let vendor_dir = root.join("vendor").join("dep");
    fs::create_dir_all(&member_dir).unwrap();
    fs::create_dir_all(&vendor_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["member"]
"#,
    )
    .unwrap();

    fs::write(
        member_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(member_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let vendor_manifest = vendor_dir.join("miden-project.toml");
    fs::write(
        &vendor_manifest,
        r#"[package]
name = "dep"
version = "9.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(vendor_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let project = Project::load_project_reference("dep", &vendor_dir, &context.source_manager)?;

    assert!(!project.is_workspace_member());
    assert_eq!(project.manifest_path(), Some(vendor_manifest.as_path()));
    assert_eq!(format!("{}", project.package().version()), "9.0.0");

    Ok(())
}

#[test]
fn load_project_reference_resolves_workspace_manifest_file_inputs() -> Result<(), Report> {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    let dep_dir = root.join("dep");
    fs::create_dir_all(&dep_dir).unwrap();

    let workspace_manifest = root.join("miden-project.toml");
    fs::write(
        &workspace_manifest,
        r#"[workspace]
members = ["dep"]
"#,
    )
    .unwrap();

    let dep_manifest = dep_dir.join("miden-project.toml");
    fs::write(
        &dep_manifest,
        r#"[package]
name = "dep"
version = "1.2.3"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(dep_dir.join("lib.masm"), "export.foo\nend\n").unwrap();
    let dep_manifest = dep_manifest.canonicalize().unwrap();

    let context = TestContext::default();
    let project =
        Project::load_project_reference("dep", &workspace_manifest, &context.source_manager)?;

    assert!(project.is_workspace_member());
    assert_eq!(project.manifest_path(), Some(dep_manifest.as_path()));
    assert_eq!(format!("{}", project.package().version()), "1.2.3");

    Ok(())
}

#[test]
fn workspace_rejects_duplicate_member_package_names() {
    let tempdir = TempDir::new().unwrap();
    let root = tempdir.path().join("workspace");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir_all(&first_dir).unwrap();
    fs::create_dir_all(&second_dir).unwrap();

    fs::write(
        root.join("miden-project.toml"),
        r#"[workspace]
members = ["first", "second"]
"#,
    )
    .unwrap();

    fs::write(
        first_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(first_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    fs::write(
        second_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "2.0.0"

[lib]
path = "lib.masm"
"#,
    )
    .unwrap();
    fs::write(second_dir.join("lib.masm"), "export.foo\nend\n").unwrap();

    let context = TestContext::default();
    let error = context
        .load_workspace(root.join("miden-project.toml"))
        .expect_err("duplicate member package names should be rejected");

    assert!(format!("{error}").contains("duplicate"), "{error}");
}
