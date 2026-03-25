use std::{process::Command, string::String};

use miden_assembly_syntax::source_file;
use miden_package_registry::PackageRegistry;
use tempfile::TempDir;

use super::*;
use crate::testing::{TestContext, TestRegistry};

#[test]
fn builds_library_package_from_project_profiles() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    write_file(
        &manifest_path,
        r#"[package]
name = "libpkg"
version = "1.2.3"
description = "sample library"

[lib]
path = "lib.masm"
"#,
    );
    write_file(
        &tempdir.path().join("lib.masm"),
        r#"pub proc helper
    push.1
    push.2
    add
end
"#,
    );

    let mut context = TestContext::new();

    let dev = context
        .assemble_library_package(&manifest_path, None)
        .expect("failed to assemble under dev profile");
    assert_eq!(&dev.name, "libpkg");
    assert_eq!(dev.version.to_string(), "1.2.3");
    assert_eq!(dev.description.as_deref(), Some("sample library"));
    assert_eq!(dev.kind, TargetType::Library);
    assert!(dev.mast.mast_forest().debug_info().num_asm_ops() > 0);

    let release = context
        .assemble_library_package(&manifest_path, Some("release"))
        .expect("failed to assemble under release profile");
    assert_eq!(release.mast.mast_forest().debug_info().num_asm_ops(), 0);
}

#[test]
fn builds_executable_target_from_shared_source_tree() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    write_file(
        &manifest_path,
        r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "lib.masm"

[[bin]]
name = "primary"
path = "main.masm"

[[bin]]
name = "alternate"
path = "main2.masm"
"#,
    );
    write_file(
        &tempdir.path().join("lib.masm"),
        r#"pub proc helper
    push.1
end
"#,
    );
    write_file(
        &tempdir.path().join("shared.masm"),
        r#"pub proc helper
    push.2
end
"#,
    );
    write_file(
        &tempdir.path().join("main.masm"),
        r#"use $exec::lib
use $exec::shared

begin
    exec.lib::helper
    exec.shared::helper
end
"#,
    );
    write_file(
        &tempdir.path().join("main2.masm"),
        r#"begin
    push.9
end
"#,
    );

    let mut context = TestContext::new();
    let package = context
        .assemble_executable_package(&manifest_path, Some("primary"), None)
        .expect("executable build should succeed");

    assert_eq!(&package.name, "app:primary");
    assert_eq!(package.kind, TargetType::Executable);
    assert!(package.is_program());
}

#[test]
fn omitted_path_targets_require_explicit_sources() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    write_file(
        &manifest_path,
        r#"[package]
name = "generated"
version = "1.0.0"

[lib]
"#,
    );

    let mut context = TestContext::new();
    let error = context
        .assemble_library_package(&manifest_path, None)
        .expect_err("assembly without sources should fail");
    assert!(error.to_string().contains("assemble_with_sources"));

    let root = Module::parse(
        "generated::temp",
        ModuleKind::Library,
        source_file!(
            context,
            r#"pub proc helper
    push.1
end
"#
        ),
        context.source_manager(),
    )
    .unwrap();

    let mut project_assembler = context.project_assembler_for_path(&manifest_path).unwrap();
    let package = project_assembler
        .assemble_with_sources(
            ProjectTargetSelector::Library,
            "dev",
            ProjectSourceInputs { root, support: Default::default() },
        )
        .expect("assembly with sources should succeed");
    assert_eq!(&package.name, "generated");
    assert_eq!(package.kind, TargetType::Library);
    assert!(PackageBuildProvenance::from_package(&package).unwrap().is_none());
}

#[test]
fn builds_kernel_package_and_supports_kernel_conversion() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    write_file(
        &manifest_path,
        r#"[package]
name = "kernel-pkg"
version = "1.0.0"

[lib]
kind = "kernel"
path = "kernel.masm"
"#,
    );
    write_file(
        &tempdir.path().join("kernel.masm"),
        r#"pub proc foo
    caller
end
"#,
    );

    let mut registry = TestRegistry::default();
    let package = Assembler::default()
        .for_project_at_path(&manifest_path, &mut registry)
        .unwrap()
        .assemble(ProjectTargetSelector::Library, "dev")
        .expect("kernel build should succeed");

    assert_eq!(package.kind, TargetType::Kernel);
    assert!(package.try_into_kernel_library().is_ok());
}

#[test]
fn assembles_mixed_dependencies_and_inherits_static_runtime_deps() {
    let tempdir = TempDir::new().unwrap();
    let mut context = TestContext::new();

    let runtime =
        context.assemble_library_package_with_export("runtime", "1.0.0", "deps::runtime::leaf", []);
    let runtime_digest = runtime.digest();
    context.registry_mut().add_package(runtime.into());

    let regdep =
        context.assemble_library_package_with_export("regdep", "1.0.0", "deps::regdep::leaf", []);
    let regdep_digest = regdep.digest();
    context.registry_mut().add_package(regdep.into());

    let predep =
        context.assemble_library_package_with_export("predep", "1.0.0", "deps::predep::leaf", []);
    let predep_path = tempdir.path().join("predep.masp");
    predep.write_to_file(&predep_path).unwrap();

    let pathdep_dir = tempdir.path().join("pathdep");
    write_file(
        &pathdep_dir.join("miden-project.toml"),
        r#"[package]
name = "pathdep"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::pathdep"

[dependencies]
runtime = "=1.0.0"
"#,
    );
    write_file(
        &pathdep_dir.join("lib.masm"),
        r#"use ::deps::runtime

pub proc call_runtime
    exec.runtime::leaf
end
"#,
    );

    let gitdep_repo = tempdir.path().join("gitdep");
    write_file(
        &gitdep_repo.join("miden-project.toml"),
        r#"[package]
name = "gitdep"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::gitdep"
"#,
    );
    write_file(
        &gitdep_repo.join("lib.masm"),
        r#"pub proc leaf
    push.7
end
"#,
    );
    run_git(&gitdep_repo, &["init", "-b", "main"]);
    run_git(&gitdep_repo, &["config", "user.email", "test@example.com"]);
    run_git(&gitdep_repo, &["config", "user.name", "Test"]);
    run_git(&gitdep_repo, &["config", "commit.gpgsign", "false"]);
    run_git(&gitdep_repo, &["add", "."]);
    run_git(&gitdep_repo, &["commit", "-m", "init"]);

    let root_dir = tempdir.path().join("root");
    write_file(
        &root_dir.join("miden-project.toml"),
        &format!(
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
pathdep = {{ path = "../pathdep", linkage = "static" }}
gitdep = {{ git = "{}", branch = "main" }}
regdep = "=1.0.0"
predep = {{ path = "../predep.masp" }}
"#,
            gitdep_repo.display()
        ),
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"use ::deps::pathdep
use ::deps::gitdep

pub proc entry
    exec.pathdep::call_runtime
    exec.gitdep::leaf
end
"#,
    );

    let package = context
        .assemble_library_package(root_dir.join("miden-project.toml"), Some("dev"))
        .expect("mixed dependency build should succeed");

    let dependency_names = package
        .manifest
        .dependencies()
        .map(|dependency| dependency.name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(dependency_names, vec!["gitdep", "predep", "regdep", "runtime"]);
    assert_eq!(
        context.registry().loaded_packages(),
        vec![
            format!("runtime@1.0.0#{runtime_digest}"),
            format!("regdep@1.0.0#{regdep_digest}")
        ]
    );
    assert!(!dependency_names.iter().any(|name| name == "pathdep"));
    assert_eq!(package.kind, TargetType::Library);
    assert_eq!(
        runtime_digest,
        package.manifest.dependencies().find(|d| &d.name == "runtime").unwrap().digest
    );
    assert_eq!(
        package
            .manifest
            .dependencies()
            .find(|d| &d.name == "runtime")
            .unwrap()
            .version
            .to_string(),
        "1.0.0"
    );
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("pathdep"), &"1.0.0".parse().unwrap())
    );
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("gitdep"), &"1.0.0".parse().unwrap())
    );
}

#[test]
fn runtime_dependency_conflict_requires_matching_digest() {
    let tempdir = TempDir::new().unwrap();
    let mut context = TestContext::new();

    let runtime_a_digest = hash_string_to_word("runtime-a");
    let runtime_b_digest = hash_string_to_word("runtime-b");

    let depa = context.assemble_library_package_with_export(
        "depa",
        "1.0.0",
        "deps::depa::leaf",
        [("runtime", "1.0.0", TargetType::Library, runtime_a_digest)],
    );
    let depa_path = tempdir.path().join("depa.masp");
    depa.write_to_file(&depa_path).unwrap();

    let depb = context.assemble_library_package_with_export(
        "depb",
        "1.0.0",
        "deps::depb::leaf",
        [("runtime", "1.0.0", TargetType::Library, runtime_b_digest)],
    );
    let depb_path = tempdir.path().join("depb.masp");
    depb.write_to_file(&depb_path).unwrap();

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
depa = { path = "../depa.masp" }
depb = { path = "../depb.masp" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::deps::depa::leaf
    exec.::deps::depb::leaf
end
"#,
    );

    let error = context
        .assemble_library_package(&root_manifest, None)
        .expect_err("runtime dependency digest conflicts should fail");
    assert!(error.to_string().contains("conflicting runtime dependency 'runtime'"));
}

#[test]
fn statically_linked_dynamic_dependencies_propagate_multiple_levels() {
    let tempdir = TempDir::new().unwrap();
    let mut context = TestContext::new();

    let runtime = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
        "runtime",
        "1.0.0",
        "deps::runtime::leaf",
        [],
    ));
    let runtime_digest = runtime.digest();
    context.registry_mut().add_package(runtime);

    let mid_dir = tempdir.path().join("mid");
    write_file(
        &mid_dir.join("miden-project.toml"),
        r#"[package]
name = "mid"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::mid"

[dependencies]
runtime = "=1.0.0"
"#,
    );
    write_file(
        &mid_dir.join("lib.masm"),
        r#"use ::deps::runtime

pub proc call_runtime
    exec.runtime::leaf
end
"#,
    );

    let top_dir = tempdir.path().join("top");
    write_file(
        &top_dir.join("miden-project.toml"),
        r#"[package]
name = "top"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::top"

[dependencies]
mid = { path = "../mid", linkage = "static" }
"#,
    );
    write_file(
        &top_dir.join("lib.masm"),
        r#"use ::deps::mid

pub proc call_mid
    exec.mid::call_runtime
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
top = { path = "../top", linkage = "static" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::deps::top::call_mid
end
"#,
    );

    let package = context
        .assemble_library_package(&root_manifest, None)
        .expect("multi-level static propagation should succeed");

    assert_eq!(
        package
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>(),
        vec![format!("runtime@1.0.0#{runtime_digest}")]
    );
}

fn write_file(path: &FsPath, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn run_git(dir: &FsPath, args: &[&str]) {
    let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "git {} failed in '{}': {}",
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn workspace_dependency_stays_on_the_workspace_member_version() {
    let tempdir = TempDir::new().unwrap();
    let root_dir = tempdir.path().join("workspace-dep");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(root_dir.join("dep")).unwrap();
    fs::create_dir_all(root_dir.join("app")).unwrap();

    write_file(
        &root_dir.join("miden-project.toml"),
        r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }
"#,
    );
    let dep_dir = root_dir.join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "0.2.0"

[lib]
path = "mod.masm"

"#,
    );
    write_file(&dep_dir.join("mod.masm"), r#"pub proc foo add end"#);

    let app_dir = root_dir.join("app");
    let app_manifest = app_dir.join("miden-project.toml");
    write_file(
        &app_manifest,
        r#"[package]
name = "app"
version = "0.1.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
    );
    write_file(&app_dir.join("mod.masm"), r#"pub proc bar push.1 push.2 exec.::dep::foo end"#);

    let mut context = TestContext::new();

    // Add a pre-existing version of 'dep' that does not match the effective version requirement
    let dep010 = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
        "dep",
        "0.1.0",
        "dep::foo",
        [],
    ));
    context.registry_mut().add_package(dep010.clone());

    let package = context
        .assemble_library_package(&app_manifest, None)
        .expect("failed to assemble 'app'");

    assert_eq!(
        package
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>(),
        vec![format!("dep@0.2.0#{}", dep010.digest())]
    );
}

#[test]
fn path_dependency_is_published_and_reused_when_sources_match() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    write_file(
        &dep_dir.join("lib.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let first = context
        .assemble_library_package(&root_manifest, None)
        .expect("first build should succeed");
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
    );
    assert!(context.registry().loaded_packages().is_empty());

    let expected_dependency = first
        .manifest
        .dependencies()
        .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
        .collect::<Vec<_>>();
    context.registry().clear_loaded_packages();

    let second = context
        .assemble_library_package(&root_manifest, None)
        .expect("second build should reuse canonical dependency");

    let dep_record = context
        .registry()
        .get_by_semver(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        .expect("dependency should be registered");
    assert_eq!(
        context.registry().loaded_packages(),
        vec![format!("dep@{}", dep_record.version())]
    );
    assert_eq!(
        second
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>(),
        expected_dependency
    );
}

#[test]
fn root_package_is_not_auto_published_when_assembling_source_dependencies() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    write_file(
        &dep_dir.join("lib.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let package = context
        .assemble_library_package(&root_manifest, None)
        .expect("assembly with a source dependency should succeed");

    assert_eq!(&package.name, "root");
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
    );
    assert!(
        !context
            .registry()
            .is_semver_available(&PackageId::from("root"), &"1.0.0".parse().unwrap())
    );
}

#[test]
fn path_dependency_source_changes_require_semver_bump() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    let dep_source = dep_dir.join("lib.masm");
    write_file(
        &dep_source,
        r#"pub proc foo
    push.1
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    context
        .assemble_library_package(&root_manifest, None)
        .expect("initial build should succeed");

    write_file(
        &dep_source,
        r#"pub proc foo
    push.2
end
"#,
    );

    let error = context
        .assemble_library_package(&root_manifest, None)
        .expect_err("changed dependency sources should require a semver bump");
    assert!(error.to_string().contains("bump the semantic version"));
}

#[test]
fn transitive_path_dependency_source_changes_require_semver_bump() {
    let tempdir = TempDir::new().unwrap();
    let leaf_dir = tempdir.path().join("leaf");
    write_file(
        &leaf_dir.join("miden-project.toml"),
        r#"[package]
name = "leaf"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::leaf"
"#,
    );
    let leaf_source = leaf_dir.join("lib.masm");
    write_file(
        &leaf_source,
        r#"pub proc foo
    push.1
end
"#,
    );

    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::dep"

[dependencies]
leaf = { path = "../leaf", linkage = "static" }
"#,
    );
    write_file(
        &dep_dir.join("lib.masm"),
        r#"use ::deps::leaf

pub proc call_leaf
    exec.leaf::foo
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::deps::dep::call_leaf
end
"#,
    );

    let mut context = TestContext::new();
    context
        .assemble_library_package(&root_manifest, None)
        .expect("initial build should succeed");

    write_file(
        &leaf_source,
        r#"pub proc foo
    push.2
end
"#,
    );

    let error = context
        .assemble_library_package(&root_manifest, None)
        .expect_err("changed transitive dependency sources should require a semver bump");
    assert!(error.to_string().contains("package 'dep' version '1.0.0'"));
    assert!(error.to_string().contains("different source provenance"));
}

#[test]
fn source_dependency_profile_changes_require_semver_bump() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    write_file(
        &dep_dir.join("lib.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    context
        .assemble_library_package(&root_manifest, Some("dev"))
        .expect("initial dev build should succeed");
    context.registry().clear_loaded_packages();

    let error = context
        .assemble_library_package(&root_manifest, Some("release"))
        .expect_err("changing package-shaping profile inputs should require a semver bump");
    assert!(error.to_string().contains("package 'dep' version '1.0.0'"));
    assert!(error.to_string().contains("different source provenance"));
    assert!(error.to_string().contains("trim_paths=true"));
}

#[test]
fn source_dependency_rebuilds_when_canonical_artifact_is_unreadable() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    write_file(
        &dep_dir.join("lib.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    context
        .assemble_library_package(&root_manifest, None)
        .expect("initial build should succeed");

    let dep_record = context
        .registry()
        .get_by_semver(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        .expect("dependency should be registered");
    let dep_version = dep_record.version().clone();
    let removed = context.registry_mut().remove_package(&PackageId::from("dep"), &dep_version);
    assert!(removed.is_some(), "expected indexed dependency artifact to exist");
    context.registry().clear_loaded_packages();

    context.assemble_library_package(&root_manifest, None).expect(
        "source dependency should rebuild from source when the canonical artifact is unreadable",
    );
    assert_eq!(context.registry().loaded_packages(), vec![format!("dep@{}", dep_version)]);
}

#[test]
fn workspace_manifest_changes_without_effect_allow_reuse_of_member_packages() {
    let tempdir = TempDir::new().unwrap();
    let workspace_dir = tempdir.path().join("workspace");
    let dep_dir = workspace_dir.join("dep");
    let app_dir = workspace_dir.join("app");
    fs::create_dir_all(&dep_dir).unwrap();
    fs::create_dir_all(&app_dir).unwrap();

    let workspace_manifest = workspace_dir.join("miden-project.toml");
    write_file(
        &workspace_manifest,
        r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }
"#,
    );
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "mod.masm"
"#,
    );
    write_file(
        &dep_dir.join("mod.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let app_manifest = app_dir.join("miden-project.toml");
    write_file(
        &app_manifest,
        r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
    );
    write_file(
        &app_dir.join("mod.masm"),
        r#"pub proc bar
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let first = context
        .assemble_library_package(&app_manifest, None)
        .expect("initial workspace build should succeed");
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
    );

    let expected_dependency = first
        .manifest
        .dependencies()
        .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
        .collect::<Vec<_>>();
    context.registry().clear_loaded_packages();

    write_file(
        &workspace_manifest,
        r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }

# comment changes provenance hashing for workspace member builds
"#,
    );

    let second = context
        .assemble_library_package(&app_manifest, None)
        .expect("workspace manifest comment changes should still allow reuse");

    let dep_record = context
        .registry()
        .get_by_semver(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        .expect("workspace dependency should be registered");
    assert_eq!(
        context.registry().loaded_packages(),
        vec![format!("dep@{}", dep_record.version())]
    );
    assert_eq!(second.digest(), first.digest());
    assert_eq!(
        second
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>(),
        expected_dependency
    );
}

#[test]
fn git_dependency_reuses_canonical_revision_and_rejects_new_commit_without_semver_bump() {
    let tempdir = TempDir::new().unwrap();
    let gitdep_repo = tempdir.path().join("gitdep");
    write_file(
        &gitdep_repo.join("miden-project.toml"),
        r#"[package]
name = "gitdep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
    );
    let git_source = gitdep_repo.join("lib.masm");
    write_file(
        &git_source,
        r#"pub proc leaf
    push.7
end
"#,
    );
    run_git(&gitdep_repo, &["init", "-b", "main"]);
    run_git(&gitdep_repo, &["config", "user.email", "test@example.com"]);
    run_git(&gitdep_repo, &["config", "user.name", "Test"]);
    run_git(&gitdep_repo, &["config", "commit.gpgsign", "false"]);
    run_git(&gitdep_repo, &["add", "."]);
    run_git(&gitdep_repo, &["commit", "-m", "init"]);

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        &format!(
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
gitdep = {{ git = "{}", branch = "main" }}
"#,
            gitdep_repo.display()
        ),
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::gitdep::leaf
end
"#,
    );

    let mut context = TestContext::new();
    context
        .assemble_library_package(&root_manifest, None)
        .expect("initial build should succeed");
    context.registry().clear_loaded_packages();

    context
        .assemble_library_package(&root_manifest, None)
        .expect("matching revision should reuse canonical dependency");
    let dep_record = context
        .registry()
        .get_by_semver(&PackageId::from("gitdep"), &"1.0.0".parse().unwrap())
        .expect("git dependency should be registered");
    assert_eq!(
        context.registry().loaded_packages(),
        vec![format!("gitdep@{}", dep_record.version())]
    );

    write_file(
        &git_source,
        r#"pub proc leaf
    push.8
end
"#,
    );
    run_git(&gitdep_repo, &["add", "."]);
    run_git(&gitdep_repo, &["commit", "-m", "change"]);

    let error = context
        .assemble_library_package(&root_manifest, None)
        .expect_err("new git revision should require a semver bump");
    assert!(error.to_string().contains("bump the semantic version"));
}

#[test]
fn omitted_path_dependency_requires_canonical_registry_entry() {
    let tempdir = TempDir::new().unwrap();
    let dep_dir = tempdir.path().join("dep");
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version = "1.0.0"

[lib]
"#,
    );

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let missing = context
        .assemble_library_package(&root_manifest, None)
        .expect_err("omitted-path dependency should require a canonical registry entry");
    assert!(missing.to_string().contains("was not found in the package registry"));

    let dep = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
        "dep",
        "1.0.0",
        "dep::foo",
        [],
    ));
    let dep_digest = dep.digest();
    context.registry_mut().add_package(dep);
    context.registry().clear_loaded_packages();

    let package = context
        .assemble_library_package(&root_manifest, None)
        .expect("canonical registry entry should satisfy omitted-path dependency");
    assert_eq!(
        package
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>(),
        vec![format!("dep@1.0.0#{dep_digest}")]
    );
}

#[test]
fn workspace_member_source_dependencies_preserve_workspace_inheritance() {
    let tempdir = TempDir::new().unwrap();
    let workspace_dir = tempdir.path().join("workspace");
    let dep_dir = workspace_dir.join("dep");
    let app_dir = workspace_dir.join("app");
    fs::create_dir_all(&dep_dir).unwrap();
    fs::create_dir_all(&app_dir).unwrap();

    write_file(
        &workspace_dir.join("miden-project.toml"),
        r#"[workspace]
members = ["dep", "app"]

[workspace.package]
version = "1.0.0"

[workspace.dependencies]
dep = { path = "dep" }
"#,
    );
    write_file(
        &dep_dir.join("miden-project.toml"),
        r#"[package]
name = "dep"
version.workspace = true

[lib]
path = "mod.masm"
"#,
    );
    write_file(
        &dep_dir.join("mod.masm"),
        r#"pub proc foo
    push.1
end
"#,
    );

    let app_manifest = app_dir.join("miden-project.toml");
    write_file(
        &app_manifest,
        r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
    );
    write_file(
        &app_dir.join("mod.masm"),
        r#"pub proc bar
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let package = context
        .assemble_library_package(&app_manifest, None)
        .expect("workspace member dependency should assemble with inherited workspace config");
    assert!(
        context
            .registry()
            .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
    );

    let dependencies = package.manifest.dependencies().collect::<Vec<_>>();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].name, PackageId::from("dep"));
    assert_eq!(dependencies[0].version.to_string(), "1.0.0");
}

#[test]
fn executable_packages_preserve_kernel_when_converted_back_to_program() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_kernel_program_project(tempdir.path());

    let mut context = TestContext::new();
    let kernel_package = context
        .assemble_library_package(&manifest_path, None)
        .expect("kernel package build should succeed");
    let expected_kernel = kernel_package
        .try_into_kernel_library()
        .expect("kernel package should round-trip as a kernel library")
        .kernel()
        .clone();
    let package = context
        .assemble_executable_package(&manifest_path, Some("main"), None)
        .expect("executable package build should succeed");
    let kernel_dependency = package
        .manifest
        .dependencies()
        .find(|dependency| dependency.kind == TargetType::Kernel)
        .cloned()
        .expect("executable package should record the linked kernel runtime dependency");
    let embedded_kernel_package = package
        .sections
        .iter()
        .find(|section| section.id == SectionId::KERNEL)
        .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
        .expect("executable package should embed the linked kernel package");
    assert_eq!(embedded_kernel_package.kind, TargetType::Kernel);
    assert_eq!(embedded_kernel_package.name, kernel_dependency.name);
    assert_eq!(embedded_kernel_package.version, kernel_dependency.version);
    assert_eq!(embedded_kernel_package.digest(), kernel_dependency.digest);

    let round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip");
    let round_tripped_program = round_tripped_package
        .try_into_program()
        .expect("executable package conversion should preserve kernel information");

    assert_eq!(round_tripped_program.kernel(), &expected_kernel);
}

#[test]
fn executable_packages_preserve_transitive_kernel_when_converted_back_to_program() {
    let tempdir = TempDir::new().unwrap();
    let (root_manifest, kernel_manifest) = write_transitive_kernel_program_project(tempdir.path());

    let mut context = TestContext::new();
    let kernel_package = context
        .assemble_library_package(&kernel_manifest, None)
        .expect("kernel package build should succeed");
    let expected_kernel = kernel_package
        .try_into_kernel_library()
        .expect("kernel package should round-trip as a kernel library")
        .kernel()
        .clone();
    let package = context
        .assemble_executable_package(&root_manifest, Some("main"), None)
        .expect("executable package build should succeed");
    let kernel_dependency = package
        .manifest
        .dependencies()
        .find(|dependency| dependency.kind == TargetType::Kernel)
        .cloned()
        .expect("executable package should record the transitive kernel runtime dependency");
    let embedded_kernel_package = package
        .sections
        .iter()
        .find(|section| section.id == SectionId::KERNEL)
        .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
        .expect("executable package should embed the transitive kernel package");
    assert_eq!(embedded_kernel_package.kind, TargetType::Kernel);
    assert_eq!(embedded_kernel_package.name, kernel_dependency.name);
    assert_eq!(embedded_kernel_package.version, kernel_dependency.version);
    assert_eq!(embedded_kernel_package.digest(), kernel_dependency.digest);

    let round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip");
    let round_tripped_program = round_tripped_package
        .try_into_program()
        .expect("executable package conversion should preserve transitive kernel information");

    assert_eq!(round_tripped_program.kernel(), &expected_kernel);
}

#[test]
fn library_packages_with_transitive_kernels_do_not_embed_kernel_sections() {
    let tempdir = TempDir::new().unwrap();
    write_transitive_kernel_program_project(tempdir.path());
    let mid_manifest = tempdir.path().join("mid").join("miden-project.toml");

    let mut context = TestContext::new();
    let package = context
        .assemble_library_package(&mid_manifest, None)
        .expect("library package build should succeed");

    assert!(
        package
            .manifest
            .dependencies()
            .any(|dependency| dependency.kind == TargetType::Kernel)
    );
    assert!(!package.sections.iter().any(|section| section.id == SectionId::KERNEL));
}

#[test]
fn preassembled_libraries_prefer_store_kernel_over_embedded_copy() {
    let tempdir = TempDir::new().unwrap();
    let (_, kernel_manifest) = write_transitive_kernel_program_project(tempdir.path());
    let mid_manifest = tempdir.path().join("mid").join("miden-project.toml");
    let mid_package_path = tempdir.path().join("mid-embedded.masp");

    let mut build_context = TestContext::new();
    let kernel_package = build_context
        .assemble_library_package(&kernel_manifest, None)
        .expect("kernel package build should succeed");
    let expected_kernel = kernel_package
        .try_into_kernel_library()
        .expect("kernel package should round-trip as a kernel library")
        .kernel()
        .clone();
    let mut mid_package = MastPackage::read_from_bytes(
        &build_context
            .assemble_library_package(&mid_manifest, None)
            .expect("mid package build should succeed")
            .to_bytes(),
    )
    .expect("mid package should deserialize");
    let mut mismatched_kernel_package = MastPackage::read_from_bytes(&kernel_package.to_bytes())
        .expect("kernel should deserialize");
    mismatched_kernel_package.version = "2.0.0".parse().unwrap();
    mid_package
        .sections
        .push(Section::new(SectionId::KERNEL, mismatched_kernel_package.to_bytes()));
    mid_package.write_to_file(&mid_package_path).unwrap();

    let root_manifest =
        write_preassembled_kernel_executable_project(tempdir.path(), &mid_package_path);
    let mut context = TestContext::new();
    context.registry_mut().add_package(kernel_package.clone());

    let package = context
        .assemble_executable_package(&root_manifest, Some("main"), None)
        .expect("executable package build should prefer the store kernel");
    let embedded_kernel_package = package
        .sections
        .iter()
        .find(|section| section.id == SectionId::KERNEL)
        .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
        .expect("executable package should embed the store-provided kernel package");
    assert_eq!(embedded_kernel_package.version, kernel_package.version);
    assert_eq!(embedded_kernel_package.digest(), kernel_package.digest());

    let round_tripped_program = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip")
        .try_into_program()
        .expect("program reconstruction should use the store-provided kernel");
    assert_eq!(round_tripped_program.kernel(), &expected_kernel);
}

#[test]
fn preassembled_libraries_fall_back_to_embedded_kernel_when_store_is_missing() {
    let tempdir = TempDir::new().unwrap();
    let (_, kernel_manifest) = write_transitive_kernel_program_project(tempdir.path());
    let mid_manifest = tempdir.path().join("mid").join("miden-project.toml");
    let mid_package_path = tempdir.path().join("mid-embedded.masp");

    let mut build_context = TestContext::new();
    let kernel_package = build_context
        .assemble_library_package(&kernel_manifest, None)
        .expect("kernel package build should succeed");
    let expected_kernel = kernel_package
        .try_into_kernel_library()
        .expect("kernel package should round-trip as a kernel library")
        .kernel()
        .clone();
    let mut mid_package = MastPackage::read_from_bytes(
        &build_context
            .assemble_library_package(&mid_manifest, None)
            .expect("mid package build should succeed")
            .to_bytes(),
    )
    .expect("mid package should deserialize");
    mid_package
        .sections
        .push(Section::new(SectionId::KERNEL, kernel_package.to_bytes()));
    mid_package.write_to_file(&mid_package_path).unwrap();

    let root_manifest =
        write_preassembled_kernel_executable_project(tempdir.path(), &mid_package_path);
    let mut context = TestContext::new();
    let package = context
        .assemble_executable_package(&root_manifest, Some("main"), None)
        .expect("executable package build should fall back to the embedded kernel");
    let embedded_kernel_package = package
        .sections
        .iter()
        .find(|section| section.id == SectionId::KERNEL)
        .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
        .expect("executable package should embed the fallback kernel package");
    assert_eq!(embedded_kernel_package.version, kernel_package.version);
    assert_eq!(embedded_kernel_package.digest(), kernel_package.digest());

    let round_tripped_program = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip")
        .try_into_program()
        .expect("program reconstruction should use the embedded fallback kernel");
    assert_eq!(round_tripped_program.kernel(), &expected_kernel);
}

#[test]
fn preassembled_libraries_fall_back_to_embedded_kernel_when_store_artifact_is_unreadable() {
    let tempdir = TempDir::new().unwrap();
    let (_, kernel_manifest) = write_transitive_kernel_program_project(tempdir.path());
    let mid_manifest = tempdir.path().join("mid").join("miden-project.toml");
    let mid_package_path = tempdir.path().join("mid-embedded.masp");

    let mut build_context = TestContext::new();
    let kernel_package = build_context
        .assemble_library_package(&kernel_manifest, None)
        .expect("kernel package build should succeed");
    let expected_kernel = kernel_package
        .try_into_kernel_library()
        .expect("kernel package should round-trip as a kernel library")
        .kernel()
        .clone();
    let kernel_version = miden_package_registry::Version::new(
        kernel_package.version.clone(),
        kernel_package.digest(),
    );
    let mut mid_package = MastPackage::read_from_bytes(
        &build_context
            .assemble_library_package(&mid_manifest, None)
            .expect("mid package build should succeed")
            .to_bytes(),
    )
    .expect("mid package should deserialize");
    mid_package
        .sections
        .push(Section::new(SectionId::KERNEL, kernel_package.to_bytes()));
    mid_package.write_to_file(&mid_package_path).unwrap();

    let root_manifest =
        write_preassembled_kernel_executable_project(tempdir.path(), &mid_package_path);
    let mut context = TestContext::new();
    context.registry_mut().add_package(kernel_package.clone());
    let removed = context
        .registry_mut()
        .remove_package(&PackageId::from("kernelpkg"), &kernel_version);
    assert!(removed.is_some(), "expected indexed kernel artifact to exist");
    context.registry().clear_loaded_packages();

    let package = context
        .assemble_executable_package(&root_manifest, Some("main"), None)
        .expect("embedded kernel should be used when the indexed artifact is unreadable");
    let embedded_kernel_package = package
        .sections
        .iter()
        .find(|section| section.id == SectionId::KERNEL)
        .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
        .expect("executable package should embed the fallback kernel package");
    assert_eq!(embedded_kernel_package.version, kernel_package.version);
    assert_eq!(embedded_kernel_package.digest(), kernel_package.digest());
    assert_eq!(
        context.registry().loaded_packages(),
        vec![format!("kernelpkg@{}", kernel_version)]
    );

    let round_tripped_program = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip")
        .try_into_program()
        .expect("program reconstruction should use the embedded fallback kernel");
    assert_eq!(round_tripped_program.kernel(), &expected_kernel);
}

#[test]
fn preassembled_libraries_without_store_or_embedded_kernel_leave_runtime_kernel_to_caller() {
    let tempdir = TempDir::new().unwrap();
    write_transitive_kernel_program_project(tempdir.path());
    let mid_manifest = tempdir.path().join("mid").join("miden-project.toml");
    let mid_package_path = tempdir.path().join("mid.masp");

    let mut build_context = TestContext::new();
    build_context
        .assemble_library_package(&mid_manifest, None)
        .expect("mid package build should succeed")
        .write_to_file(&mid_package_path)
        .unwrap();

    let root_manifest =
        write_preassembled_kernel_executable_project(tempdir.path(), &mid_package_path);
    let mut context = TestContext::new();
    let package = context
        .assemble_executable_package(&root_manifest, Some("main"), None)
        .expect("executable package build should succeed without an available kernel artifact");

    assert!(
        package
            .manifest
            .dependencies()
            .any(|dependency| dependency.kind == TargetType::Kernel)
    );
    assert!(!package.sections.iter().any(|section| section.id == SectionId::KERNEL));

    let round_tripped_program = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip")
        .try_into_program()
        .expect("packages without a recoverable kernel should still convert to a program");
    assert!(round_tripped_program.kernel().is_empty());
}

#[test]
fn embedded_kernel_package_must_match_runtime_dependency() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_kernel_program_project(tempdir.path());

    let mut context = TestContext::new();
    let package = context
        .assemble_executable_package(&manifest_path, Some("main"), None)
        .expect("executable package build should succeed");
    let mut round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip");
    let kernel_dependency = round_tripped_package
        .manifest
        .dependencies()
        .find(|dependency| dependency.kind == TargetType::Kernel)
        .cloned()
        .expect("executable package should record a kernel dependency");
    let embedded_kernel_section = round_tripped_package
        .sections
        .iter_mut()
        .find(|section| section.id == SectionId::KERNEL)
        .expect("executable package should embed a kernel package");
    let mut embedded_kernel_package =
        MastPackage::read_from_bytes(embedded_kernel_section.data.as_ref())
            .expect("embedded kernel package should deserialize");
    embedded_kernel_package.version = "2.0.0".parse().unwrap();
    embedded_kernel_section.data = embedded_kernel_package.to_bytes().into();

    let error = round_tripped_package
        .try_into_program()
        .expect_err("mismatched embedded kernel metadata should be rejected");
    let kernel_name = kernel_dependency.name.to_string();
    assert!(error.to_string().contains("does not match the embedded kernel package"));
    assert!(error.to_string().contains(&kernel_name));
}

#[test]
fn executable_packages_without_embedded_kernel_section_fall_back_to_empty_kernel() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_kernel_program_project(tempdir.path());

    let mut context = TestContext::new();
    let package = context
        .assemble_executable_package(&manifest_path, Some("main"), None)
        .expect("executable package build should succeed");
    let mut round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
        .expect("serialized executable package should round-trip");
    round_tripped_package.sections.retain(|section| section.id != SectionId::KERNEL);

    let round_tripped_program = round_tripped_package
        .try_into_program()
        .expect("packages without embedded kernels should still convert to a program");

    assert!(round_tripped_program.kernel().is_empty());
}

#[test]
fn preassembled_dependency_must_match_graph_selected_artifact() {
    let tempdir = TempDir::new().unwrap();
    let dep_package_path = tempdir.path().join("dep.masp");
    let dep_v1 =
        MastPackage::generate("dep".into(), "1.0.0".parse().unwrap(), TargetType::Library, []);
    dep_v1.write_to_file(&dep_package_path).unwrap();

    let root_dir = tempdir.path().join("root");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep.masp" }
"#,
    );
    write_file(
        &root_dir.join("lib.masm"),
        r#"pub proc entry
    exec.::dep::foo
end
"#,
    );

    let mut context = TestContext::new();
    let mut project_assembler = context.project_assembler_for_path(&root_manifest).unwrap();
    let dep_v2 =
        MastPackage::generate("dep".into(), "1.0.1".parse().unwrap(), TargetType::Library, []);
    dep_v2.write_to_file(&dep_package_path).unwrap();

    let error = project_assembler
        .assemble(ProjectTargetSelector::Library, "dev")
        .expect_err("mutating the preassembled artifact after graph construction should fail");
    assert!(error.to_string().contains("no longer matches the dependency graph selection"));
}

fn write_kernel_program_project(root: &FsPath) -> PathBuf {
    let manifest_path = root.join("miden-project.toml");
    write_file(
        &manifest_path,
        r#"[package]
name = "app"
version = "1.0.0"

[lib]
kind = "kernel"
path = "kernel.masm"

[[bin]]
name = "main"
path = "main.masm"
"#,
    );
    write_file(
        &root.join("kernel.masm"),
        r#"pub proc foo
    caller
end
"#,
    );
    write_file(
        &root.join("main.masm"),
        r#"begin
    syscall.foo
end
"#,
    );

    manifest_path
}

fn write_transitive_kernel_program_project(root: &FsPath) -> (PathBuf, PathBuf) {
    let kernel_dir = root.join("kernel");
    let kernel_manifest = kernel_dir.join("miden-project.toml");
    write_file(
        &kernel_manifest,
        r#"[package]
name = "kernelpkg"
version = "1.0.0"

[lib]
kind = "kernel"
path = "kernel.masm"
"#,
    );
    write_file(
        &kernel_dir.join("kernel.masm"),
        r#"pub proc foo
    caller
end
"#,
    );

    let mid_dir = root.join("mid");
    write_file(
        &mid_dir.join("miden-project.toml"),
        r#"[package]
name = "mid"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::mid"

[dependencies]
kernelpkg = { path = "../kernel" }
"#,
    );
    write_file(
        &mid_dir.join("lib.masm"),
        r#"pub proc call_kernel
    syscall.foo
end
"#,
    );

    let root_dir = root.join("app");
    let root_manifest = root_dir.join("miden-project.toml");
    write_file(
        &root_manifest,
        r#"[package]
name = "app"
version = "1.0.0"

[[bin]]
name = "main"
path = "main.masm"

[dependencies]
mid = { path = "../mid", linkage = "static" }
"#,
    );
    write_file(
        &root_dir.join("main.masm"),
        r#"begin
    exec.::deps::mid::call_kernel
end
"#,
    );

    (root_manifest, kernel_manifest)
}

fn write_preassembled_kernel_executable_project(
    root: &FsPath,
    dependency_package_path: &FsPath,
) -> PathBuf {
    let manifest_path = root.join("preassembled-app").join("miden-project.toml");
    write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "app"
version = "1.0.0"

[[bin]]
name = "main"
path = "main.masm"

[dependencies]
mid = {{ path = "{}", linkage = "static" }}
"#,
            dependency_package_path.display()
        ),
    );
    write_file(
        &manifest_path.parent().unwrap().join("main.masm"),
        r#"begin
    exec.::deps::mid::call_kernel
end
"#,
    );

    manifest_path
}
