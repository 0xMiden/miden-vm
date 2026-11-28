//! Fuzz target for loading Miden project manifests from a filesystem tree.
//!
//! This target exercises `Package::load` and `Project::load`, including workspace-member loading
//! and workspace inheritance. It does not assemble MASM sources.
//!
//! Run with: cargo +nightly fuzz run project_load --fuzz-dir tools/miden-core-fuzz

#![no_main]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::debuginfo::{DefaultSourceManager, SourceManagerExt};
use miden_project::{Package, Project};

const MAX_MANIFEST_LEN: usize = 40 * 1024;

static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(0);

struct TempProjectTree {
    root: PathBuf,
}

impl TempProjectTree {
    fn new() -> std::io::Result<Self> {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .join(format!("miden-project-load-fuzz-{}-{id}", std::process::id()));

        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;

        Ok(Self { root })
    }

    fn path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(path)
    }
}

impl Drop for TempProjectTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_MANIFEST_LEN {
        return;
    }
    let Ok(manifest) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(tree) = TempProjectTree::new() else {
        return;
    };

    let source_manager = DefaultSourceManager::default();

    match scenario_index(data, 5) {
        0 => load_standalone_package(&tree, &source_manager, manifest),
        1 => load_standalone_project(&tree, &source_manager, manifest),
        2 => load_fuzzed_workspace(&tree, &source_manager, manifest),
        3 => load_inherited_workspace_member(&tree, &source_manager, manifest),
        _ => load_project_reference(&tree, &source_manager, manifest),
    }
});

fn load_standalone_package(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
    manifest: &str,
) {
    let manifest_path = tree.path("standalone/miden-project.toml");
    if write_file(&manifest_path, manifest).is_err() {
        return;
    }

    if let Ok(source) = source_manager.load_file(&manifest_path) {
        let _ = Package::load(source);
    }
}

fn load_standalone_project(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
    manifest: &str,
) {
    let manifest_path = tree.path("standalone/miden-project.toml");
    if write_file(&manifest_path, manifest).is_err() {
        return;
    }

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load(tree.path("standalone"), source_manager);
    } else {
        let _ = Project::load(&manifest_path, source_manager);
    }
}

fn load_fuzzed_workspace(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
    manifest: &str,
) {
    let workspace_manifest = tree.path("fuzzed-workspace/miden-project.toml");
    let workspace_member = tree.path("fuzzed-workspace/app/miden-project.toml");

    if write_file(&workspace_manifest, manifest).is_err()
        || write_file(
            &workspace_member,
            r#"[package]
name = "app"
version = "0.1.0"

[lib]
path = "lib.masm"
"#,
        )
        .is_err()
        || write_file(
            &tree.path("fuzzed-workspace/app/lib.masm"),
            r#"pub proc helper
    push.1
end
"#,
        )
        .is_err()
    {
        return;
    }

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load(tree.path("fuzzed-workspace"), source_manager);
    } else {
        let _ = Project::load(&workspace_manifest, source_manager);
    }
}

fn load_inherited_workspace_member(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
    manifest: &str,
) {
    let member_manifest = write_inherited_workspace(tree, manifest);
    let Ok(member_manifest) = member_manifest else {
        return;
    };

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load(tree.path("inherited-workspace/app"), source_manager);
    } else {
        let _ = Project::load(&member_manifest, source_manager);
    }
    check_inheritance_ground_truth(tree, source_manager);
}

fn load_project_reference(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
    manifest: &str,
) {
    if write_inherited_workspace(tree, manifest).is_err() {
        return;
    }
    let workspace_manifest = tree.path("inherited-workspace/miden-project.toml");

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load_project_reference(
            "app",
            tree.path("inherited-workspace"),
            source_manager,
        );
    } else {
        let _ = Project::load_project_reference("app", &workspace_manifest, source_manager);
    }
}

fn write_inherited_workspace(tree: &TempProjectTree, manifest: &str) -> std::io::Result<PathBuf> {
    let workspace_manifest = tree.path("inherited-workspace/miden-project.toml");
    let member_manifest = tree.path("inherited-workspace/app/miden-project.toml");

    write_file(
        &workspace_manifest,
        r#"[workspace]
members = ["app"]

[workspace.package]
version = "1.0.0"
description = "workspace defaults"

[workspace.dependencies]
shared = { version = "1.0.0" }
"#,
    )?;
    write_file(&member_manifest, manifest)?;
    write_file(
        &tree.path("inherited-workspace/app/lib.masm"),
        r#"pub proc helper
    push.1
end
"#,
    )?;
    // GROUND-TRUTH MEMBER (writer-produced, run-#241 pattern): a fixed manifest that
    // inherits BOTH version and description from the workspace, whose resolved values are
    // known exactly — the inheritance oracle's fixture.
    write_file(
        &tree.path("inherited-workspace/gt/miden-project.toml"),
        r#"[package]
name = "gt-member"
version = { workspace = true }
description = { workspace = true }
"#,
    )?;
    Ok(member_manifest)
}

/// INHERITANCE ORACLE: the ground-truth member declares `{ workspace = true }` for version
/// and description, so the ONLY source of the workspace's known values ("1.0.0",
/// "workspace defaults") in the loaded package is the inheritance path. A regression that
/// drops inheritance, resolves the wrong field, or substitutes a default fails here.
fn check_inheritance_ground_truth(
    tree: &TempProjectTree,
    source_manager: &DefaultSourceManager,
) {
    let gt_manifest = tree.path("inherited-workspace/gt/miden-project.toml");
    let source = source_manager.load_file(&gt_manifest).unwrap_or_else(|e| {
        panic!("loading the ground-truth member manifest {gt_manifest:?} failed: {e:?}")
    });
    let workspace_manifest = tree.path("inherited-workspace/miden-project.toml");
    let workspace_source = source_manager.load_file(&workspace_manifest).unwrap_or_else(|e| {
        panic!("loading the workspace manifest {workspace_manifest:?} failed: {e:?}")
    });
    let workspace_ast = miden_project::ast::WorkspaceFile::parse(workspace_source)
        .expect("the known workspace manifest must parse");
    let package = miden_project::Package::load_from_workspace(source, &workspace_ast)
        .expect("the ground-truth member must load within its workspace");
    // EXACT accessors, not Debug substring search: containment would accept a near-miss
    // description ("workspace defaults WRONG") or a prerelease version.
    assert!(
        *package.name().inner() == *"gt-member",
        "the member name must be exact"
    );
    let expected_version: miden_project::SemVer = "1.0.0"
        .parse()
        .expect("the expected version literal must parse");
    assert_eq!(
        *package.version().inner(),
        &expected_version,
        "the inherited version must equal the workspace value exactly (prereleases rejected)"
    );
    assert_eq!(
        package.description().as_deref(),
        Some("workspace defaults"),
        "the inherited description must equal the workspace value exactly"
    );
}

fn scenario_index(data: &[u8], count: usize) -> usize {
    data.iter()
        .fold(0usize, |acc, byte| acc.wrapping_mul(31).wrapping_add(*byte as usize))
        % count
}

fn write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}
