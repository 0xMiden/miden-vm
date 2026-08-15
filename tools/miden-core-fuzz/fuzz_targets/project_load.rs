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
use miden_diagnostics::{SourceMap, SourceNamespace};
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

    let mut sources = SourceMap::new(SourceNamespace::new_unchecked(1));

    match scenario_index(data, 5) {
        0 => load_standalone_package(&tree, &mut sources, manifest),
        1 => load_standalone_project(&tree, &mut sources, manifest),
        2 => load_fuzzed_workspace(&tree, &mut sources, manifest),
        3 => load_inherited_workspace_member(&tree, &mut sources, manifest),
        _ => load_project_reference(&tree, &mut sources, manifest),
    }
});

fn load_standalone_package(
    tree: &TempProjectTree,
    sources: &mut SourceMap,
    manifest: &str,
) {
    let manifest_path = tree.path("standalone/miden-project.toml");
    if write_file(&manifest_path, manifest).is_err() {
        return;
    }

    if let Ok(source) = fs::read_to_string(&manifest_path)
        && let Ok(source_id) = sources.insert(manifest_path.display().to_string(), source.clone(), None)
    {
        let _ = Package::load(source_id, &source, Some(&manifest_path));
    }
}

fn load_standalone_project(
    tree: &TempProjectTree,
    sources: &mut SourceMap,
    manifest: &str,
) {
    let manifest_path = tree.path("standalone/miden-project.toml");
    if write_file(&manifest_path, manifest).is_err() {
        return;
    }

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load(tree.path("standalone"), sources);
    } else {
        let _ = Project::load(&manifest_path, sources);
    }
}

fn load_fuzzed_workspace(
    tree: &TempProjectTree,
    sources: &mut SourceMap,
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
        let _ = Project::load(tree.path("fuzzed-workspace"), sources);
    } else {
        let _ = Project::load(&workspace_manifest, sources);
    }
}

fn load_inherited_workspace_member(
    tree: &TempProjectTree,
    sources: &mut SourceMap,
    manifest: &str,
) {
    let member_manifest = write_inherited_workspace(tree, manifest);
    let Ok(member_manifest) = member_manifest else {
        return;
    };

    if scenario_index(manifest.as_bytes(), 2) == 0 {
        let _ = Project::load(tree.path("inherited-workspace/app"), sources);
    } else {
        let _ = Project::load(&member_manifest, sources);
    }
}

fn load_project_reference(
    tree: &TempProjectTree,
    sources: &mut SourceMap,
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
            sources,
        );
    } else {
        let _ = Project::load_project_reference("app", &workspace_manifest, sources);
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
    Ok(member_manifest)
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
