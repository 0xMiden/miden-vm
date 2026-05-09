//! Fuzz target for assembling Miden projects from a filesystem tree.
//!
//! This target exercises `ProjectAssembler::assemble` on controlled library, executable, and
//! kernel project layouts. It also reads emitted debug sections and converts assembled executable
//! and kernel packages through the public package APIs.
//!
//! Run with: cargo +nightly fuzz run project_assemble --fuzz-dir miden-core-fuzz

#![no_main]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use libfuzzer_sys::fuzz_target;
use miden_assembly::{Assembler, ProjectTargetSelector};
use miden_core::serde::{Deserializable, SliceReader};
use miden_mast_package::{
    Package as MastPackage, SectionId, TargetType,
    debug_info::{DebugFunctionsSection, DebugSourcesSection, DebugTypesSection},
};
use miden_package_registry::InMemoryPackageRegistry;

const MAX_MANIFEST_SNIPPET_LEN: usize = 40 * 1024;
const EXECUTABLE_TARGET: &str = "main";

static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(0);

struct TempProjectTree {
    root: PathBuf,
}

impl TempProjectTree {
    fn new() -> std::io::Result<Self> {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir()
            .join(format!("miden-project-assemble-fuzz-{}-{id}", std::process::id()));

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
    if data.len() > MAX_MANIFEST_SNIPPET_LEN {
        return;
    }
    let Ok(snippet) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(tree) = TempProjectTree::new() else {
        return;
    };
    let metadata_value = toml::Value::String(snippet.to_owned()).to_string();

    match scenario_index(data, 8) {
        0 => assemble_library_project(&tree, &metadata_value, "dev"),
        1 => assemble_library_project(&tree, &metadata_value, "release"),
        2 => assemble_executable_project(&tree, &metadata_value, "dev"),
        3 => assemble_executable_project(&tree, &metadata_value, "release"),
        4 => assemble_kernel_project(&tree, &metadata_value, ProjectTargetSelector::Library, "dev"),
        5 => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Library,
            "release",
        ),
        6 => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Executable(EXECUTABLE_TARGET),
            "dev",
        ),
        _ => assemble_kernel_project(
            &tree,
            &metadata_value,
            ProjectTargetSelector::Executable(EXECUTABLE_TARGET),
            "release",
        ),
    }
});

fn assemble_library_project(tree: &TempProjectTree, metadata_value: &str, profile: &str) {
    let manifest_path = tree.path("library/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "libpkg"
version = "1.0.0"
description = "library fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
path = "lib.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("library/lib.masm"),
            r#"pub proc helper
    push.1
    push.2
    add
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, ProjectTargetSelector::Library, profile);
}

fn assemble_executable_project(tree: &TempProjectTree, metadata_value: &str, profile: &str) {
    let manifest_path = tree.path("executable/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "apppkg"
version = "1.0.0"
description = "executable fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
path = "lib.masm"

[[bin]]
name = "main"
path = "main.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("executable/lib.masm"),
            r#"pub proc helper
    push.3
end
"#,
        )
        .is_err()
        || write_file(
            &tree.path("executable/main.masm"),
            r#"use $exec::lib

begin
    exec.lib::helper
    drop
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, ProjectTargetSelector::Executable(EXECUTABLE_TARGET), profile);
}

fn assemble_kernel_project(
    tree: &TempProjectTree,
    metadata_value: &str,
    target: ProjectTargetSelector<'_>,
    profile: &str,
) {
    let manifest_path = tree.path("kernel/miden-project.toml");
    if write_file(
        &manifest_path,
        &format!(
            r#"[package]
name = "kernelpkg"
version = "1.0.0"
description = "kernel fuzz package"

[package.metadata.fuzz]
input = {metadata_value}

[lib]
kind = "kernel"
path = "kernel.masm"

[[bin]]
name = "main"
path = "main.masm"

[profile.dev]
debug = true

[profile.release]
debug = true
trim-paths = true
"#,
        ),
    )
    .is_err()
        || write_file(
            &tree.path("kernel/kernel.masm"),
            r#"pub proc foo
    caller
end
"#,
        )
        .is_err()
        || write_file(
            &tree.path("kernel/main.masm"),
            r#"begin
    syscall.foo
end
"#,
        )
        .is_err()
    {
        return;
    }

    assemble_project(&manifest_path, target, profile);
}

fn assemble_project(manifest_path: &Path, target: ProjectTargetSelector<'_>, profile: &str) {
    let assembler = Assembler::default();
    let mut registry = InMemoryPackageRegistry::default();

    let Ok(mut project_assembler) = assembler.for_project_at_path(manifest_path, &mut registry)
    else {
        return;
    };
    let Ok(package) = project_assembler.assemble(target, profile) else {
        return;
    };

    validate_package(&package);
}

fn validate_package(package: &MastPackage) {
    validate_debug_sections(package);

    // These conversion helpers borrow the package, despite the `try_into_*` names.
    match package.kind {
        TargetType::Executable => {
            let _ = package.try_into_program();
            let _ = package.try_embedded_kernel_package();
        },
        TargetType::Kernel => {
            let _ = package.try_into_kernel_library();
            let _ = package.to_kernel();
            let _ = package.kernel_module_info();
        },
        _ if package.is_library() => {
            let _ = package.kernel_runtime_dependency();
        },
        _ => (),
    }
}

fn validate_debug_sections(package: &MastPackage) {
    for section in &package.sections {
        if section.id == SectionId::DEBUG_SOURCES {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = DebugSourcesSection::read_from(&mut reader);
        } else if section.id == SectionId::DEBUG_FUNCTIONS {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = DebugFunctionsSection::read_from(&mut reader);
        } else if section.id == SectionId::DEBUG_TYPES {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = DebugTypesSection::read_from(&mut reader);
        }
    }
}

fn write_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

fn scenario_index(data: &[u8], count: usize) -> usize {
    data.iter()
        .fold(0usize, |acc, byte| acc.wrapping_mul(31).wrapping_add(*byte as usize))
        % count
}
