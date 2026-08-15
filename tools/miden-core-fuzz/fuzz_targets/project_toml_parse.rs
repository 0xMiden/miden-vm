//! Fuzz target for Project TOML manifest parsing.
//!
//! This target fuzzes the `miden_project::ast::MidenProject` TOML parsing,
//! which is used to parse `miden-project.toml` manifest files.
//!
//! Run with: cargo +nightly fuzz run project_toml_parse --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_diagnostics::{SourceId, SourceNamespace};
use miden_project::ast::{MidenProject, PackageConfig, PackageTable, ProjectFile, WorkspaceFile};

fuzz_target!(|data: &[u8]| {
    // Try to parse the data as a TOML string
    if let Ok(toml_str) = core::str::from_utf8(data) {
        let source_id = SourceId::new(SourceNamespace::new_unchecked(1), 0);

        // Exercise the production manifest parser, including validation and source-span setup.
        let _ = MidenProject::parse(source_id, toml_str);

        // Attempt to parse as MidenProject AST (workspace or package manifest)
        let _ = toml::from_str::<MidenProject>(toml_str);

        // Also try parsing individual components
        let _ = toml::from_str::<ProjectFile>(toml_str);
        let _ = toml::from_str::<WorkspaceFile>(toml_str);
        let _ = toml::from_str::<PackageConfig>(toml_str);
        let _ = toml::from_str::<PackageTable>(toml_str);
    }
});
