//! Fuzz target for Project TOML manifest parsing.
//!
//! This target fuzzes the `miden_project::ast::MidenProject` TOML parsing,
//! which is used to parse `miden-project.toml` manifest files.
//!
//! Run with: cargo +nightly fuzz run project_toml_parse --fuzz-dir miden-core-fuzz

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::debuginfo::{SourceFile, SourceId, SourceLanguage};
use miden_project::{
    Uri,
    ast::{MidenProject, PackageConfig, PackageTable, ProjectFile, WorkspaceFile},
};

fuzz_target!(|data: &[u8]| {
    // Try to parse the data as a TOML string
    if let Ok(toml_str) = core::str::from_utf8(data) {
        let source_file = Arc::new(SourceFile::new(
            SourceId::default(),
            SourceLanguage::Other("toml"),
            Uri::new("fuzz://miden-project.toml"),
            toml_str,
        ));

        // Exercise the production manifest parser, including validation and source-span setup.
        let _ = MidenProject::parse(source_file);

        // Attempt to parse as MidenProject AST (workspace or package manifest)
        let _ = toml::from_str::<MidenProject>(toml_str);

        // Also try parsing individual components
        let _ = toml::from_str::<ProjectFile>(toml_str);
        let _ = toml::from_str::<WorkspaceFile>(toml_str);
        let _ = toml::from_str::<PackageConfig>(toml_str);
        let _ = toml::from_str::<PackageTable>(toml_str);
    }
});
