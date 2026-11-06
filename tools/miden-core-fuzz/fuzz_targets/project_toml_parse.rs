//! Fuzz target for Project TOML manifest parsing.
//!
//! This target fuzzes the `miden_project::ast::MidenProject` TOML parsing,
//! which is used to parse `miden-project.toml` manifest files.
//!
//! Run with: cargo +nightly fuzz run project_toml_parse --fuzz-dir tools/miden-core-fuzz

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

        // Attempt to parse as MidenProject AST (workspace or package manifest); the
        // result feeds the variant-stability oracle below.
        let parsed_project = toml::from_str::<MidenProject>(toml_str);

        // Also try parsing individual components
        let _ = toml::from_str::<ProjectFile>(toml_str);
        let _ = toml::from_str::<WorkspaceFile>(toml_str);
        let _ = toml::from_str::<PackageConfig>(toml_str);
        let _ = toml::from_str::<PackageTable>(toml_str);

        // VARIANT-STABILITY ORACLE (upgraded from crash-only): MidenProject is an UNTAGGED
        // serde enum — the classic roundtrip hazard is a variant flip when the re-serialized
        // TOML no longer discriminates the original variant. For any successful parse, the
        // re-serialization must re-parse to the SAME variant and re-serialize to the SAME
        // string. Corpus reachability measured per the reachability rule: 21-24/1722 ().
        if let Ok(project) = parsed_project {
            let variant_before = project.is_workspace();
            let reserialized = toml::to_string(&project)
                .expect("a successfully parsed manifest must re-serialize");
            let reparsed = toml::from_str::<MidenProject>(&reserialized)
                .expect("the canonical TOML form must re-parse");
            assert_eq!(
                reparsed.is_workspace(),
                variant_before,
                "untagged variant must be stable across the TOML roundtrip"
            );
            let reserialized2 = toml::to_string(&reparsed).expect("re-parse must re-serialize");
            assert_eq!(
                reserialized2, reserialized,
                "TOML serialization must be stable across the roundtrip"
            );
        }
    }
});
