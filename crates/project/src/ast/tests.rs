use core::{assert_matches, fmt};
use std::{
    fs,
    path::Path,
    string::{String, ToString},
    vec::Vec,
};

use miden_assembly_syntax::diagnostics::{
    AnnotateRenderer, DefaultFailurePolicy, Diagnostic, Severity, SourceMap, SourceNamespace,
    SourceSpan, Spanned, WarningsAsErrors,
};

use super::{MidenProject, ProjectFile, WorkspaceFile};
use crate::{Outcome, SourceId};

struct TestContext {
    sources: SourceMap,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            sources: SourceMap::new(SourceNamespace::new_unchecked(90)),
        }
    }
}

impl TestContext {
    fn parse_file(&mut self, path: impl AsRef<Path>) -> Outcome<MidenProject> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).unwrap();
        let source_id =
            self.sources.insert(path.display().to_string(), source.clone(), None).unwrap();
        MidenProject::parse(source_id, &source)
    }

    fn parse_source(&mut self, source: &str) -> Outcome<MidenProject> {
        let source_id = self.sources.insert("project-test.toml", source.to_string(), None).unwrap();
        MidenProject::parse(source_id, source)
    }

    fn render(&self, outcome: &Outcome<MidenProject>) -> String {
        let prepared = outcome.diagnostics.prepare(&self.sources).unwrap();
        prepared
            .iter()
            .map(|diagnostic| AnnotateRenderer::default().render(diagnostic).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[test]
fn can_parse_miden_project_package_single_target_example() {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/package/miden-project.toml");
    let mut context = TestContext::default();
    let outcome = context.parse_file(MANIFEST_PATH).expect("parsing should succeed");

    assert_matches!(outcome, MidenProject::Package(_));
}

#[test]
fn can_parse_miden_project_package_multi_target_example() {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/protocol/miden-project.toml");
    let mut context = TestContext::default();
    let outcome = context.parse_file(MANIFEST_PATH).expect("parsing should succeed");

    assert_matches!(outcome, MidenProject::Workspace(_));
}

#[test]
fn parse_errors_resolve_through_the_callers_source_map() {
    let mut context = TestContext::default();
    let outcome = context.parse_source("[package]\nname = [\n");

    assert!(outcome.is_err());
    assert!(outcome.result.is_err());
    let rendered = context.render(&outcome);
    assert!(rendered.contains("project-test.toml"), "{rendered}");
    assert!(rendered.contains("name = ["), "{rendered}");
    assert!(rendered.contains("unclosed array"), "{rendered}");
}

#[test]
fn independent_semantic_errors_are_collected() {
    let mut context = TestContext::default();
    let outcome = context.parse_source(
        r#"[package]
name = "not valid"
version = "not-a-version"

[dependencies]
first = { version = "not-a-requirement" }
second = { version = "1", linkage = "sideways" }

[lib]
kind = "executable"
namespace = "not valid"
path = "mod.masm"
"#,
    );

    assert!(outcome.is_err());
    assert!(outcome.result.is_err());
    assert!(outcome.diagnostics.counts().errors() >= 5);
    let rendered = context.render(&outcome);
    assert!(rendered.contains("invalid project name"), "{rendered}");
    assert!(rendered.contains("invalid package version"), "{rendered}");
    assert!(rendered.contains("invalid dependency version requirement"), "{rendered}");
    assert!(rendered.contains("unknown linkage"), "{rendered}");
    assert!(rendered.contains("invalid library target"), "{rendered}");
}

#[test]
fn package_ast_preserves_toml_key_and_value_spans() {
    let source = r#"[package]
name = "example"
version = "1.2.3"

[package.metadata.network]
endpoint = "localhost"

[dependencies]
dep = { version = "=1.0.0", git = "https://example.invalid/dep", branch = "main", linkage = "static" }

[profile.dev]
inherits = "release"
network = "local"

[lints.miden]
unused = "warning"
"#;
    let project = toml::from_str::<ProjectFile>(source).unwrap();

    assert_toml_span(source, &project.package.name, "\"example\"");
    assert_toml_span(source, project.package.detail.version.as_ref().unwrap(), "\"1.2.3\"");

    let (metadata_table, metadata) = project.package.detail.metadata.first_key_value().unwrap();
    assert_toml_span(source, metadata_table, "network");
    let (metadata_key, metadata_value) = metadata.first_key_value().unwrap();
    assert_toml_span(source, metadata_key, "endpoint");
    assert_toml_span(source, metadata_value, "\"localhost\"");

    let (dependency_name, dependency) = project.config.dependencies.first_key_value().unwrap();
    assert_toml_span(source, dependency_name, "dep");
    let dependency = dependency.get_ref();
    assert_toml_span(source, &dependency.name, "dep");
    assert_toml_span(source, dependency.version_or_digest.as_ref().unwrap(), "\"=1.0.0\"");
    assert_toml_span(source, dependency.git.as_ref().unwrap(), "\"https://example.invalid/dep\"");
    assert_toml_span(source, dependency.branch.as_ref().unwrap(), "\"main\"");
    assert_toml_span(source, dependency.linkage.as_ref().unwrap(), "\"static\"");

    let profile = project.profiles.first().unwrap();
    assert_toml_span(source, &profile.name, "dev");
    assert_toml_span(source, profile.inherits.as_ref().unwrap(), "\"release\"");
    let (profile_key, profile_value) = profile.metadata.first_key_value().unwrap();
    assert_toml_span(source, profile_key, "network");
    assert_toml_span(source, profile_value, "\"local\"");

    let (lint_table, lints) = project.config.lints.first_key_value().unwrap();
    assert_toml_span(source, lint_table, "miden");
    let (lint_key, lint_value) = lints.first_key_value().unwrap();
    assert_toml_span(source, lint_key, "unused");
    assert_toml_span(source, lint_value, "\"warning\"");
}

#[test]
fn workspace_ast_preserves_member_and_inherited_value_spans() {
    let source = r#"[workspace]
members = ["first", "second"]

[workspace.package]
version = "2.0.0"
"#;
    let workspace = toml::from_str::<WorkspaceFile>(source).unwrap();

    assert_toml_span(source, &workspace.workspace.members[0], "\"first\"");
    assert_toml_span(source, &workspace.workspace.members[1], "\"second\"");
    assert_toml_span(source, workspace.workspace.package.version.as_ref().unwrap(), "\"2.0.0\"");
}

#[test]
fn package_lowering_preserves_canonical_source_spans() {
    use crate::{DependencyVersionScheme, Package, VersionRequirement};

    let source = r#"[package]
name = "example"
version = "1.2.3"

[package.metadata.network]
endpoint = "localhost"

[dependencies]
dep = { version = "=1.0.0", path = "../dep" }

[profile.custom]
network = "local"

[lints.miden]
unused = "warning"
"#;
    let source_id = SourceId::new(SourceNamespace::new_unchecked(88), 0);
    let package = Package::load(source_id, source, None).expect("package should load");

    assert_source_span(source, package.name().span(), "\"example\"");
    assert_source_span(source, package.version().span(), "\"1.2.3\"");

    let dependency = package.dependencies().first().unwrap();
    assert_source_span(source, dependency.span(), "dep");
    let DependencyVersionScheme::Path { path, version } = dependency.scheme() else {
        panic!("expected a path dependency");
    };
    assert_source_span(source, path.span(), "\"../dep\"");
    let Some(VersionRequirement::Semantic(version)) = version else {
        panic!("expected a semantic version requirement");
    };
    assert_source_span(source, version.span(), "\"=1.0.0\"");

    let (metadata_table, metadata) = package.metadata().first_key_value().unwrap();
    assert_source_span(source, metadata_table.span(), "network");
    let (metadata_key, metadata_value) = metadata.first_key_value().unwrap();
    assert_source_span(source, metadata_key.span(), "endpoint");
    assert_source_span(source, metadata_value.span(), "\"localhost\"");

    let profile = package.get_profile("custom").unwrap();
    assert_source_span(source, profile.span(), "custom");
    let (profile_key, profile_value) = profile.metadata().first_key_value().unwrap();
    assert_source_span(source, profile_key.span(), "network");
    assert_source_span(source, profile_value.span(), "\"local\"");

    let (lint_table, lints) = package.lints().first_key_value().unwrap();
    assert_source_span(source, lint_table.span(), "miden");
    let (lint_key, lint_value) = lints.first_key_value().unwrap();
    assert_source_span(source, lint_key.span(), "unused");
    assert_source_span(source, lint_value.span(), "\"warning\"");
}

fn assert_toml_span<T>(source: &str, value: &toml::Spanned<T>, expected: &str) {
    assert_eq!(&source[value.span()], expected);
}

fn assert_source_span(source: &str, span: SourceSpan, expected: &str) {
    assert_eq!(&source[span.range().into_slice_index()], expected);
}

#[derive(Debug)]
struct TestWarning;

impl Diagnostic for TestWarning {
    fn message(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        out.write_str("test-only project warning")
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }
}

#[test]
fn warning_diagnostics_survive_a_successful_parse_and_are_policy_driven() {
    let source = "[package]\nname = \"example\"\nversion = \"1.0.0\"\n";
    let source_id = SourceId::new(SourceNamespace::new_unchecked(89), 0);
    let outcome = super::parse_typed::<ProjectFile>(source_id, source, |project, context| {
        ProjectFile::validate(project, context);
        let _ = context.add(TestWarning);
    });

    assert!(outcome.result.is_ok(), "{:#?}", outcome.diagnostics);
    assert_eq!(outcome.diagnostics.counts().warnings(), 1);
    assert!(!outcome.diagnostics.assess(&DefaultFailurePolicy));
    assert!(outcome.diagnostics.assess(&WarningsAsErrors));
}
