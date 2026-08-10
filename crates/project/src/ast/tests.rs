use core::assert_matches;
use std::path::Path;

use miden_assembly_syntax::debuginfo::{
    DefaultSourceManager, SourceLanguage, SourceManager, SourceManagerExt,
};
use miden_diagnostics::{AnnotateRenderer, NoteKind, SourceKey};

use crate::{ast::MidenProject, *};

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
    pub fn parse_file(&self, path: impl AsRef<Path>) -> Result<MidenProject, Report> {
        let path = path.as_ref();
        let source_file = self.source_manager.load_file(path).map_err(Report::msg)?;
        MidenProject::parse(source_file)
    }

    fn parse_source(&self, source: &str) -> Result<MidenProject, Report> {
        let source_file = self.source_manager.load(
            SourceLanguage::Other("toml"),
            Uri::new("memory:///project-test.toml"),
            source.into(),
        );
        MidenProject::parse(source_file)
    }
}

#[test]
fn can_parse_miden_project_package_single_target_example() -> Result<(), Report> {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/package/miden-project.toml");
    let context = TestContext::default();
    let project = context.parse_file(MANIFEST_PATH)?;

    assert_matches!(project, MidenProject::Package(_));

    Ok(())
}

#[test]
fn can_parse_miden_project_package_multi_target_example() -> Result<(), Report> {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/protocol/miden-project.toml");
    let context = TestContext::default();
    let project = context.parse_file(MANIFEST_PATH)?;

    assert_matches!(project, MidenProject::Workspace(_));

    Ok(())
}

#[test]
fn parse_errors_retain_an_attached_source() {
    let context = TestContext::default();
    let error = context
        .parse_source("[package]\nname = [\n")
        .expect_err("the malformed TOML must be rejected");
    let prepared = error.prepare_attached().expect("the attached source must resolve");

    assert_eq!(
        prepared.snapshot.message,
        "unable to parse project manifest: unclosed array, expected `]`"
    );
    assert_eq!(prepared.snapshot.labels.len(), 1);
    assert!(matches!(prepared.snapshot.labels[0].span.source(), SourceKey::Attached(_)));

    let rendered = AnnotateRenderer::default()
        .render(&prepared)
        .expect("the attached source diagnostic must render");
    assert!(rendered.contains("project-test.toml"), "{rendered}");
    assert!(rendered.contains("name = ["), "{rendered}");
}

#[test]
fn invalid_library_targets_are_preserved_as_related_diagnostics() {
    let context = TestContext::default();
    let error = context
        .parse_source(
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\n\n[lib]\nkind = \"executable\"\npath = \"mod.masm\"\n",
        )
        .expect_err("an executable target cannot be used as a library");
    let prepared = error.prepare_attached().expect("the attached source must resolve");

    assert_eq!(prepared.snapshot.message, "invalid build target configuration");
    assert_eq!(prepared.snapshot.related.len(), 1);
    let related = &prepared.snapshot.related[0];
    assert_eq!(related.message, "invalid library target");
    assert!(related.notes.iter().any(|note| note.kind == NoteKind::Help));
    assert!(matches!(related.labels[0].span.source(), SourceKey::Attached(_)));

    let rendered = AnnotateRenderer::default()
        .render(&prepared)
        .expect("the related diagnostic must render");
    assert!(rendered.contains("invalid library target"), "{rendered}");
    assert!(rendered.contains("kind = \"executable\""), "{rendered}");
}
