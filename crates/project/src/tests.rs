use std::path::Path;

use miden_assembly_syntax::debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt};
use miden_core::assert_matches;

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
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/multi_target/miden-project.toml");
    let context = TestContext::default();
    let project = context.parse_file(MANIFEST_PATH)?;

    assert_matches!(project, MidenProject::Package(_));

    Ok(())
}

#[test]
fn can_parse_miden_project_workspace_example() -> Result<(), Report> {
    const MANIFEST_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/examples/workspace/miden-project.toml");
    let context = TestContext::default();
    let project = context.parse_file(MANIFEST_PATH)?;

    assert_matches!(project, MidenProject::Workspace(_));

    Ok(())
}
