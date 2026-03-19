#![cfg(feature = "std")]

use std::path::Path;

use miden_assembly::{Report, testing::TestContext};

pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// This test assembles the `main` exectuable target of the `protocol` kernel project.
///
/// This exercises:
///
/// * Workspace management
/// * Intra-workspace dependencies
/// * Inter-workspace dependencies
/// * Multi-target projects
/// * Multiple linkage modes
#[test]
fn assemble_a_protocol_like_workspace_project() -> Result<(), Report> {
    let mut context = TestContext::new();

    let manifest_path = Path::new(FIXTURES_DIR)
        .join("protocol")
        .join("kernel")
        .join("miden-project.toml");

    context.assemble_executable_package(&manifest_path, Some("entry"), None)?;

    Ok(())
}
