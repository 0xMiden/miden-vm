#![cfg(feature = "std")]

use std::path::Path;

use miden_assembly::{Report, testing};

pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// This test assembles the `main` exectuable target of the `protocolish` kernel project.
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
    let context = testing::TestContext::new();

    let manifest_path = Path::new(FIXTURES_DIR)
        .join("protocolish")
        .join("kernel")
        .join("miden-project.toml");
    context.assemble_target_of_project("entry", &manifest_path)?;

    Ok(())
}
