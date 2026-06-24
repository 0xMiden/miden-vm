#![cfg(feature = "std")]

use std::path::Path;

use miden_assembly::{Report, testing::TestContext};
use miden_mast_package::TargetType;

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

/// This test assembles the `userspace` library target of the `protocol` workspace.
///
/// The userspace package overrides the workspace `miden-utils` dependency to dynamic linkage and
/// depends on the workspace `miden-tx` kernel package. Its manifest should therefore record both
/// packages as runtime dependencies.
#[test]
fn assemble_protocol_userspace_dynamic_dependencies() -> Result<(), Report> {
    let mut context = TestContext::new();

    let manifest_path = Path::new(FIXTURES_DIR)
        .join("protocol")
        .join("userspace")
        .join("miden-project.toml");

    let package = context.assemble_library_package(&manifest_path, None)?;
    assert_eq!(&package.name, "miden-protocol");
    assert_eq!(package.kind, TargetType::Library);

    let dependencies = package.manifest.dependencies().collect::<Vec<_>>();
    assert_eq!(dependencies.len(), 2);

    let utils = dependencies
        .iter()
        .copied()
        .find(|dependency| &dependency.name == "miden-utils")
        .expect("userspace package should record dynamic miden-utils dependency");
    assert_eq!(utils.kind, TargetType::Library);
    assert_eq!(utils.version.to_string(), "0.1.0");

    let tx = dependencies
        .iter()
        .copied()
        .find(|dependency| &dependency.name == "miden-tx")
        .expect("userspace package should record workspace kernel dependency");
    assert_eq!(tx.kind, TargetType::Kernel);
    assert_eq!(tx.version.to_string(), "1.0.0");

    Ok(())
}
