//! Synthetic transaction kernel benchmark generator
//!
//! This crate generates Miden assembly benchmarks based on VM profiles
//! exported from miden-base's transaction kernel.

pub mod generator;
pub mod profile;
pub mod validator;

use std::path::Path;

use anyhow::Result;

/// Load a VM profile from a JSON file
pub fn load_profile<P: AsRef<Path>>(path: P) -> Result<profile::VmProfile> {
    let content = std::fs::read_to_string(path)?;
    let profile = serde_json::from_str(&content)?;
    Ok(profile)
}

/// Get the latest profile from the profiles directory
///
/// # Note
/// This function looks for the profile relative to the current working directory.
/// For workspace-relative paths, use `load_profile` with an explicit path.
pub fn latest_profile() -> Result<profile::VmProfile> {
    // Try to find the workspace root by looking for Cargo.toml with workspace definition
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").map(std::path::PathBuf::from).or_else(|_| {
            std::env::current_dir()
                .map_err(|e| anyhow::anyhow!("Failed to determine current directory: {}", e))
        })?;

    load_profile(manifest_dir.join("profiles/latest.json"))
}
