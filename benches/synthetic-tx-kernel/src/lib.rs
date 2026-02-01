//! Synthetic transaction kernel benchmark generator
//!
//! This crate generates Miden assembly benchmarks based on VM profiles
//! exported from miden-base's transaction kernel.

pub mod profile;
pub mod generator;
pub mod validator;

use anyhow::Result;
use std::path::Path;

/// Load a VM profile from a JSON file
pub fn load_profile<P: AsRef<Path>>(path: P) -> Result<profile::VmProfile> {
    let content = std::fs::read_to_string(path)?;
    let profile = serde_json::from_str(&content)?;
    Ok(profile)
}

/// Get the latest profile from the profiles directory
pub fn latest_profile() -> Result<profile::VmProfile> {
    load_profile("profiles/latest.json")
}
