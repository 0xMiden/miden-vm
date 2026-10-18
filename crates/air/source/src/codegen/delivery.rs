//! Read-only comparisons for protected projections and standalone source checks.
use std::{format, fs, path::Path, string::String};

use super::masm_renderer::{ArtifactOwnership, RenderedArtifact};

fn compare(root: &Path, artifact: &RenderedArtifact, reason: &str) -> Result<(), String> {
    let path = root.join(&artifact.relative_path);
    let actual =
        fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if actual != artifact.body {
        return Err(format!("{} {reason}", path.display()));
    }
    Ok(())
}

pub(super) fn validate_protected(
    root: &Path,
    artifacts: &[RenderedArtifact],
) -> Result<(), String> {
    for artifact in artifacts
        .iter()
        .filter(|a| a.ownership == ArtifactOwnership::ProtectedCheckOnly)
    {
        compare(
            root,
            artifact,
            "has protected template-body drift; review without accepting new pins",
        )?;
    }
    Ok(())
}

pub(super) fn check(root: &Path, artifacts: &[RenderedArtifact]) -> Result<(), String> {
    for artifact in artifacts {
        compare(root, artifact, "is stale; run make regenerate-constraints")?;
    }
    Ok(())
}
