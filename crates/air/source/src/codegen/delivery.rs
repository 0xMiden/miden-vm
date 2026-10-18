//! Destination I/O for complete projections; callers validate all protected inputs before writes.
use std::{format, fs, path::Path, string::String};

use super::{
    Mode,
    masm_renderer::{ArtifactOwnership, RenderedArtifact},
};

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

pub(super) fn deliver(
    root: &Path,
    artifacts: &[RenderedArtifact],
    mode: Mode,
) -> Result<(), String> {
    for artifact in artifacts {
        match mode {
            Mode::Check => compare(root, artifact, "is stale; run make regenerate-constraints")?,
            Mode::Write if artifact.ownership == ArtifactOwnership::Managed => {
                let path = root.join(&artifact.relative_path);
                fs::create_dir_all(path.parent().expect("projection parent"))
                    .and_then(|()| fs::write(&path, &artifact.body))
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            },
            Mode::Write => {},
        }
    }
    Ok(())
}
