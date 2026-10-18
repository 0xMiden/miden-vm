//! Explicit developer delivery of the complete source-rendered verifier projections.

use std::{format, fs, path::Path, string::String};

pub use miden_air_source::codegen::Mode;
use miden_air_source::codegen::{
    self, constraints, evaluator,
    masm_renderer::{ArtifactOwnership, RenderedArtifact},
};

/// Validate every accepted/protected input before checking or writing any managed output.
pub fn run(root: &Path, mode: Mode) -> Result<(), String> {
    let rendered = codegen::render_and_validate(root)?;
    validate_obsolete(root)?;
    if mode == Mode::Check {
        constraints::public_inputs_masm_matches_air(root)?;
        constraints::security_masm_matches_air(root)?;
    }
    deliver(root, &rendered.before_evaluator, mode)?;
    let evaluator_path = root.join("crates/air/generated/artifacts").join(evaluator::ARTIFACT_FILE);
    evaluator::deliver(&evaluator_path, &rendered.evaluator, mode)?;
    deliver(root, &rendered.after_evaluator, mode)
}

/// Removed algorithm copies are an explicit migration, never silently ignored or regenerated.
fn validate_obsolete(root: &Path) -> Result<(), String> {
    for mask in 0..7 {
        for file in ["aux_trace", "constraints_eval", "deep_queries", "ood_frames", "public_inputs"]
        {
            let path = root.join(std::format!("crates/lib/core/asm/sys/pvm/v{mask}/{file}.masm"));
            if path.exists() {
                return Err(std::format!(
                    "obsolete variant algorithm {} must be removed by the reviewed sharing migration",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn compare(root: &Path, artifact: &RenderedArtifact) -> Result<(), String> {
    let path = root.join(&artifact.relative_path);
    let actual =
        fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if actual != artifact.body {
        return Err(format!("{} is stale; run make regenerate-constraints", path.display()));
    }
    Ok(())
}

fn deliver(root: &Path, artifacts: &[RenderedArtifact], mode: Mode) -> Result<(), String> {
    for artifact in artifacts {
        match mode {
            Mode::Check => compare(root, artifact)?,
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

#[cfg(test)]
mod tests;
