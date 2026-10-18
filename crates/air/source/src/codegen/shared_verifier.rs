//! Shared runtime delivery is separate from per-relation namespace projection.
use super::{
    constraints,
    masm_renderer::{self, RenderedArtifact},
    precompile,
};
use std::{path::Path, string::String, vec::Vec};

pub fn generate() -> Vec<RenderedArtifact> {
    let mut plans = std::vec![masm_renderer::prepare_v1(
        constraints::compile(constraints::accepted_setup_commitments()).masm
    )];
    for variant in miden_core::deferred::PvmAirVariant::ALL_VARIANTS {
        plans.push(masm_renderer::prepare_v1(
            precompile::compile_for(Some(precompile::accepted_setup_commitment()), variant).masm,
        ));
    }
    masm_renderer::shared::render(&plans)
}

/// Removed algorithm copies are an explicit migration, never silently ignored or regenerated.
pub(super) fn validate_obsolete(root: &Path) -> Result<(), String> {
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
