//! Shared runtime rendering is separate from per-relation namespace projection.
use std::vec::Vec;

use super::{
    constraints,
    masm_renderer::{self, RenderedArtifact},
    precompile,
};

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
