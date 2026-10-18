//! Selected PVM projections from the same typed engine as the full relation.
//!
//! Each internal module pins an exact circuit, statement, geometry and security descriptor.
//! The public wrapper dispatches to these modules after checking the three-bit selection.

use std::{format, path::Path, string::String, vec::Vec};

use super::{accepted, masm_renderer, precompile};
use crate::precompile::PvmAirVariant;

pub struct VariantArtifacts {
    pub mask: u8,
    pub circuit: [u64; 4],
    pub relation: [u64; 4],
    pub files: Vec<masm_renderer::RenderedArtifact>,
}

pub fn generate() -> Vec<VariantArtifacts> {
    let plans: Vec<_> = PvmAirVariant::ALL_VARIANTS[..7]
        .iter()
        .map(|&variant| {
            let input =
                precompile::compile_for(Some(precompile::accepted_setup_commitment()), variant);
            masm_renderer::prepare_v1(input.masm)
        })
        .collect();
    render_prepared(&plans)
}

pub(super) fn render_prepared(plans: &[masm_renderer::V1RenderPlan]) -> Vec<VariantArtifacts> {
    plans
        .iter()
        .map(|plan| {
            let input = &plan.input;
            let masm_renderer::RelationInput::Pvm { glue, .. } = &input.relation else {
                unreachable!("PVM projection")
            };
            let mask = glue.variant.as_u8();
            let files = masm_renderer::render_v1(plan)
                .into_iter()
                .filter(|artifact| {
                    artifact.relative_path.ends_with("/mod.masm")
                        || artifact.relative_path.ends_with("/layout.masm")
                })
                .map(|mut artifact| {
                    let file = artifact
                        .relative_path
                        .strip_prefix("crates/lib/core/asm/sys/pvm/")
                        .expect("PVM projection path");
                    artifact.relative_path = format!("crates/lib/core/asm/sys/pvm/v{mask}/{file}");
                    artifact
                })
                .collect();
            VariantArtifacts {
                mask,
                circuit: input.circuit.digest,
                relation: input.relation_digest,
                files,
            }
        })
        .collect()
}

pub(super) fn validate(root: &Path, variants: &[VariantArtifacts]) -> Result<(), String> {
    let accepted = accepted::load(root)?;
    for variant in variants {
        accepted.check(
            &format!("precompile-{}", variant.mask),
            variant.circuit,
            variant.relation,
        )?;
        super::delivery::validate_protected(root, &variant.files)?;
    }
    Ok(())
}
