//! Source-owned compilation and rendering using package-local templates and authored AIR values.
//! Complete projections validate accepted inputs and protected bodies without writing outputs.

use alloc::{format, string::String, vec::Vec};

pub mod constraints;
pub mod degrees;
pub mod evaluator;
pub mod masm_renderer;
pub mod metadata;
pub use constraints::Mode;

pub mod precompile;
pub mod pvm_variants;
pub mod shared_verifier;

mod accepted;
mod delivery;

/// Complete projections in delivery order, with the binary evaluator transport kept separate.
pub struct RenderedArtifacts {
    pub before_evaluator: Vec<masm_renderer::RenderedArtifact>,
    pub evaluator: String,
    pub after_evaluator: Vec<masm_renderer::RenderedArtifact>,
}

/// Compile and render all projections, checking accepted identities, protected bodies and ABI.
///
/// Reads explicit checkout inputs without writing outputs or accepting pins. The destination
/// owner must also reject obsolete modules before delivery.
pub fn render_and_validate(root: &std::path::Path) -> Result<RenderedArtifacts, String> {
    let identities = accepted::load(root)?;
    let compiled_vm = constraints::compile(constraints::accepted_setup_commitments());
    let vm_plan = masm_renderer::prepare_v1(compiled_vm.masm);
    let vm = constraints::render_prepared(&vm_plan, compiled_vm.preprocessed_commitments);
    let pvm_plan = masm_renderer::prepare_v1(
        precompile::compile(precompile::accepted_setup_commitment()).masm,
    );
    let pvm = precompile::render_prepared(&pvm_plan);
    identities.check(
        "vm",
        vm.circuit_digest.map(|felt| felt.as_canonical_u64()),
        vm.relation_digest.map(|felt| felt.as_canonical_u64()),
    )?;
    identities.check(
        "precompile",
        (*pvm.circuit_digest).map(|felt| felt.as_canonical_u64()),
        pvm.relation_digest.map(|felt| felt.as_canonical_u64()),
    )?;
    constraints::validate_delivery(root, &vm)?;
    constraints::validate_shared_abi(root)?;
    precompile::validate_delivery(root, &pvm)?;
    let mut plans = std::vec![vm_plan];
    plans.extend(miden_core::deferred::PvmAirVariant::ALL_VARIANTS[..7].iter().map(|&variant| {
        masm_renderer::prepare_v1(
            precompile::compile_for(Some(precompile::accepted_setup_commitment()), variant).masm,
        )
    }));
    let variants = pvm_variants::render_prepared(&plans[1..]);
    pvm_variants::validate(root, &identities, &variants)?;
    plans.push(pvm_plan);
    let shared = masm_renderer::shared::render(&plans);
    let rust_evaluator = evaluator::generate();
    let tables: Vec<_> = degrees::generate()
        .into_iter()
        .chain(metadata::generate())
        .map(|(file, body)| masm_renderer::RenderedArtifact {
            relative_path: format!("crates/air/generated/artifacts/{file}"),
            body,
            ownership: masm_renderer::ArtifactOwnership::Managed,
        })
        .collect();
    let mut before_evaluator = shared;
    before_evaluator.extend(vm.files);
    before_evaluator.extend(pvm.files);
    before_evaluator.extend(tables);
    Ok(RenderedArtifacts {
        before_evaluator,
        evaluator: rust_evaluator,
        after_evaluator: variants.into_iter().flat_map(|variant| variant.files).collect(),
    })
}

#[cfg(test)]
fn expect_panic<T>(run: impl FnOnce() -> T) -> String {
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
        .err()
        .expect("invalid authored compiler input must panic");
    if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        (*panic.downcast_ref::<&str>().expect("string panic message")).into()
    }
}
