//! Source-owned generation workflow. Compilation/rendering uses package-local templates and
//! ordinary authored AIR values. Output paths are explicit; default writes never accept new pins.

use alloc::string::String;

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

/// Compile and validate every projection before writing any managed output.
/// Accepted identities are loaded explicitly; protected bodies remain check-only.
pub fn run(root: &std::path::Path, mode: Mode) -> Result<(), String> {
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
    precompile::validate_delivery(root, &pvm)?;
    let mut plans = std::vec![vm_plan];
    plans.extend(miden_core::deferred::PvmAirVariant::ALL_VARIANTS[..7].iter().map(|&variant| {
        masm_renderer::prepare_v1(
            precompile::compile_for(Some(precompile::accepted_setup_commitment()), variant).masm,
        )
    }));
    let variants = pvm_variants::render_prepared(&plans[1..]);
    pvm_variants::validate(root, &variants)?;
    shared_verifier::validate_obsolete(root)?;
    plans.push(pvm_plan);
    let shared = masm_renderer::shared::render(&plans);
    let rust_evaluator = evaluator::generate();
    let degree_tables = degrees::generate();
    let metadata_tables = metadata::generate();
    let artifacts = root.join("crates/air/generated/artifacts");
    let evaluator_path = root.join("crates/air/generated/artifacts").join(evaluator::ARTIFACT_FILE);
    // All accepted/protected checks above precede every managed write.
    if mode == Mode::Check {
        constraints::public_inputs_masm_matches_air(root)?;
        constraints::security_masm_matches_air(root)?;
    }
    delivery::deliver(root, &shared, mode)?;
    delivery::deliver(root, &vm.files, mode)?;
    delivery::deliver(root, &pvm.files, mode)?;
    degrees::deliver(&artifacts, &degree_tables, mode)?;
    degrees::deliver(&artifacts, &metadata_tables, mode)?;
    evaluator::deliver(&evaluator_path, &rust_evaluator, mode)?;
    for variant in variants {
        delivery::deliver(root, &variant.files, mode)?;
    }
    Ok(())
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
