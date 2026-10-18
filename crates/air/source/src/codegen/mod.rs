//! Source-owned generation workflow. Compilation/rendering uses package-local templates and
//! ordinary authored AIR values. Output paths are explicit; default writes never accept new pins.

pub mod constraints;
pub mod degrees;
pub mod evaluator;
pub mod metadata;
pub use constraints::Mode;

pub mod precompile;
mod pvm_ood_frames;

/// Run the source-owned generation workflow for the caller's checkout.
pub fn run(root: &std::path::Path, mode: Mode) -> Result<(), alloc::string::String> {
    let artifacts = root.join("crates/air/generated/artifacts");
    evaluator::run(&artifacts.join(evaluator::ARTIFACT_FILE), mode)?;
    constraints::run(root, mode)?;
    precompile::run(root, mode)?;
    degrees::deliver(&artifacts, &degrees::generate(), mode)?;
    degrees::deliver(&artifacts, &metadata::generate(), mode)
}
