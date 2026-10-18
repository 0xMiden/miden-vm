//! Compatibility command entrypoint for the source-owned evaluator generator.

use alloc::string::String;

pub use miden_air_source::codegen::Mode;

pub fn run(mode: Mode) -> Result<(), String> {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let destination = workspace
        .join("crates/air/generated/artifacts")
        .join(miden_air_source::codegen::evaluator::ARTIFACT_FILE);
    miden_air_source::codegen::evaluator::run(&destination, mode)
}
