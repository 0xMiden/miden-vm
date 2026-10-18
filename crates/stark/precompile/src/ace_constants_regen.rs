//! Compatibility entrypoint for source-owned PVM generation.

use alloc::string::String;

pub use miden_air_source::codegen::Mode;
pub fn run(mode: Mode) -> Result<(), String> {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    miden_air_source::codegen::precompile::run(&workspace, mode)
}
