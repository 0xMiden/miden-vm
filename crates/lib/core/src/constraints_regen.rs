//! Compatibility entrypoints for source-owned VM constraint/MASM generation.

use alloc::string::String;

pub use miden_air_source::codegen::constraints::{Mode, compute_relation_digest};

fn workspace() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn run(mode: Mode) -> Result<(), String> {
    miden_air_source::codegen::constraints::run(&workspace(), mode)
}

pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    miden_air_source::codegen::constraints::constraints_eval_masm_matches_air(&workspace())
}

pub fn relation_digest_matches_air() -> Result<(), String> {
    miden_air_source::codegen::constraints::relation_digest_matches_air(&workspace())
}

pub fn public_inputs_masm_matches_air() -> Result<(), String> {
    miden_air_source::codegen::constraints::public_inputs_masm_matches_air(&workspace())
}

pub fn vm_geometry_matches_air() -> Result<(), String> {
    miden_air_source::codegen::constraints::vm_geometry_matches_air(&workspace())
}

pub fn security_masm_matches_air() -> Result<(), String> {
    miden_air_source::codegen::constraints::security_masm_matches_air(&workspace())
}
