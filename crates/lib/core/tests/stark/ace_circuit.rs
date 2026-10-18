use std::path::{Path, PathBuf};

use miden_air_source::codegen::{Mode, constraints, evaluator};
use miden_core_lib_codegen::verifier;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[test]
fn generated_recursive_verifier_artifacts_match_air() {
    verifier::run(&workspace(), Mode::Check)
        .expect("recursive-verifier artifact drift check failed");
}

#[test]
fn security_masm_matches_air() {
    constraints::security_masm_matches_air(&workspace())
        .expect("security literal drift check failed");
}

#[test]
fn generated_evaluator_matches_air() {
    evaluator::run(
        &workspace()
            .join("crates/air/generated/artifacts")
            .join(evaluator::ARTIFACT_FILE),
        Mode::Check,
    )
    .expect("generated constraint evaluator drift check failed");
}

#[test]
fn source_rendering_abi_matches_live_stark_constants() {
    let source = include_str!("../../asm/stark/constants.masm");
    for (name, expected) in [
        ("LOG_AIR_TRACE_LENGTHS_PTR", constraints::SHARED_ABI.heights_ptr),
        ("LOG_AIR_TRACE_LENGTHS_CAPACITY", constraints::SHARED_ABI.heights_capacity),
        (
            "CONSTRAINT_COMPOSITION_COEFS_PTR",
            constraints::SHARED_ABI.composition_coefficients_ptr,
        ),
        ("PUBLIC_INPUTS_ADDRESS_PTR", constraints::SHARED_ABI.public_inputs_address_ptr),
    ] {
        let declaration = format!("pub const {name} = ");
        let values: Vec<u32> = source
            .lines()
            .filter_map(|line| {
                line.trim().strip_prefix(&declaration)?.split_whitespace().next()?.parse().ok()
            })
            .collect();
        assert_eq!(values, [expected], "source renderer assumes a different {name}");
    }
}
