#![cfg(feature = "constraints-tools")]

use miden_core_lib::{constraints_regen, evaluator_regen};

#[test]
fn generated_recursive_verifier_artifacts_match_air() {
    constraints_regen::run(constraints_regen::Mode::Check)
        .expect("recursive-verifier artifact drift check failed");
}

#[test]
fn security_masm_matches_air() {
    constraints_regen::security_masm_matches_air().expect("security literal drift check failed");
}

#[test]
fn generated_evaluator_matches_air() {
    evaluator_regen::run(evaluator_regen::Mode::Check)
        .expect("generated constraint evaluator drift check failed");
}
