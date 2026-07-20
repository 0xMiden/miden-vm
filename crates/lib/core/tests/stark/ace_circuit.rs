#![cfg(feature = "constraints-tools")]

use miden_core_lib::{constraints_regen, evaluator_regen};

#[test]
fn constraints_eval_masm_matches_air() {
    constraints_regen::constraints_eval_masm_matches_air()
        .expect("constraints_eval.masm drift check failed");
}

#[test]
fn relation_digest_matches_air() {
    constraints_regen::relation_digest_matches_air().expect("relation digest check failed");
}

#[test]
fn public_inputs_masm_matches_air() {
    constraints_regen::public_inputs_masm_matches_air()
        .expect("public_inputs.masm drift check failed");
}

#[test]
fn generated_evaluator_matches_air() {
    evaluator_regen::run(evaluator_regen::Mode::Check)
        .expect("generated constraint evaluator drift check failed");
}
