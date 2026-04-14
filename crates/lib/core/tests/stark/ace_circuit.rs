#![cfg(feature = "constraints-tools")]

use miden_core_lib::constraints_regen;

#[test]
fn constraints_eval_masm_matches_air() {
    constraints_regen::constraints_eval_masm_matches_air()
        .expect("constraints_eval.masm drift check failed");
}

#[test]
fn relation_digest_matches_air() {
    constraints_regen::relation_digest_matches_air().expect("relation digest check failed");
}
