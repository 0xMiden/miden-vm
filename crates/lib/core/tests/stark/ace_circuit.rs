use miden_core_lib::constraints_regen;

#[test]
#[ignore = "run manually to regenerate ACE circuit data in MASM and Rust files"]
#[allow(clippy::print_stdout)]
fn regenerate_ace_circuit_data() {
    constraints_regen::regenerate_ace_circuit_data().expect("failed to regenerate ACE circuit data");
}

#[test]
fn constraints_eval_masm_matches_air() {
    constraints_regen::constraints_eval_masm_matches_air().expect("constraints_eval.masm drift check failed");
}

#[test]
fn relation_digest_matches_air() {
    constraints_regen::relation_digest_matches_air().expect("relation digest check failed");
}

