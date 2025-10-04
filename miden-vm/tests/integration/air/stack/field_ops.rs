use miden_utils_testing::build_op_test;

#[test]
#[ignore = "fix-prover"]
fn incr() {
    let asm_op = "add.1 add.1 push.0 add.1 add.1 eq assert";
    let pub_inputs = vec![0];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
#[ignore = "fix-prover"]
fn neg() {
    let asm_op = "dup.0 neg add eq.0 assert";
    let pub_inputs = vec![7];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
#[ignore = "fix-prover"]
fn not() {
    let asm_op = "dup.0 not add eq.1 assert";
    let pub_inputs = vec![1];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
#[ignore = "fix-prover"]
fn expacc() {
    // Test 9^10.
    let asm_op = "push.10 exp eq.3486784401 assert";
    let pub_inputs = vec![9];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}
