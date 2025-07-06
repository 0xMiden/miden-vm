use miden_test_utils::build_op_test;

#[test]
fn swap() {
    // Test on random input state.
    let asm_op = "swap push.0 swap push.34 swap drop drop";
    let pub_inputs = vec![7, 69];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}
