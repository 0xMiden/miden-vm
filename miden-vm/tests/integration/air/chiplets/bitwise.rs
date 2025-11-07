use miden_utils_testing::{build_op_test, build_test};

#[test]
fn bitwise_and() {
    // Test all bit input combinations: (1, 1), (1, 0), (0, 0). Then test larger numbers.
    let asm_op = "u32and push.0 u32and push.0 u32and push.65535 push.137 u32and";
    let pub_inputs = vec![1, 1];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn bitwise_or() {
    // Test all bit input combinations: (1, 1), (1, 0), (0, 0). Then test larger numbers.
    let asm_op = "u32or push.0 u32or not push.0 u32or push.65535 push.137 u32or";
    let pub_inputs = vec![1, 1];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn bitwise_xor() {
    // Test all bit input combinations: (1, 1), (0, 0), (1, 0). Then test larger numbers
    let asm_op = "u32xor push.0 u32xor push.1 u32xor push.65535 push.137 u32xor";
    let pub_inputs = vec![1, 1];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn all_operations() {
    let source = "begin u32and push.0 u32or push.0 u32xor end";
    let pub_inputs = vec![1, 1];

    build_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}
