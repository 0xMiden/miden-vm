#![cfg(feature = "integration-tests")]
use miden_utils_testing::build_op_test;

mod field_ops;
mod stack_manipualtion_ops;

/// Test empty starting stack with no overflow outputs.
#[test]
fn empty_input() {
    let asm_op = "push.1 drop";
    let pub_inputs = vec![];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

/// Test starting stack with some inputs but not full with no overflow outputs.
#[test]
fn some_inputs() {
    let asm_op = "push.5 drop";
    let pub_inputs = vec![1, 2, 3, 4];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

/// Test full starting stack with no overflow outputs.
#[test]
fn full_inputs() {
    let asm_op = "push.17 drop";
    let pub_inputs = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    build_op_test!(&asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}
