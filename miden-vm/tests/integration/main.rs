extern crate alloc;

use miden_utils_testing::{build_op_test, build_test};

mod air;
mod cli;
mod exec;
mod flow_control;
mod operations;

// TESTS
// ================================================================================================

#[test]
fn simple_program() {
    build_test!("begin push.1 push.2 add swap drop end").expect_stack(&[3]);
}

#[test]
fn multi_output_program() {
    let test = build_test!("begin mul movup.2 drop end", &[1, 2, 3]);
    test.prove_and_verify(vec![1, 2, 3], false);
}

#[test]
fn program_with_respan() {
    let source = "
        repeat.49
            swap dup.1 add
        end";
    let pub_inputs = vec![];

    build_op_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}
