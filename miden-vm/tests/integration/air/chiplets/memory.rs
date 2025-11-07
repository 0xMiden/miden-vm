use miden_utils_testing::{build_op_test, build_test};

#[test]
fn mem_load() {
    let asm_op = "mem_load.0 swap";

    build_op_test!(asm_op).prove_and_verify(vec![], false);
}

#[test]
fn mem_store() {
    let asm_op = "mem_store.0";
    let pub_inputs = vec![1];

    build_op_test!(asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn mem_loadw() {
    let asm_op = "mem_loadw_be.0";

    build_op_test!(asm_op).prove_and_verify(vec![], false);
}

#[test]
fn mem_storew() {
    let asm_op = "mem_storew_be.0";
    let pub_inputs = vec![1, 2, 3, 4];

    build_op_test!(asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn write_read() {
    let source = "begin mem_storew_be.0 mem_loadw_be.0 swapw end";

    let pub_inputs = vec![4, 3, 2, 1];

    build_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn update() {
    let source = "
    begin
        push.0.0.0.0
        mem_loadw_be.0
        mem_storew_be.0
        swapw dropw
    end";
    let pub_inputs = vec![8, 7, 6, 5, 4, 3, 2, 1];

    build_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn incr_write_addr() {
    let source = "begin mem_storew_be.0 mem_storew_be.4 end";
    let pub_inputs = vec![4, 3, 2, 1];

    build_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}
