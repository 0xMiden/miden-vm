#![cfg(feature = "integration-tests")]
use miden_utils_testing::{build_test, rand::rand_vector};

mod bitwise;
mod hasher;
mod memory;

#[test]
fn chiplets() {
    // Test a program that uses all of the chiplets.
    let source = "
    begin
        hperm                   # hasher operation
        push.5 push.10 u32or    # bitwise operation
        mem_load                # memory operation
        drop
    end";
    let pub_inputs = rand_vector::<u64>(8);

    build_test!(source, &pub_inputs).prove_and_verify(pub_inputs, false);
}
