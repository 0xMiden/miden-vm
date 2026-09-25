use miden_utils_testing::build_test;

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
    let pub_inputs: Vec<u64> = (0..8).map(|_| rand::random()).collect();

    build_test!(source, &pub_inputs).check_constraints();
}
