use miden_core::chiplets::hasher::apply_permutation;
use miden_utils_testing::{
    Felt, PrimeField64, TRUNCATE_STACK_PROC, ToElements, assert_eq, build_op_test, build_test,
};

mod adv_ops;
mod constant_ops;
mod env_ops;
mod local_ops;
mod mem_ops;

// COMBINING DIFFERENT TYPES OF I/O OPERATIONS
// ================================================================================================

#[test]
fn mem_stream_pipe() {
    let source = "
        begin
            # pipe elements from advice to memory and hash them on the stack
            adv_pipe hperm

            # keep only the output elements from the adv_pipe hash
            dropw
            swapw
            dropw
            movup.4
            drop

            # push address 0 and a hasher state of ZEROs onto the stack
            repeat.13
                push.0
            end

            # use mem_stream and hperm to put the elements from memory on the stack and hash them
            mem_stream hperm

            # keep only the output elements from the mem_stream hash
            dropw
            swapw
            dropw
            movup.4
            drop

            # truncate the stack
            swapdw dropw dropw
        end";

    let advice_stack = [1, 2, 3, 4, 5, 6, 7, 8];

    // --- different stack values should yield the same results from adv_pipe and mem_stream ------
    // initialize with anything other than zeros, since the stack is set to 0s between the adv_pipe
    // and mem_stream operations in the source script.
    let stack_inputs = [1, 1, 1, 1, 1, 1, 1, 1];
    let test = build_test!(source, &stack_inputs, &advice_stack);
    let final_stack = test.get_last_stack_state();
    assert_eq!(final_stack[0..4], final_stack[4..8]);

    // --- the same stack values should yield the same results from adv_pipe and mem_stream -------
    // initialize with all zeros, just like between the adv_pipe and mem_stream operations above.
    let test = build_test!(source, &[], &advice_stack);
    let final_stack = test.get_last_stack_state();
    assert_eq!(final_stack[0..4], final_stack[4..8]);

    // --- assert that the hashed output values are correct ---------------------------------------
    // compute the expected result of hashing the elements in the advice stack inputs.
    // Rate words come first in state, then capacity:
    // state = [rate1_0-3, rate2_4-7, capacity_8-11]
    let mut state: [Felt; 12] =
        [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0].to_elements().try_into().unwrap();
    apply_permutation(&mut state);

    // The MASM code keeps state[4..8] (rate word 2) after the stack manipulation:
    // dropw swapw dropw movup.4 drop
    let final_stack: Vec<u64> = state[4..8]
        .iter()
        .chain(state[4..8].iter())
        .map(|&v| v.as_canonical_u64())
        .collect();

    test.expect_stack(&final_stack);
}
