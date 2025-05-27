use miden_core::{Felt, chiplets::hasher::apply_permutation, utils::ToElements};
use miden_processor::{AdviceError, ExecutionError, RowIndex};
use miden_utils_testing::expect_exec_error_matches;

use super::{TRUNCATE_STACK_PROC, build_op_test, build_test};

// PUSHING VALUES ONTO THE STACK (PUSH)
// ================================================================================================

#[test]
fn adv_push() {
    let asm_op = "adv_push";
    let advice_stack = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let test_n = |n: usize| {
        let source = format!("{asm_op}.{n}");
        let mut final_stack = vec![0; n];
        final_stack.copy_from_slice(&advice_stack[..n]);
        final_stack.reverse();

        let test = build_op_test!(source, &[], &advice_stack);
        test.expect_stack(&final_stack);
    };

    // --- push 1 ---------------------------------------------------------------------------------
    test_n(1);

    // --- push max -------------------------------------------------------------------------------
    test_n(16);
}

#[test]
fn adv_push_invalid() {
    // attempting to read from empty advice stack should throw an error
    let test = build_op_test!("adv_push.1");
    expect_exec_error_matches!(
        test,
        ExecutionError::AdviceError {
            err: AdviceError::StackReadFailed, clk, ..
        } if clk == RowIndex::from(2),
    )
}

// OVERWRITING VALUES ON THE STACK (LOAD)
// ================================================================================================

#[test]
fn adv_loadw() {
    let asm_op = "adv_loadw";
    let advice_stack = [1, 2, 3, 4];
    let mut final_stack = advice_stack;
    final_stack.reverse();

    let test = build_op_test!(asm_op, &[8, 7, 6, 5], &advice_stack);
    test.expect_stack(&final_stack);
}

#[test]
fn adv_loadw_invalid() {
    // attempting to read from empty advice stack should throw an error
    let test = build_op_test!("adv_loadw", &[0, 0, 0, 0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::AdviceError {
            err: AdviceError::StackReadFailed, clk, ..
        } if clk == RowIndex::from(2),
    );
}

// MOVING ELEMENTS TO MEMORY VIA THE STACK (PIPE)
// ================================================================================================

#[test]
fn adv_pipe() {
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        begin
            push.12.11.10.9.8.7.6.5.4.3.2.1
            adv_pipe

            exec.truncate_stack
        end"
    );

    let advice_stack = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state is built by replacing the values on the top of the stack with the top 8 values
    // from the head of the advice stack (i.e. values 1 through 8). Thus, the first 8 elements on
    // the stack will be 1-8 in stack order (stack[0] = 8), and the remaining 4 are untouched
    // (i.e., 9, 10, 11, 12).
    let state: [Felt; 12] =
        [12_u64, 11, 10, 9, 1, 2, 3, 4, 5, 6, 7, 8].to_elements().try_into().unwrap();

    // to get the final state of the stack, reverse the above state and push the expected address
    // to the end (the address will be 2 since 0 + 2 = 2).
    let mut final_stack = state.iter().map(|&v| v.as_int()).collect::<Vec<u64>>();
    final_stack.reverse();
    final_stack.push(8);

    let test = build_test!(source, &[], &advice_stack);
    test.expect_stack(&final_stack);
}

#[test]
fn adv_pipe_with_hperm() {
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        begin
            push.12.11.10.9.8.7.6.5.4.3.2.1
            adv_pipe hperm

            exec.truncate_stack
        end"
    );

    let advice_stack = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state of the hasher is the first 12 elements of the stack (in reverse order). the state
    // is built by replacing the values on the top of the stack with the top 8 values from the head
    // of the advice stack (i.e. values 1 through 8). Thus, the first 8 elements on the stack will
    // be 1-8 in stack order (stack[0] = 8), and the remaining 4 are untouched (i.e., 9, 10, 11,
    // 12).
    let mut state: [Felt; 12] =
        [12_u64, 11, 10, 9, 1, 2, 3, 4, 5, 6, 7, 8].to_elements().try_into().unwrap();

    // apply a hash permutation to the state
    apply_permutation(&mut state);

    // to get the final state of the stack, reverse the hasher state and push the expected address
    // to the end (the address will be 2 since 0 + 2 = 2).
    let mut final_stack = state.iter().map(|&v| v.as_int()).collect::<Vec<u64>>();
    final_stack.reverse();
    final_stack.push(8);

    let test = build_test!(source, &[], &advice_stack);
    test.expect_stack(&final_stack);
}
