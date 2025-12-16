use miden_processor::ExecutionError;
use miden_utils_testing::{Felt, U32_BOUND, build_op_test, expect_exec_error_matches, prop_randw};

mod arithmetic_ops;
mod bitwise_ops;
mod comparison_ops;
mod conversion_ops;

// HELPER FUNCTIONS
// ================================================================================================

/// This helper function tests a provided u32 assembly operation, which takes a single input, to
/// ensure that it fails when the input is >= 2^32.
pub fn test_input_out_of_bounds(asm_op: &str) {
    let test = build_op_test!(asm_op, &[U32_BOUND]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 1 &&
            values[0] == Felt::new(U32_BOUND)
    );
}

/// This helper function tests a provided u32 assembly operation, which takes multiple inputs, to
/// ensure that it fails when any one of the inputs is >= 2^32. Each input is tested independently.
pub fn test_inputs_out_of_bounds(asm_op: &str, input_count: usize) {
    let inputs = vec![0_u64; input_count];

    for i in 0..input_count {
        let mut i_inputs = inputs.clone();
        // should fail when the value of the input at index i is out of bounds
        i_inputs[i] = U32_BOUND;

        let test = build_op_test!(asm_op, &i_inputs);

        expect_exec_error_matches!(
            test,
            ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
                values.len() == 1 &&
                values[0] == Felt::new(U32_BOUND)
        );
    }
}
