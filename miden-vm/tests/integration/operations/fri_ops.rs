use miden_utils_testing::{Felt, TRUNCATE_STACK_PROC, build_test, push_inputs, rand::rand_array};

// FRI_EXT2FOLD4
// ================================================================================================

#[test]
fn fri_ext2fold4() {
    for coset in 0..4 {
        let mut inputs =
            rand_array::<Felt, 17>().iter().map(Felt::as_canonical_u64).collect::<Vec<_>>();

        // inputs[7] -> stack[9] = natural coset.
        inputs[7] = coset;
        // poe must be nonzero.
        inputs[6] = inputs[6].max(1);

        // The opened row is stored in bit-reversed order. The selected row must match
        // prev_value = (pe0, pe1) at stack positions 11 and 12.
        let row_idx = match coset {
            0 => 0,
            1 => 2,
            2 => 1,
            3 => 3,
            _ => unreachable!(),
        };
        let row_stack_pos = row_idx as usize * 2;
        inputs[5] = inputs[16 - row_stack_pos];
        inputs[4] = inputs[16 - (row_stack_pos + 1)];

        let end_ptr = Felt::new_unchecked(inputs[0]);
        let layer_ptr = Felt::new_unchecked(inputs[1]);
        let poe = Felt::new_unchecked(inputs[6]);
        let f_pos = Felt::new_unchecked(inputs[8]);
        let next_layer_ptr = layer_ptr + Felt::new_unchecked(8);

        let source = format!(
            "
            {TRUNCATE_STACK_PROC}

            begin
                {inputs}
                fri_ext2fold4

                exec.truncate_stack
            end",
            inputs = push_inputs(&inputs)
        );

        let test = build_test!(source, &[]);

        // Full transition constraints are checked by `check_constraints`; these assertions
        // pin down the loop state consumed by the recursive verifier.
        let stack_state = test.get_last_stack_state();
        assert_eq!(stack_state[8], next_layer_ptr);
        assert_eq!(stack_state[9], next_layer_ptr);
        assert_eq!(stack_state[10], poe.exp_u64(4));
        assert_eq!(stack_state[11], f_pos);
        assert_eq!(stack_state[14], next_layer_ptr);
        assert_eq!(stack_state[15], end_ptr);

        test.check_constraints();
    }
}
