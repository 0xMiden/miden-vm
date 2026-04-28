use miden_utils_testing::{Felt, TRUNCATE_STACK_PROC, build_test, push_inputs, rand::rand_array};

// FRI_EXT2FOLD4
// ================================================================================================

#[test]
fn fri_ext2fold4() {
    // create a set of random inputs
    let mut inputs =
        rand_array::<Felt, 17>().iter().map(Felt::as_canonical_u64).collect::<Vec<_>>();
    // inputs[7] -> stack[9] = p (bit-reversed tree index).
    // The instruction computes d_seg = p & 3 and f_pos = p >> 2.
    // We want d_seg=2, f_pos=inputs[8], so p = 4*f_pos + 2.
    // f_pos must fit in u32 to avoid overflow when computing p.
    inputs[8] %= (u32::MAX as u64) >> 2;
    inputs[7] = 4 * inputs[8] + 2;

    // When d_seg=2, query_values[2] = (v4, v5) must equal prev_value = (pe0, pe1).
    // After pushing 17 inputs:
    //   v4 = inputs[12] (stack[4]), v5 = inputs[11] (stack[5])
    //   pe0 = inputs[5] (stack[11]), pe1 = inputs[4] (stack[12])
    // So we need inputs[12] = inputs[5] (v4 = pe0) and inputs[11] = inputs[4] (v5 = pe1).
    inputs[12] = inputs[5];
    inputs[11] = inputs[4];

    let end_ptr = inputs[0];
    let layer_ptr = inputs[1];
    let poe = inputs[6];
    let f_pos = inputs[8];

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

    // execute the program
    let test = build_test!(source, &[]);

    // check some items in the state transition; full state transition is checked in the
    // processor tests
    let stack_state = test.get_last_stack_state();
    assert_eq!(stack_state[8], Felt::new_unchecked(poe).square());
    assert_eq!(stack_state[10], Felt::new_unchecked(layer_ptr + 8));
    assert_eq!(stack_state[11], Felt::new_unchecked(poe).exp_u64(4));
    assert_eq!(stack_state[12], Felt::new_unchecked(f_pos));
    assert_eq!(stack_state[15], Felt::new_unchecked(end_ptr));

    // make sure STARK proof can be generated and verified
    test.check_constraints();
}
