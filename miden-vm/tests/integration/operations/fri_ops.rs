use miden_core::field::PrimeCharacteristicRing;
use miden_utils_testing::{
    Felt, PrimeField64, TRUNCATE_STACK_PROC, build_test, push_inputs, rand::rand_array,
};

// FRI_EXT2FOLD4
// ================================================================================================

#[test]
fn fri_ext2fold4() {
    // create a set of random inputs
    let mut inputs = rand_array::<Felt, 17>()
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect::<Vec<_>>();
    inputs[7] = 2; // domain segment must be < 4

    // when domain segment is 2, the 3rd query value and the previous value must be the same
    inputs[4] = inputs[13];
    inputs[5] = inputs[14];

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
    assert_eq!(stack_state[8], Felt::new(poe).square());
    assert_eq!(stack_state[10], Felt::new(layer_ptr + 8));
    assert_eq!(stack_state[11], Felt::new(poe).exp_u64(4));
    assert_eq!(stack_state[12], Felt::new(f_pos));
    assert_eq!(stack_state[15], Felt::new(end_ptr));

    // make sure STARK proof can be generated and verified
    test.prove_and_verify(vec![], false);
}
