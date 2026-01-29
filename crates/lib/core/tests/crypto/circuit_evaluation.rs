use miden_core::{
    Felt, ONE, ZERO,
    field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64, QuadFelt},
};
use miden_utils_testing::rand::rand_quad_felt;

#[test]
fn circuit_evaluation_prove_verify() {
    let num_repetitions = 20;
    let pointer = 1 << 16;

    let source = format!(
        "
    const NUM_READ_ROWS = 4
    const NUM_EVAL_ROWS = 4

    begin
       repeat.{num_repetitions}
            # Set up the stack for loading data from advice map
            push.{pointer}
            padw padw padw

            # Load data
            repeat.2
                adv_pipe
            end

            # Set up the inputs to the arithmetic circuit evaluation op and execute it
            push.NUM_EVAL_ROWS push.NUM_READ_ROWS push.{pointer}
            eval_circuit

            # Clean up the stack
            drop drop drop
            repeat.3 dropw end
            drop
       end
    end
    "
    );

    // the circuit
    let input_0 = rand_quad_felt();
    let input_1 = input_0 * (input_0 - QuadFelt::ONE);
    // inputs
    let input_0_coeffs = input_0.as_basis_coefficients_slice();
    let input_1_coeffs = input_1.as_basis_coefficients_slice();
    let mut data = vec![
        // id = 7, v = rand
        input_0_coeffs[0],
        input_0_coeffs[1],
        // id = 6, v = rand * (rand - 1) = result
        input_1_coeffs[0],
        input_1_coeffs[1],
    ];

    // constants
    data.extend_from_slice(&[
        -ONE, ZERO, // id = 5, v = -1
        ZERO, ZERO, // id = 4, v = 0
    ]);
    // eval gates
    data.extend_from_slice(&[
        // id = 3, v = rand + -1
        Felt::new(7 + (5 << 30) + (2 << 60)), // id_l = 7; id_r = 5; op = ADD
        // id = 2, v = rand * (rand - 1)
        Felt::new(7 + (3 << 30) + (1 << 60)), // id_l = 7; id_r = 3; op = MUL
        // id = 1, v = rand * (rand - 1) - result = zero
        Felt::new(2 + (6 << 30)), // id_l = 2; id_r = 6; op = SUB
        // id = 0, v = zero * zero
        Felt::new(1 + (1 << 30) + (1 << 60)), // id_l = 1; id_r = 1; op = MUL
    ]);

    // padding related only to the use of "adv_pipe" in the MASM example
    data.extend_from_slice(&[ZERO, ZERO, ZERO, ZERO]);

    // finalize the advice stack
    let adv_stack = data.repeat(num_repetitions);
    let adv_stack: Vec<u64> = adv_stack.iter().map(|a| a.as_canonical_u64()).collect();

    let test = miden_utils_testing::build_test!(source, &[], &adv_stack);
    test.expect_stack(&[]);
    test.prove_and_verify(vec![], false)
}
