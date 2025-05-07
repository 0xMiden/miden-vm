use test_utils::{QuadFelt, rand::rand_value};
use vm_core::{Felt, FieldElement, ONE, ZERO};

#[test]
fn arithmetic_circuit_eval_and_execute() {
    let num_repetitions = 20;
    let pointer = 1 << 16;

    let source = format!(
        "
    const.NUM_READ_ROWS=4
    const.NUM_EVAL_ROWS=4
    
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
            arithmetic_circuit_eval

            # Clean up the stack
            drop drop drop
            repeat.3 dropw end
            drop
       end
    end
    "
    );

    // the circuit
    let input_0: QuadFelt = rand_value();
    let input_1 = input_0 * (input_0 - QuadFelt::ONE);
    // inputs
    let mut data = vec![
        // id = 7, v = rand
        input_0.base_element(0),
        input_0.base_element(1),
        // id = 6, v = rand * (rand - 1) = result
        input_1.base_element(0),
        input_1.base_element(1),
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
    let adv_stack: Vec<u64> = adv_stack.iter().map(|a| a.as_int()).collect();

    let test = test_utils::build_test!(source, &[], &adv_stack);
    test.expect_stack(&[]);
    test.prove_and_verify(vec![], false)
}
