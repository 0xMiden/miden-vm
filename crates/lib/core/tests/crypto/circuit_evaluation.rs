use miden_ace_codegen::{AceConfig, InputKey, LayoutKind, build_ace_circuit_for_air};
use miden_air::ProcessorAir;
use miden_core::{
    Felt, ONE, ZERO,
    advice::AdviceStackBuilder,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
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

#[test]
fn processor_air_eval_circuit_masm() {
    let air = ProcessorAir::default();
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_aux_inputs: 14,
        layout: LayoutKind::Masm,
    };
    let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config).unwrap();
    let layout = circuit.layout().clone();

    let mut inputs = fill_inputs(&layout);
    // The ACE output is linear in each quotient coordinate. We can zero the circuit by
    // nudging a single quotient coordinate by delta = -root / slope.
    adjust_quotient_to_zero(&circuit, &layout, &mut inputs);
    assert_eq!(circuit.eval(&inputs).expect("circuit eval"), QuadFelt::ZERO);

    // Encode the circuit.
    let encoded = circuit.to_ace().unwrap();
    let mut memory_felts = Vec::with_capacity(inputs.len() * 2 + encoded.size_in_felt());
    for value in &inputs {
        memory_felts.extend_from_slice(value.as_basis_coefficients_slice());
    }
    memory_felts.extend_from_slice(encoded.instructions());

    let padded_len = memory_felts.len().next_multiple_of(8);
    memory_felts.resize(padded_len, ZERO);
    let num_adv_pipe = padded_len / 8;

    let mut advice_builder = AdviceStackBuilder::new();
    advice_builder.push_for_adv_pipe(&memory_felts);
    let adv_stack = advice_builder.build_vec_u64();

    // Place the circuit in memory at a fixed address.
    let pointer = 1 << 16;
    let num_read = encoded.num_vars();
    let num_eval = encoded.num_eval_rows();
    let source = format!(
        "
    const NUM_ADV_PIPE = {num_adv_pipe}
    const NUM_READ = {num_read}
    const NUM_EVAL = {num_eval}

    begin
        push.{pointer}
        padw padw padw

        repeat.NUM_ADV_PIPE
            adv_pipe
        end

        push.NUM_EVAL push.NUM_READ push.{pointer}
        eval_circuit

        drop drop drop
        repeat.3 dropw end
        drop
    end
    "
    );

    let test = miden_utils_testing::build_test!(source, &[], &adv_stack);
    test.expect_stack(&[]);
    test.prove_and_verify(vec![], false)
}

fn fill_inputs(layout: &miden_ace_codegen::InputLayout) -> Vec<QuadFelt> {
    let mut values = Vec::with_capacity(layout.total_inputs);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..layout.total_inputs {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let lo = Felt::new(state);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let hi = Felt::new(state);
        values.push(QuadFelt::new([lo, hi]));
    }
    values
}

fn adjust_quotient_to_zero(
    circuit: &miden_ace_codegen::AceCircuit<QuadFelt>,
    layout: &miden_ace_codegen::InputLayout,
    inputs: &mut [QuadFelt],
) {
    let root = circuit.eval(inputs).expect("circuit eval");
    if root == QuadFelt::ZERO {
        return;
    }
    let (idx, slope) =
        find_nonzero_quotient_slope(circuit, layout, inputs, root).expect("non-zero slope");
    // Because the output is linear in the chosen quotient coordinate:
    // root + slope * delta = 0 => delta = -root / slope.
    let delta = -root * slope.inverse();
    inputs[idx] += delta;
}

fn find_nonzero_quotient_slope(
    circuit: &miden_ace_codegen::AceCircuit<QuadFelt>,
    layout: &miden_ace_codegen::InputLayout,
    inputs: &mut [QuadFelt],
    root: QuadFelt,
) -> Option<(usize, QuadFelt)> {
    // Search for a quotient coordinate that has a non-zero influence on the output.
    // We do this by bumping a coordinate by +1 and re-evaluating to get the slope.
    for chunk in 0..layout.counts.num_quotient_chunks {
        for coord in 0..layout.counts.ext_degree {
            let idx = layout
                .index(InputKey::QuotientChunkCoord { offset: 0, chunk, coord })
                .expect("quotient coord exists");
            let original = inputs[idx];
            inputs[idx] = original + QuadFelt::ONE;
            let slope = circuit.eval(inputs).expect("circuit eval") - root;
            inputs[idx] = original;
            if slope != QuadFelt::ZERO {
                return Some((idx, slope));
            }
        }
    }
    None
}
