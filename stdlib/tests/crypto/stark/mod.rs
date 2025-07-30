use std::{array, sync::Arc};

use miden_air::{FieldExtension, HashFunction, PublicInputs};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{Felt, FieldElement, QuadFelt, WORD_SIZE, Word, ZERO};
use miden_processor::{
    DefaultHost, Program, ProgramInfo,
    crypto::{RandomCoin, Rpo256, RpoRandomCoin},
};
use miden_utils_testing::{
    AdviceInputs, ProvingOptions, StackInputs, VerifierError, proptest::proptest, prove,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;
use verifier_recursive::{VerifierData, generate_advice_inputs};

mod verifier_recursive;

// Note: Changes to Miden VM may cause this test to fail when some of the assumptions documented
// in `stdlib/asm/crypto/stark/verifier.masm` are violated.
#[rstest]
#[case(None)]
#[case(Some(KERNEL_EVEN_NUM_PROC))]
#[case(Some(KERNEL_ODD_NUM_PROC))]
fn stark_verifier_e2f4(#[case] kernel: Option<&str>) {
    // An example MASM program to be verified inside Miden VM.

    let example_source = "begin
            repeat.320
                swap dup.1 add
                
            end
            u32split drop
        end";
    let mut stack_inputs = vec![0_u64; 16];
    stack_inputs[15] = 0;
    stack_inputs[14] = 1;

    let VerifierData {
        initial_stack,
        advice_stack: tape,
        store,
        mut advice_map,
    } = generate_recursive_verifier_data(example_source, stack_inputs, kernel).unwrap();

    let circuit: Vec<Felt> = CONSTRAINT_EVALUATION_CIRCUIT.iter().map(|a| Felt::new(*a)).collect();
    let circuit_digest = Rpo256::hash_elements(&circuit);

    advice_map.push((circuit_digest, circuit));

    // Verify inside Miden VM
    let source = "
        use.std::crypto::miden_vm_verifier
        begin
            exec.miden_vm_verifier::verify
        end
        ";

    let test = build_test!(source, &initial_stack, &tape, store, advice_map);
    test.expect_stack(&[]);
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> Result<VerifierData, VerifierError> {
    let program = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel_lib =
                    Assembler::new(context.source_manager()).assemble_kernel(kernel).unwrap();
                let assembler = Assembler::with_kernel(context.source_manager(), kernel_lib);
                let program: Program = assembler.assemble_program(source).unwrap();
                program
            },
            None => {
                let program: Program = Assembler::default().assemble_program(source).unwrap();
                program
            },
        }
    };
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();

    let options =
        ProvingOptions::new(27, 8, 0, FieldExtension::Quadratic, 4, 127, HashFunction::Rpo256);

    let (stack_outputs, proof) = prove(
        &program,
        stack_inputs.clone(),
        advice_inputs,
        &mut host,
        options,
        Arc::new(DefaultSourceManager::default()),
    )
    .unwrap();

    let program_info = ProgramInfo::from(program);

    // build public inputs and generate the advice data needed for recursive proof verification
    let pub_inputs = PublicInputs::new(program_info, stack_inputs, stack_outputs);
    let (_, proof) = proof.into_parts();
    Ok(generate_advice_inputs(proof, pub_inputs).unwrap())
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
#[case(1000)]
fn variable_length_public_inputs(#[case] num_kernel_proc_digests: usize) {
    // STARK parameters
    let num_queries = 27;
    let log_trace_len = 10;
    let grinding_bits = 16;
    let initial_stack = vec![num_queries, log_trace_len, grinding_bits];

    // Seeded random number generator for reproducibility
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate fixed length public inputs

    let input_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let output_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());

    let mut fixed_length_public_inputs = input_operand_stack.to_vec();
    fixed_length_public_inputs.extend_from_slice(&output_operand_stack);
    fixed_length_public_inputs.extend_from_slice(&program_digest);
    let fix_len_pi_with_padding = fixed_length_public_inputs.len().next_multiple_of(8);
    fixed_length_public_inputs.resize(fix_len_pi_with_padding, 0);

    // 2) Generate the variable length public inputs, i.e., the kernel procedures digests

    let num_elements_kernel_proc_digests =
        num_kernel_proc_digests * (WORD_SIZE.next_multiple_of(8));
    let kernel_procedures_digests =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);

    // 3) Generate the auxiliary randomness

    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // 4) Build the advice stack

    let mut advice_stack = vec![num_elements_kernel_proc_digests as u64];
    advice_stack.extend_from_slice(&fixed_length_public_inputs);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);
    advice_stack.push(num_kernel_proc_digests as u64);

    // 5) Compute the expected randomness-reduced value of all the kernel procedures digests

    let beta =
        QuadFelt::new(Felt::new(auxiliary_rand_values[0]), Felt::new(auxiliary_rand_values[1]));
    let alpha =
        QuadFelt::new(Felt::new(auxiliary_rand_values[2]), Felt::new(auxiliary_rand_values[3]));
    let reduced_value_inv =
        reduce_kernel_procedures_digests(&kernel_procedures_digests, alpha, beta).inv();
    let [reduced_value_inv_0, reduced_value_inv_1] = reduced_value_inv.to_base_elements();

    // 6) Run the test

    let source = format!(
        "
        use.std::crypto::stark::random_coin
        use.std::crypto::stark::constants
        use.std::crypto::stark::public_inputs
        begin
            # 1) Initialize the FS transcript
            exec.random_coin::init_seed
            # => [C, ...]

            # 2) Process the public inputs
            exec.public_inputs::process_public_inputs
            # => [...]

            # 3) Load the reduced value of all kernel procedures digests
            #    Note that the memory layout is as follows:
            #    [..., a_0, ..., a_[m-1], b_0, b_1, 0, 0, alpha0, alpha1, beta0, beta1, OOD-evaluations-start, ...]
            #
            #    where:
            #
            #    i) [a_0, ..., a[m-1]] are the fixed length public inputs,
            #    ii) [b_0, b_1] is the reduced value of all kernel procedures digests,
            #    iii) [alpha0, alpha1, beta0, beta1] is the auxiliary randomness,
            #    iv) [OOD-evaluations-start, ...] the start of the section that will hold the OOD evaluations,
            #
            #    Note that [b_0, b_1, 0, 0, alpha0, alpha1, beta0, beta1, OOD-evaluations-start, ...] will hold temporarily
            #    the kernel procedures digests, but there will be later on overwritten by the reduced value, the auxiliary
            #    randomness, and the OOD evaluations.
            padw
            exec.constants::ood_evaluations_ptr
            sub.8
            mem_loadw

            # 4) Compare with the expected result, including the padding
            push.{reduced_value_inv_0}
            push.{reduced_value_inv_1}
            push.0.0
            eqw assert

            # 5) Clean up the stack
            dropw dropw
        end
        "
    );

    let test = build_test!(source, &initial_stack, &advice_stack);
    test.expect_stack(&[]);
}

#[test]
fn generate_query_indices() {
    let source = TEST_RANDOM_INDICES_GENERATION;

    let num_queries = 27;
    let lde_log_size = 18;
    let lde_size = 1 << lde_log_size;

    let input_stack = vec![num_queries as u64, lde_log_size as u64, lde_size as u64];

    let seed = Word::default();
    let mut coin = RpoRandomCoin::new(seed);
    let indices = coin
        .draw_integers(num_queries, lde_size, 0)
        .expect("should not fail to generate the indices");

    let advice_stack: Vec<u64> = indices.iter().rev().map(|index| *index as u64).collect();

    let test = build_test!(source, &input_stack, &advice_stack);

    test.expect_stack(&[]);
}

proptest! {
    #[test]
    fn generate_query_indices_proptest(num_queries in 7..150_usize, lde_log_size in 9..32_usize) {
        let source = TEST_RANDOM_INDICES_GENERATION;
        let lde_size = 1 << lde_log_size;

        let seed = Word::default();
        let mut coin = RpoRandomCoin::new(seed);
        let indices = coin
            .draw_integers(num_queries, lde_size, 0)
            .expect("should not fail to generate the indices");
        let advice_stack: Vec<u64> = indices.iter().rev().map(|index| *index as u64).collect();

        let input_stack = vec![num_queries as u64, lde_log_size as u64, lde_size as u64];
        let test = build_test!(source, &input_stack, &advice_stack);
        test.prop_expect_stack(&[])?;
    }
}

// HELPERS
// ===============================================================================================

/// Generates a vector with a specific number of kernel procedures digests given a `Rng`.
///
/// The digests are padded to the next multiple of 8 and are reversed. This is done in order to
/// make reducing these, in the recursive verifier, faster using Horner evaluation.
fn generate_kernel_procedures_digests<R: Rng>(
    rng: &mut R,
    num_kernel_proc_digests: usize,
) -> Vec<u64> {
    let num_elements_kernel_proc_digests = num_kernel_proc_digests * 2 * WORD_SIZE;

    let mut kernel_proc_digests: Vec<u64> = Vec::with_capacity(num_elements_kernel_proc_digests);

    (0..num_kernel_proc_digests).for_each(|_| {
        let digest: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u64());
        let mut digest = digest.to_vec();
        digest.resize(WORD_SIZE * 2, 0);
        digest.reverse();
        kernel_proc_digests.extend_from_slice(&digest);
    });

    kernel_proc_digests
}

fn reduce_kernel_procedures_digests(
    kernel_procedures_digests: &[u64],
    alpha: QuadFelt,
    beta: QuadFelt,
) -> QuadFelt {
    kernel_procedures_digests
        .chunks(2 * WORD_SIZE)
        .map(|digest| reduce_digest(digest, alpha, beta))
        .fold(QuadFelt::ONE, |acc, term| acc * term)
}

fn reduce_digest(digest: &[u64], alpha: QuadFelt, beta: QuadFelt) -> QuadFelt {
    const KERNEL_OP_LABEL: Felt = Felt::new(48);
    alpha
        + KERNEL_OP_LABEL.into()
        + beta
            * digest.iter().fold(QuadFelt::ZERO, |acc, coef| {
                acc * beta + QuadFelt::new(Felt::new(*coef), ZERO)
            })
}

// CONSTANTS
// ===============================================================================================

const KERNEL_ODD_NUM_PROC: &str = r#"
        export.foo
            add
        end
        export.bar
            div
        end
        export.baz
            mul
        end"#;

const KERNEL_EVEN_NUM_PROC: &str = r#"
        export.foo
            add
        end
        export.bar
            div
        end"#;

const TEST_RANDOM_INDICES_GENERATION: &str = r#"
        const.QUERY_ADDRESS=1024

        use.std::crypto::stark::random_coin
        use.std::crypto::stark::constants

        begin
            exec.constants::set_lde_domain_size
            exec.constants::set_lde_domain_log_size
            exec.constants::set_number_queries
            push.QUERY_ADDRESS exec.constants::set_fri_queries_address

            exec.random_coin::load_random_coin_state
            hperm
            hperm
            exec.random_coin::store_random_coin_state

            exec.random_coin::generate_list_indices

            exec.constants::get_lde_domain_log_size
            exec.constants::get_number_queries neg
            push.QUERY_ADDRESS
            # => [query_ptr, loop_counter, lde_size_log, ...]

            push.1
            while.true
                dup add.3 mem_load
                movdn.3
                # => [query_ptr, loop_counter, lde_size_log, query_index, ...]
                dup
                add.2 mem_load
                dup.3 assert_eq

                add.4
                # => [query_ptr + 4, loop_counter, lde_size_log, query_index, ...]

                swap add.1 swap
                # => [query_ptr + 4, loop_counter, lde_size_log, query_index, ...]

                dup.1 neq.0
                # => [?, query_ptr + 4, loop_counter + 1, lde_size_log, query_index, ...]
            end
            drop drop drop

            exec.constants::get_number_queries neg
            push.1
            while.true
                swap
                adv_push.1
                assert_eq
                add.1
                dup
                neq.0
            end
            drop
        end
        "#;

/// This is an output of the ACE codegen in AirScript and encodes the circuit for executing
/// the constraint evaluation check i.e., DEEP-ALI.
const CONSTRAINT_EVALUATION_CIRCUIT: [u64; 112] = [
    1,
    0,
    0,
    0,
    2305843126251553075,
    114890375379,
    2305843283017859381,
    2305843266911732021,
    1152921616275996777,
    2305843265837990197,
    1152921614128513127,
    2305843319525081397,
    1152921611981029477,
    2305843318451339573,
    1152921609833545827,
    2305843317377597749,
    1152921607686062177,
    2305843316303855925,
    1152921605538578527,
    1152921604464836831,
    1152921614128513128,
    1152921602317353060,
    1152921601243611234,
    1152921600169869408,
    1152921599096127582,
    1152921598022385920,
    2305843101555490908,
    1152921604464836735,
    1152921614128513129,
    1152921593727418468,
    1152921592653676642,
    1152921591579934816,
    1152921590506192990,
    1152921776263528702,
    270582939757,
    1152921587284967502,
    1152921586211225679,
    1152921611981029479,
    1152921584063742050,
    1152921582990000224,
    1152921581916258398,
    1152921580842516556,
    2305843084375621707,
    1152921609833545829,
    1152921577621291104,
    1152921576547549278,
    315680096365,
    1152921574400065828,
    314606354541,
    1152921572252581952,
    1152921571178840130,
    2305843074711945285,
    1152921607686062179,
    1152921567957614686,
    1152921566883872830,
    2305843070416977980,
    1152921605538578529,
    1152921563662647358,
    2305843067195752504,
    1152921571178840159,
    2305843065048268853,
    2305843063974527060,
    53687091285,
    333933707485,
    117037858930,
    118111600754,
    120259084402,
    117037858929,
    1152921557220196467,
    2305843055384592490,
    1152921553998970927,
    1152921548630261805,
    1152921547556519982,
    1152921546482778154,
    1152921628087156851,
    1152921544335294771,
    1152921544335294579,
    1152921542187811039,
    2305843045720916004,
    1152921542187810931,
    1152921538966585392,
    2305843042499690529,
    1152921551851487278,
    1152921535745359902,
    2305843039278465062,
    1152921538966585459,
    1152921532524134623,
    1152921551851487279,
    1152921530376650777,
    2305843033909755931,
    1152921625939673300,
    2305843031762272469,
    1152921526081683569,
    2305843029614788822,
    1152921523934199921,
    2305843027467305175,
    1152921521786716273,
    2305843025319821528,
    1152921519639232625,
    2305843023172337881,
    1152921517491748977,
    2305843021024854234,
    1152921515344265329,
    2305843018877370587,
    1152921548630261804,
    1152921512123039752,
    6442450966,
    1152921509975556101,
    1152921508901814276,
    1152921507828072451,
    1152921506754330626,
    1152921505680588801,
];
