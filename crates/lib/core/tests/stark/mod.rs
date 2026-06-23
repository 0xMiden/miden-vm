use std::{array, sync::Arc};

use miden_air::{
    MidenMultiAir, NUM_PUBLIC_VALUES, NUM_VAR_LEN_PUBLIC_INPUT_GROUPS, ProofOrder, PublicInputs,
    Statement, config,
};
use miden_assembly::{
    Assembler, DefaultSourceManager, Path,
    ast::{Module, ModuleKind},
};
use miden_core::{
    Felt, WORD_SIZE, Word,
    advice::AdviceStackBuilder,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    precompile::PrecompileTranscriptState,
    proof::HashFunction,
};
use miden_crypto::stark::{Preprocessed, StarkConfig, challenger::CanObserve};
use miden_mast_package::Package;
use miden_processor::{DefaultHost, ExecutionOptions, Program, ProgramInfo};
use miden_utils_testing::{
    AdviceInputs, ProvingOptions,
    crypto::MerkleStore,
    prove_sync,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;

const SECURITY_PARAMS_LEN: usize = 4;
const AND8_LOOKUP_LOG_HEIGHT: u64 = 16;
const STATEMENT_DESCRIPTOR_LEN: usize = 4;
const SHAPE_TEST_OUTPUT_PTR: u32 = 1000;

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);
    let order = run_recursive_verifier(&data);
    assert_eq!(order, expected_order_from_shape(&data));
}

#[test]
fn stark_verifier_e2f4_large() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, inputs, None);
    let order = run_recursive_verifier(&data);
    assert_eq!(order, expected_order_from_shape(&data));
}

#[test]
fn stark_verifier_e2f4_with_kernel_even() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let order = run_recursive_verifier(&data);
    assert_eq!(order, expected_order_from_shape(&data));
}

#[test]
fn stark_verifier_e2f4_with_kernel_odd() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_ODD_NUM_PROC),
    );
    let order = run_recursive_verifier(&data);
    assert_eq!(order, expected_order_from_shape(&data));
}

#[test]
fn stark_verifier_e2f4_with_kernel_single() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    let order = run_recursive_verifier(&data);
    assert_eq!(order, expected_order_from_shape(&data));
}

#[test]
fn stark_verifier_e2f4_with_kernel_flipped_order() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_LARGE,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    let order = run_recursive_verifier(&data);
    let expected = expected_order_from_shape(&data);

    assert_eq!(order, expected);
    assert_ne!(order, ProofOrder::instance_order());
}

#[test]
fn stark_verifier_e2f4_uses_shape_order_tag_for_small_proofs() {
    let equal_height = generate_recursive_verifier_data(EXAMPLE_EQUAL_HEIGHTS, vec![], None);
    let core_heavy = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);

    let equal_height_order = run_recursive_verifier(&equal_height);
    let core_heavy_order = run_recursive_verifier(&core_heavy);

    assert_eq!(equal_height_order, expected_order_from_shape(&equal_height));
    assert_eq!(core_heavy_order, expected_order_from_shape(&core_heavy));
}

#[test]
fn stark_verifier_e2f4_rejects_wrong_order_tag() {
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    assert_ne!(expected_order_from_shape(&data), ProofOrder::instance_order());

    let source = "
        use miden::core::stark::constants
        use miden::core::stark::verifier

        use miden::core::sys::vm
        use miden::core::sys::vm::aux_trace
        use miden::core::sys::vm::constraints_eval
        use miden::core::sys::vm::deep_queries
        use miden::core::sys::vm::ood_frames
        use miden::core::sys::vm::public_inputs

        proc wrong_constraints_eval
            # Flip the derived tag, then dispatch to the wrong order-specific circuit.
            exec.constants::get_order_tag
            add.1
            exec.constants::order_tag_count
            u32mod
            exec.constants::set_order_tag
            exec.constraints_eval::execute_constraint_evaluation_check
        end

        begin
            adv_push exec.constants::set_number_queries
            adv_push exec.constants::set_query_pow_bits
            adv_push exec.constants::set_deep_pow_bits
            adv_push exec.constants::set_folding_pow_bits

            exec.vm::init_miden_air_shape_state

            procref.deep_queries::compute_deep_composition_polynomial_queries
            procref.wrong_constraints_eval
            procref.ood_frames::process_row_ood_evaluations
            procref.public_inputs::process_public_inputs
            procref.aux_trace::observe_aux_trace

            exec.verifier::verify
        end
        ";

    let test = build_test!(
        source,
        &data.initial_stack,
        &data.advice_stack,
        data.store.clone(),
        data.advice_map
    );
    assert!(test.execute_for_output().is_err(), "wrong order tag should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_registry() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let registry_root = Word::new(config::RELATION_DIGEST);
    let mut store = MerkleStore::new();
    store.extend(data.store.inner_nodes().filter(|node| node.value != registry_root));
    data.store = store;

    assert_recursive_verifier_rejects(data, "missing ACE registry should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let order = expected_order_from_shape(&data);
    let circuit_key = Word::new(config::ACE_CIRCUIT_REGISTRY_LEAVES[order.tag() as usize]);
    data.advice_map.retain(|(key, _)| *key != circuit_key);

    assert_recursive_verifier_rejects(data, "missing ACE circuit stream should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_corrupted_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let order = expected_order_from_shape(&data);
    let circuit_key = Word::new(config::ACE_CIRCUIT_REGISTRY_LEAVES[order.tag() as usize]);
    let (_, stream) = data
        .advice_map
        .iter_mut()
        .find(|(key, _)| *key == circuit_key)
        .expect("advice map must include the selected ACE circuit stream");
    stream[0] += Felt::ONE;

    assert_recursive_verifier_rejects(data, "corrupted ACE circuit stream should fail");
}

fn assert_recursive_verifier_rejects(data: VerifierData, message: &str) {
    let source = "
        use miden::core::sys::vm
        begin
            exec.vm::verify_proof
        end
        ";
    let test = build_test!(
        source,
        &data.initial_stack,
        &data.advice_stack,
        data.store.clone(),
        data.advice_map
    );

    assert!(test.execute_for_output().is_err(), "{message}");
}

pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> VerifierData {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let mut parser = Module::parser(Some(ModuleKind::Kernel));
                let kernel =
                    parser.parse_str(Some(Path::KERNEL), kernel, source_manager.clone()).unwrap();
                let kernel_lib = Assembler::new(source_manager.clone())
                    .assemble_kernel("kernel", kernel, None)
                    .map(Arc::<Package>::from)
                    .unwrap();
                let assembler = Assembler::with_kernel(source_manager, kernel_lib.clone()).unwrap();
                let program: Program =
                    assembler.assemble_program("program", source).unwrap().unwrap_program();
                (program, Some(kernel_lib))
            },
            None => {
                let program: Program = Assembler::new(source_manager)
                    .assemble_program("program", source)
                    .unwrap()
                    .unwrap_program();
                (program, None)
            },
        }
    };
    let stack_inputs = stack_inputs_from_ints(stack_inputs);
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    if let Some(ref kernel_lib) = kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    let options = ProvingOptions::new(HashFunction::Eidos);

    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .unwrap();

    let program_info = ProgramInfo::from(program);

    // Build public inputs and generate the advice data needed for recursive verification.
    let pub_inputs = PublicInputs::new(
        program_info,
        stack_inputs,
        stack_outputs,
        PrecompileTranscriptState::default(),
    );
    let (_, proof_bytes, _precompile_requests) = proof.into_parts();
    generate_advice_inputs(&proof_bytes, pub_inputs).unwrap()
}

/// Run the recursive verifier MASM program with the given VerifierData.
fn run_recursive_verifier(data: &VerifierData) -> ProofOrder {
    let source = "
        use miden::core::sys::vm
        begin
            exec.vm::verify_proof
        end
        ";
    let test = build_test!(
        source,
        &data.initial_stack,
        &data.advice_stack,
        data.store.clone(),
        data.advice_map.clone()
    );
    let (output, _host) = test.execute_for_output().expect("recursive verifier execution failed");

    // Cross-check: extract READ section, sanity-check values, evaluate circuit in Rust.
    ace_read_check::cross_check_ace_circuit(&output)
}

fn expected_order_from_shape(data: &VerifierData) -> ProofOrder {
    ProofOrder::from_instance_log_heights(&[
        shape_log(data, 0),
        shape_log(data, 1),
        shape_log(data, 2),
        AND8_LOOKUP_LOG_HEIGHT as u8,
    ])
}

fn shape_log(data: &VerifierData, offset: usize) -> u8 {
    let index = SECURITY_PARAMS_LEN + offset;
    data.advice_stack[index] as u8
}

// EXAMPLE PROGRAMS
// ================================================================================================

/// repeat.320 -> log_trace_height=10 -> FRI remainder degree < 64 -> verify_64 path
const EXAMPLE_FIB_SMALL: &str = "begin
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// repeat.400 -> log_trace_height=11 -> FRI remainder degree < 128 -> verify_128 path
const EXAMPLE_FIB_LARGE: &str = "begin
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

const EXAMPLE_EQUAL_HEIGHTS: &str = "begin push.1 drop end";

/// Like EXAMPLE_FIB_SMALL but with a syscall, for kernel-aware tests.
const EXAMPLE_FIB_KERNEL_SMALL: &str = "begin
        syscall.foo
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// Like EXAMPLE_FIB_LARGE but with a syscall, for kernel-aware flipped-order tests.
const EXAMPLE_FIB_KERNEL_LARGE: &str = "begin
        syscall.foo
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

// VARIABLE LENGTH PUBLIC INPUTS TESTS
// ================================================================================================

#[test]
fn miden_air_shape_accepts_valid_logs() {
    let shape = miden_air_shape_advice(10, 10, 10);
    assert!(shape_init_succeeds(&shape));
}

#[test]
fn order_tag_derivation_matches_rust_for_height_orderings() {
    let mut representatives = [None; 24];

    for log_core in 6..=29 {
        for log_chiplets in 6..=29 {
            for log_blakeg in 6..=29 {
                let logs = [log_core, log_chiplets, log_blakeg, AND8_LOOKUP_LOG_HEIGHT];
                let order = ProofOrder::from_instance_log_heights(&logs.map(|log| log as u8));
                representatives[order.tag() as usize].get_or_insert(logs);
            }
        }
    }

    for (tag, logs) in representatives.into_iter().enumerate() {
        let logs = logs.unwrap_or_else(|| panic!("no representative logs for order tag {tag}"));
        let (cached_logs, masm_tag) = masm_shape_state_from_advice(logs);

        assert_eq!(cached_logs, logs, "cached shape mismatch for advice {logs:?}");
        assert_eq!(masm_tag, tag as u32, "order tag mismatch for log heights {logs:?}");
    }
}

#[rstest]
#[case::low_core_height(0, 5)]
#[case::high_core_height(0, 30)]
#[case::low_chiplets_height(1, 5)]
#[case::high_chiplets_height(1, 30)]
#[case::low_blakeg_height(2, 5)]
#[case::high_blakeg_height(2, 30)]
fn miden_air_shape_rejects_malformed_fields(#[case] index: usize, #[case] value: u64) {
    let mut shape = miden_air_shape_advice(10, 10, 10);
    shape[index] = value;

    assert!(!shape_init_succeeds(&shape));
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
#[case(255)]
fn variable_length_public_inputs(#[case] num_kernel_proc_digests: usize) {
    let log_core_trace_length = 10_u64;
    let log_chiplets_trace_length = 10_u64;
    let log_blakeg_compression_trace_length = 10_u64;
    let initial_stack = vec![];

    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate fixed-length public inputs
    let input_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u32() as u64);
    let output_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u32() as u64);
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u32() as u64);

    let fixed_length_public_inputs =
        fixed_public_inputs(&program_digest, &input_operand_stack, &output_operand_stack);

    // 2) Generate the variable-length public inputs (kernel procedure digests)
    let kernel_procedures_digests =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);

    // 3) Generate the auxiliary randomness
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u32() as u64);

    // 4) Build the advice stack
    let mut advice_stack = miden_air_shape_advice(
        log_core_trace_length,
        log_chiplets_trace_length,
        log_blakeg_compression_trace_length,
    )
    .to_vec();
    advice_stack.extend_from_slice(&fixed_length_public_inputs);
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    // 5) Compute the expected reduced value
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);

    let reduced_value = reduce_kernel_procedures_digests(&kernel_procedures_digests, alpha, beta);
    let coeffs: &[Felt] = reduced_value.as_basis_coefficients_slice();

    // 6) Run process_public_inputs and verify the reduced value in memory
    let source = "
        use miden::core::sys::vm
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs

        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.12 exec.constants::set_deep_pow_bits
            push.4 exec.constants::set_folding_pow_bits
            exec.vm::init_miden_air_shape_state
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
        ";

    let test = build_test!(source, &initial_stack, &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    use miden_processor::ContextId;
    let ctx = ContextId::root();

    // Read reduced kernel value from var_len_ptr (in ACE READ section).
    // Must match `VARIABLE_LEN_PUBLIC_INPUTS_ADDRESS_PTR` in
    // `crates/lib/core/asm/stark/constants.masm`.
    let var_len_addr_ptr = 3223322670_u32;
    let var_len_ptr = output
        .memory
        .read_element(ctx, Felt::from_u32(var_len_addr_ptr))
        .unwrap()
        .as_canonical_u64() as u32;
    let masm_0 = output.memory.read_element(ctx, Felt::from_u32(var_len_ptr)).unwrap();
    let masm_1 = output.memory.read_element(ctx, Felt::from_u32(var_len_ptr + 1)).unwrap();

    assert_eq!(
        masm_0.as_canonical_u64(),
        coeffs[0].as_canonical_u64(),
        "kernel_reduced coord 0 mismatch (nk={num_kernel_proc_digests})"
    );
    assert_eq!(
        masm_1.as_canonical_u64(),
        coeffs[1].as_canonical_u64(),
        "kernel_reduced coord 1 mismatch (nk={num_kernel_proc_digests})"
    );
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(8)]
#[case(255)]
fn public_input_transcript_matches_rust_challenger(#[case] num_kernel_proc_digests: usize) {
    const RANDOM_COIN_BUFFER_LEN_PTR: u32 = 3223322760;
    const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3223322761;
    const ABSORB_SCRATCH_PTR: u32 = 3223324000;
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let log_core_trace_length = 10_u64;
    let log_chiplets_trace_length = 11_u64;
    let log_blakeg_compression_trace_length = 12_u64;
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let program_digest: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let input_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u32() as u64);
    let output_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u32() as u64);
    let fixed_length_public_inputs =
        fixed_public_inputs(&program_digest, &input_operand_stack, &output_operand_stack);

    let kernel_digest_advice =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u32() as u64);
    let main_trace_commitment: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);

    let mut advice_stack = miden_air_shape_advice(
        log_core_trace_length,
        log_chiplets_trace_length,
        log_blakeg_compression_trace_length,
    )
    .to_vec();
    advice_stack.extend_from_slice(&fixed_length_public_inputs);
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_digest_advice);
    advice_stack.extend_from_slice(&auxiliary_rand_values);
    advice_stack.extend_from_slice(&main_trace_commitment);

    let source = "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm::public_inputs

        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.12 exec.constants::set_deep_pow_bits
            push.4 exec.constants::set_folding_pow_bits
            exec.vm::init_miden_air_shape_state
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
            padw adv_loadw
            exec.constants::main_trace_com_ptr mem_storew_le
            exec.random_coin::reseed_main_after_shape
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let test = build_test!(source, &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = config::eidos_config(config::pcs_params());
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    let air_inputs = fixed_length_public_inputs
        .iter()
        .copied()
        .map(Felt::new_unchecked)
        .collect::<Vec<_>>();
    let aux_inputs = natural_kernel_digest_felts(&kernel_digest_advice);
    let log_heights = [
        log_core_trace_length as u8,
        log_chiplets_trace_length as u8,
        log_blakeg_compression_trace_length as u8,
        AND8_LOOKUP_LOG_HEIGHT as u8,
    ];
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        air_inputs,
        aux_inputs,
    )
    .expect("valid statement");

    let preprocessed = Preprocessed::build(&statement, &config).expect("AND8 setup is present");
    let preprocessed_commitment: [u64; WORD_SIZE] = preprocessed.commitment().into();
    for &element in &preprocessed_commitment {
        challenger.observe(Felt::new_unchecked(element));
    }
    statement.observe(&mut challenger, &log_heights);
    challenger.observe(Felt::new_unchecked(4));
    for &log_height in &log_heights {
        challenger.observe(Felt::new_unchecked(log_height as u64));
    }
    for &element in &main_trace_commitment {
        challenger.observe(Felt::new_unchecked(element));
    }
    let expected_word = challenger.squeeze_word();

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(SQUEEZED_WORD_PTR),
        read(SQUEEZED_WORD_PTR + 1),
        read(SQUEEZED_WORD_PTR + 2),
        read(SQUEEZED_WORD_PTR + 3),
    ];

    let kernel_felts_len = 4 * num_kernel_proc_digests;
    let mut expected_stream =
        Vec::with_capacity(STATEMENT_DESCRIPTOR_LEN + NUM_PUBLIC_VALUES + kernel_felts_len);
    expected_stream.push(Felt::new_unchecked(NUM_PUBLIC_VALUES as u64));
    expected_stream.push(Felt::new_unchecked(NUM_VAR_LEN_PUBLIC_INPUT_GROUPS as u64));
    expected_stream.push(Felt::new_unchecked(kernel_felts_len as u64));
    expected_stream.push(Felt::ZERO);
    expected_stream.extend(fixed_length_public_inputs.iter().copied().map(Felt::new_unchecked));
    expected_stream.extend(natural_kernel_digest_felts(&kernel_digest_advice));
    for (i, expected) in expected_stream.iter().enumerate() {
        assert_eq!(
            read(ABSORB_SCRATCH_PTR + i as u32),
            *expected,
            "scratch stream mismatch at offset {i}"
        );
    }

    assert_eq!(masm_word, expected_word.as_elements());
    assert_eq!(read(RANDOM_COIN_BUFFER_LEN_PTR), Felt::ZERO);
    assert_eq!(read(RANDOM_COIN_OUTPUT_LEN_PTR), Felt::ZERO);
}

#[test]
fn eidos_init_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let source = "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.12 exec.constants::set_deep_pow_bits
            push.4 exec.constants::set_folding_pow_bits
            exec.vm::init_miden_air_shape_state
            exec.random_coin::init_seed
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let shape = miden_air_shape_advice(10, 11, 12);
    let test = build_test!(source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = config::eidos_config(config::pcs_params());
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);
    let expected_word = challenger.squeeze_word();

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(SQUEEZED_WORD_PTR),
        read(SQUEEZED_WORD_PTR + 1),
        read(SQUEEZED_WORD_PTR + 2),
        read(SQUEEZED_WORD_PTR + 3),
    ];

    assert_eq!(masm_word, expected_word.as_elements());
}

#[test]
fn eidos_relation_digest_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let source = "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            exec.vm::init_miden_air_shape_state
            push.6225836997093344009.6615246172502583955.3539038439026260303.4361500420518448919
            padw exec.constants::relation_digest_ptr mem_loadw_le
            exec.random_coin::eidos_init_challenger
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let shape = miden_air_shape_advice(10, 11, 12);
    let test = build_test!(source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = config::eidos_config(config::pcs_params());
    let mut challenger = config.challenger();
    let expected_word = challenger.squeeze_word();

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(SQUEEZED_WORD_PTR),
        read(SQUEEZED_WORD_PTR + 1),
        read(SQUEEZED_WORD_PTR + 2),
        read(SQUEEZED_WORD_PTR + 3),
    ];

    assert_eq!(masm_word, expected_word.as_elements());
}

#[test]
fn eidos_absorb_block_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants

        begin
            push.13.12.11.10 exec.constants::random_coin_cv_ptr mem_storew_le
            dropw
            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let test = build_test!(source, &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let init_cv = miden_core::Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
    ]);
    let mut challenger = miden_crypto::hash::eidos::MidenEidosChallenger::from_cv(init_cv);
    challenger.absorb_raw_block([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ]);
    let expected_word = challenger.squeeze_word();

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(SQUEEZED_WORD_PTR),
        read(SQUEEZED_WORD_PTR + 1),
        read(SQUEEZED_WORD_PTR + 2),
        read(SQUEEZED_WORD_PTR + 3),
    ];

    assert_eq!(masm_word, expected_word.as_elements());
}

#[test]
fn eidos_hash_elements_single_block_matches_masm_bcompress_loop() {
    const HASH_WORD_PTR: u32 = 1000;

    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, 8);
    let init = init_cv.as_elements();
    let source = format!(
        "
        begin
            push.{cv3}.{cv2}.{cv1}.{cv0}
            push.8.7.6.5
            push.4.3.2.1
            bcompress
            dropw dropw
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init[0].as_canonical_u64(),
        cv1 = init[1].as_canonical_u64(),
        cv2 = init[2].as_canonical_u64(),
        cv3 = init[3].as_canonical_u64(),
    );

    let test = build_test!(&source, &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let elements = (1..=8).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(HASH_WORD_PTR),
        read(HASH_WORD_PTR + 1),
        read(HASH_WORD_PTR + 2),
        read(HASH_WORD_PTR + 3),
    ];

    assert_eq!(masm_word, expected_word.as_elements());
}

#[test]
fn eidos_hash_elements_adv_pipe_loop_matches_masm_bcompress_loop() {
    const HASH_WORD_PTR: u32 = 1000;
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, elements.len() as u32);
    let init = init_cv.as_elements();
    let mut advice_builder = AdviceStackBuilder::new();
    advice_builder.push_for_adv_pipe(&elements);
    let advice_stack = advice_builder.build_vec_u64();

    let source = format!(
        "
        begin
            push.{STREAM_PTR}
            push.{cv3}.{cv2}.{cv1}.{cv0}
            padw padw
            repeat.2
                adv_pipe
                bcompress
            end
            dropw dropw
            movup.4 drop
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init[0].as_canonical_u64(),
        cv1 = init[1].as_canonical_u64(),
        cv2 = init[2].as_canonical_u64(),
        cv3 = init[3].as_canonical_u64(),
    );

    let test = build_test!(&source, &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    let masm_word = [
        read(HASH_WORD_PTR),
        read(HASH_WORD_PTR + 1),
        read(HASH_WORD_PTR + 2),
        read(HASH_WORD_PTR + 3),
    ];

    assert_eq!(masm_word, expected_word.as_elements());
}

#[test]
fn eidos_hash_elements_advice_map_loop_matches_masm_bcompress_loop() {
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);
    let key = expected_word.as_elements();
    let map_values = elements
        .iter()
        .map(Felt::as_canonical_u64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, elements.len() as u32);
    let init = init_cv.as_elements();

    let source = format!(
        "
        adv_map HASH_OUTPUT([{key0}, {key1}, {key2}, {key3}]) = [
            {map_values}
        ]

        begin
            push.HASH_OUTPUT
            adv.push_mapval
            push.{STREAM_PTR}
            push.{cv3}.{cv2}.{cv1}.{cv0}
            padw padw
            repeat.2
                adv_pipe
                bcompress
            end
            dropw dropw
            movup.4 drop
            assert_eqw
        end
        ",
        key0 = key[0].as_canonical_u64(),
        key1 = key[1].as_canonical_u64(),
        key2 = key[2].as_canonical_u64(),
        key3 = key[3].as_canonical_u64(),
        map_values = map_values,
        cv0 = init[0].as_canonical_u64(),
        cv1 = init[1].as_canonical_u64(),
        cv2 = init[2].as_canonical_u64(),
        cv3 = init[3].as_canonical_u64(),
    );

    let test = build_test!(&source, &[]);
    test.execute().expect("execution failed");
}

#[test]
fn variable_length_public_inputs_rejects_too_many_kernel_proc_digests() {
    let mut advice_stack = miden_air_shape_advice(10, 10, 10).to_vec();
    advice_stack.extend_from_slice(&[0_u64; NUM_PUBLIC_VALUES]);
    advice_stack.push(256);

    let source = "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm::public_inputs

        begin
            push.27 exec.constants::set_number_queries
            push.16 exec.constants::set_query_pow_bits
            push.12 exec.constants::set_deep_pow_bits
            push.4 exec.constants::set_folding_pow_bits
            exec.vm::init_miden_air_shape_state
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
        ";

    let test = build_test!(source, &[], &advice_stack);
    assert!(
        test.execute_for_output().is_err(),
        "kernel procedure digest count above MultiAir::max_aux_inputs should fail"
    );
}

// HELPERS
// ===============================================================================================

fn miden_air_shape_advice(
    log_core: u64,
    log_chiplets: u64,
    log_blakeg_compression: u64,
) -> [u64; 3] {
    [log_core, log_chiplets, log_blakeg_compression]
}

fn shape_init_succeeds(shape: &[u64]) -> bool {
    let source = "
        use miden::core::sys::vm

        begin
            exec.vm::init_miden_air_shape_state
        end
        ";
    let test = build_test!(source, &[], shape);

    test.execute().is_ok()
}

fn masm_shape_state_from_advice(logs: [u64; 4]) -> ([u64; 4], u32) {
    let source = format!(
        "
        use miden::core::stark::constants
        use miden::core::sys::vm

        begin
            exec.vm::init_miden_air_shape_state
            exec.constants::get_core_trace_length_log push.{SHAPE_TEST_OUTPUT_PTR} mem_store
            exec.constants::get_chiplets_trace_length_log push.{chiplets_ptr} mem_store
            exec.constants::get_blakeg_compression_trace_length_log push.{blakeg_ptr} mem_store
            exec.constants::get_and8_lookup_trace_length_log push.{and8_ptr} mem_store
            exec.constants::get_order_tag push.{tag_ptr} mem_store
        end
        ",
        chiplets_ptr = SHAPE_TEST_OUTPUT_PTR + 1,
        blakeg_ptr = SHAPE_TEST_OUTPUT_PTR + 2,
        and8_ptr = SHAPE_TEST_OUTPUT_PTR + 3,
        tag_ptr = SHAPE_TEST_OUTPUT_PTR + 4,
    );
    let shape = miden_air_shape_advice(logs[0], logs[1], logs[2]);
    let test = build_test!(&source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("shape init should succeed");

    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");

    (
        [
            read(SHAPE_TEST_OUTPUT_PTR).as_canonical_u64(),
            read(SHAPE_TEST_OUTPUT_PTR + 1).as_canonical_u64(),
            read(SHAPE_TEST_OUTPUT_PTR + 2).as_canonical_u64(),
            read(SHAPE_TEST_OUTPUT_PTR + 3).as_canonical_u64(),
        ],
        read(SHAPE_TEST_OUTPUT_PTR + 4).as_canonical_u64() as u32,
    )
}

fn fixed_public_inputs(
    program_digest: &[u64; WORD_SIZE],
    input_operand_stack: &[u64; 16],
    output_operand_stack: &[u64; 16],
) -> Vec<u64> {
    let mut values = program_digest.to_vec();
    values.extend_from_slice(input_operand_stack);
    values.extend_from_slice(output_operand_stack);
    values.resize(values.len().next_multiple_of(8), 0);
    values
}

fn natural_kernel_digest_felts(kernel_digest_advice: &[u64]) -> Vec<Felt> {
    kernel_digest_advice
        .chunks(2 * WORD_SIZE)
        .flat_map(|digest| {
            [
                Felt::new_unchecked(digest[7]),
                Felt::new_unchecked(digest[6]),
                Felt::new_unchecked(digest[5]),
                Felt::new_unchecked(digest[4]),
            ]
        })
        .collect()
}

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
        let digest: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
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
    // kernel_corr = sum_i 1 / term_i. The chiplet removes and the boundary adds, so there is no
    // negation.
    kernel_procedures_digests
        .chunks(2 * WORD_SIZE)
        .map(|digest| reduce_digest(digest, alpha, beta))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        })
}

fn reduce_digest(digest: &[u64], alpha: QuadFelt, beta: QuadFelt) -> QuadFelt {
    // gamma = beta^MAX_MESSAGE_WIDTH = beta^16
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    // KERNEL_ROM_INIT = 0, so bus_prefix = alpha + (0+1) * gamma = alpha + gamma
    let bus_prefix = alpha + gamma;
    // Horner evaluation matches MASM `horner_eval_base` over the 8-element reversed digest.
    bus_prefix
        + digest.iter().fold(QuadFelt::ZERO, |acc, coef| {
            acc * beta + QuadFelt::from(Felt::new_unchecked(*coef))
        })
}

// CONSTANTS
// ===============================================================================================

const KERNEL_SINGLE_PROC: &str = r#"
        pub proc foo
            add
        end"#;

const KERNEL_EVEN_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end"#;

const KERNEL_ODD_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end
        pub proc baz
            mul
        end"#;
