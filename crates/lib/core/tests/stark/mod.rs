use std::{array, fmt::Write as _, sync::Arc};

use miden_air::{MIDEN_AIR_COUNT, MidenMultiAir, NUM_PUBLIC_VALUES, ProofOrder, Statement, config};
use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    program::{ExecutionClaim, KERNEL_DOMAIN_TAG, KernelDescriptor, NUM_CLAIM_ELEMENTS},
    proof::HashFunction,
};
use miden_crypto::stark::{
    Preprocessed, StarkConfig,
    challenger::{CanObserve, FieldChallenger},
};
use miden_mast_package::Package;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, Program, ProgramInfo};
use miden_utils_testing::{
    AdviceInputs, Prover,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;
mod pvm_aux_trace;
mod pvm_deep_queries;
mod pvm_ood_frames;
mod pvm_public_inputs;
mod pvm_settlement;
mod pvm_verifier;
mod pvm_wrapper;
mod security;
mod security_math;

fn pvm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/pvm/layout.masm");
    let prefix = format!("const {name} = ");
    let value = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix)?.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("missing generated PVM layout constant {name}"));
    u32::try_from(value).expect("PVM layout pointer must fit in u32")
}

fn vm_layout_const(name: &str) -> u32 {
    let source = include_str!("../../asm/sys/vm/layout.masm");
    let prefix = format!("const {name} = ");
    let value = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix)?.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("missing generated VM layout constant {name}"));
    u32::try_from(value).expect("VM layout pointer must fit in u32")
}

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_large() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_even() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_EVEN_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_odd() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_ODD_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_single() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_max_kernel() {
    let kernel = max_kernel_source();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(&kernel),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_deferred_root() {
    let data =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    run_recursive_verifier(&data);
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

/// Executes the MASM proof-order dispatch for every Lehmer tag and compares its result with the
/// Rust protocol decoder. This directly covers all 24 branches that order the normalized LogUp
/// boundary values.
#[test]
fn aux_trace_proof_order_dispatch_matches_every_rust_variant() {
    const INSTANCE_LOG_HEIGHTS: [u64; MIDEN_AIR_COUNT] = [10, 11, 12, 13];
    const ORDER_OUTPUT_PTR: u32 = 1000;

    for tag in 0..miden_air::PROOF_ORDER_COUNT as u32 {
        let source = format!(
            "
            use miden::core::stark::constants
            use miden::core::sys::vm::aux_trace
            use miden::core::sys::vm::layout

            begin
                push.{core} exec.layout::set_core_trace_length_log
                push.{chiplets} exec.layout::set_chiplets_trace_length_log
                push.{eidos_compression} exec.layout::set_eidos_compression_trace_length_log
                push.{and8} exec.layout::set_and8_lookup_trace_length_log
                push.{tag} exec.constants::set_order_tag
                exec.aux_trace::push_proof_order_log_heights
                push.{output_ptr} mem_store
                push.{output_ptr_plus_1} mem_store
                push.{output_ptr_plus_2} mem_store
                push.{output_ptr_plus_3} mem_store
            end
            ",
            core = INSTANCE_LOG_HEIGHTS[0],
            chiplets = INSTANCE_LOG_HEIGHTS[1],
            eidos_compression = INSTANCE_LOG_HEIGHTS[2],
            and8 = INSTANCE_LOG_HEIGHTS[3],
            output_ptr = ORDER_OUTPUT_PTR,
            output_ptr_plus_1 = ORDER_OUTPUT_PTR + 1,
            output_ptr_plus_2 = ORDER_OUTPUT_PTR + 2,
            output_ptr_plus_3 = ORDER_OUTPUT_PTR + 3,
        );
        let test = build_test!(source.as_str(), &[]);
        let (output, _host) = test
            .execute_for_output()
            .unwrap_or_else(|err| panic!("MASM proof-order dispatch failed for tag {tag}: {err}"));
        let order = ProofOrder::from_tag(tag).expect("tag is in range");
        let actual_order = read_word(&output, ORDER_OUTPUT_PTR);

        for (stack_idx, air) in order.airs().iter().copied().enumerate() {
            let actual = actual_order[stack_idx].as_canonical_u64();
            assert_eq!(
                actual,
                INSTANCE_LOG_HEIGHTS[air.instance_index()],
                "MASM/Rust proof-order mismatch at tag {tag}, stack index {stack_idx}",
            );
        }
    }
}

#[test]
fn stark_verifier_e2f4_rejects_wrong_order_tag() {
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, fib_stack_inputs(), None);
    assert_ne!(expected_order_from_shape(&data), ProofOrder::instance_order());

    // Mirror `verify_vm_proof`'s staging, but flip the derived order tag before dispatching the
    // constraint evaluation check. The registry then selects a different circuit commitment, so
    // circuit lookup/authentication cannot succeed.
    let source = format!(
        "
        use miden::core::mem
        use miden::core::stark::constants
        use miden::core::stark::verifier

        use miden::core::sys::vm
        use miden::core::sys::vm::aux_trace
        use miden::core::sys::vm::claim
        use miden::core::sys::vm::constraints_eval
        use miden::core::sys::vm::deep_queries
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::ood_frames
        use miden::core::sys::vm::public_inputs

        const KERNEL_DOMAIN_TAG = {kernel_domain_tag}

        proc wrong_constraints_eval
            # Flip the derived tag, then dispatch to the wrong order-specific circuit.
            exec.constants::get_order_tag
            add.1
            push.24
            u32mod
            exec.constants::set_order_tag
            exec.constraints_eval::execute_constraint_evaluation_check
        end

        # Same staging as the private `verify_vm_proof` kernel-witness helper.
        proc materialize_kernel_witness
            padw exec.layout::claim_ptr add.4 mem_loadw_le
            adv.push_mapvaln
            adv_push
            u32assert
            dup u32mod.4 assertz
            div.4
            dup u32lte.255 assert
            dup exec.layout::num_kernel_procedures_ptr mem_store
            exec.layout::kernel_witness_ptr swap
            push.KERNEL_DOMAIN_TAG
            exec.mem::pipe_words_to_memory_in_domain
            movup.4 drop
            assert_eqw
        end

        begin
            # Initial stack: [CLAIM_COMMITMENT].
            exec.layout::claim_commitment_ptr mem_storew_le
            exec.layout::claim_ptr exec.claim::materialize_claim

            adv_push exec.constants::set_number_queries
            adv_push exec.constants::set_query_pow_bits
            adv_push exec.constants::set_deep_pow_bits
            adv_push exec.constants::set_folding_pow_bits

            exec.materialize_kernel_witness
            exec.public_inputs::stage_boundary_inputs
            exec.vm::load_air_context

            procref.deep_queries::compute_deep_composition_polynomial_queries
            procref.wrong_constraints_eval
            procref.ood_frames::process_row_ood_evaluations
            procref.public_inputs::process_public_inputs
            procref.aux_trace::observe_aux_trace

            exec.verifier::verify
        end
        ",
        kernel_domain_tag = KERNEL_DOMAIN_TAG.as_canonical_u64(),
    );

    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map
    );
    assert!(test.execute_for_output().is_err(), "wrong order tag should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_registry() {
    use miden_utils_testing::crypto::MerkleStore;

    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let registry_root = Word::new(config::ACE_CIRCUIT_REGISTRY_ROOT);
    let mut store = MerkleStore::new();
    store.extend(data.store.inner_nodes().filter(|node| node.value != registry_root));
    data.store = store;

    assert_recursive_verifier_rejects(data, "missing ACE registry should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_missing_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let order = expected_order_from_shape(&data);
    let circuit_key = recursive_circuit_key(&order);
    data.advice_map.retain(|(key, _)| *key != circuit_key);

    assert_recursive_verifier_rejects(data, "missing ACE circuit stream should fail");
}

#[test]
fn stark_verifier_e2f4_rejects_corrupted_ace_circuit_stream() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let order = expected_order_from_shape(&data);
    let circuit_key = recursive_circuit_key(&order);
    let stream = advice_map_value_mut(&mut data, circuit_key);
    stream[0] += Felt::ONE;

    assert_recursive_verifier_rejects(data, "corrupted ACE circuit stream should fail");
}

fn assert_recursive_verifier_rejects(data: VerifierData, message: &str) {
    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map
    );

    assert!(test.execute_for_output().is_err(), "{message}");
}

#[test]
fn folding_reseed_helper_matches_reference_sampler() {
    fn source(use_combined_helper: bool, pow_bits: usize) -> String {
        let sample = if use_combined_helper {
            "
            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            "
        } else {
            "
            push.41.31.29.23 push.0
            exec.random_coin::reseed_with_felt
            exec.random_coin::sample_folding_pow_and_ext
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.{pow_bits} exec.constants::set_folding_pow_bits
                push.109.113.127.131 exec.constants::random_coin_cv_ptr mem_storew_le dropw
                exec.random_coin::eidos_clear_buffer
                push.0 exec.constants::random_coin_counter_ptr mem_store
                push.0 exec.constants::random_coin_output_len_ptr mem_store

                {sample}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.constants::random_coin_counter_ptr mem_load
                exec.constants::random_coin_buffer_len_ptr mem_load
                padw exec.constants::random_coin_output_word_ptr mem_loadw_le
                padw exec.constants::random_coin_cv_ptr mem_loadw_le
                exec.sys::truncate_stack
            end
            "
        )
    }

    for pow_bits in [0, 1] {
        let (reference, _) = build_test!(&source(false, pow_bits), &[])
            .execute_for_output()
            .unwrap_or_else(|err| {
                panic!("reference sampler should execute with pow_bits={pow_bits}: {err:?}")
            });
        let (combined, _) = build_test!(&source(true, pow_bits), &[])
            .execute_for_output()
            .unwrap_or_else(|err| {
                panic!("combined sampler should execute with pow_bits={pow_bits}: {err:?}")
            });

        assert_eq!(
            combined.stack.get_num_elements(15),
            reference.stack.get_num_elements(15),
            "combined FRI reseed helper diverged from reference sampler with pow_bits={pow_bits}"
        );
    }
}

#[test]
fn folding_reseed_rejects_nonempty_buffer() {
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.1 exec.constants::set_folding_pow_bits
            push.109.113.127.131 exec.constants::random_coin_cv_ptr mem_storew_le dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(
        test,
        "reseed_with_folding_pow_and_ext: buffer must be empty"
    );
}

#[test]
fn zero_pow_folding_reseed_accepts_nonempty_buffer() {
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.0 exec.constants::set_folding_pow_bits
            push.109.113.127.131 exec.constants::random_coin_cv_ptr mem_storew_le dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.41.31.29.23 push.0
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            drop drop
        end
        ";

    build_test!(source, &[])
        .execute()
        .expect("zero-PoW reseed should flush a partial buffer");
}

#[test]
fn word_observe_helper_matches_scalar_observe() {
    fn source(use_word_helpers: bool) -> String {
        let observe = if use_word_helpers {
            "
            push.11.7.5.3
            exec.random_coin::observe_word
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        } else {
            "
            push.3 exec.random_coin::observe_felt
            push.5 exec.random_coin::observe_felt
            push.7 exec.random_coin::observe_felt
            push.11 exec.random_coin::observe_felt
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 exec.constants::random_coin_cv_ptr mem_storew_le dropw
                exec.random_coin::eidos_clear_buffer
                push.0 exec.constants::random_coin_counter_ptr mem_store
                push.0 exec.constants::random_coin_output_len_ptr mem_store

                {observe}
                exec.random_coin::sample_felt

                exec.constants::random_coin_output_len_ptr mem_load
                exec.constants::random_coin_counter_ptr mem_load
                exec.constants::random_coin_buffer_len_ptr mem_load
                padw exec.constants::random_coin_output_word_ptr mem_loadw_le
                padw exec.constants::random_coin_cv_ptr mem_loadw_le
                exec.sys::truncate_stack
            end
            "
        )
    }

    let (reference, _) = build_test!(&source(false), &[])
        .execute_for_output()
        .expect("scalar observe path should execute");
    let (optimized, _) = build_test!(&source(true), &[])
        .execute_for_output()
        .expect("word observe path should execute");

    assert_eq!(
        optimized.stack.get_num_elements(13),
        reference.stack.get_num_elements(13),
        "batched observe helpers changed random coin state"
    );
}

#[test]
fn observe_word_and_flush_buffer_matches_scalar_observe() {
    fn source(prefix_len: usize, use_word_helper: bool) -> String {
        let prefix = (0..prefix_len)
            .map(|idx| format!("push.{} exec.random_coin::observe_felt", idx + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let observe = if use_word_helper {
            "
            push.23.19.17.13
            exec.random_coin::observe_word_and_flush_buffer
            "
        } else {
            "
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            push.19 exec.random_coin::observe_felt
            push.23 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 exec.constants::random_coin_cv_ptr mem_storew_le dropw
                exec.random_coin::eidos_clear_buffer
                push.0 exec.constants::random_coin_counter_ptr mem_store
                push.0 exec.constants::random_coin_output_len_ptr mem_store

                {prefix}
                {observe}
                exec.random_coin::sample_felt

                exec.constants::random_coin_output_len_ptr mem_load
                exec.constants::random_coin_counter_ptr mem_load
                exec.constants::random_coin_buffer_len_ptr mem_load
                padw exec.constants::random_coin_output_word_ptr mem_loadw_le
                padw exec.constants::random_coin_cv_ptr mem_loadw_le
                exec.sys::truncate_stack
            end
            "
        )
    }

    for prefix_len in [0, 3, 4, 6] {
        let (reference, _) = build_test!(&source(prefix_len, false), &[])
            .execute_for_output()
            .expect("scalar observe path should execute");
        let (optimized, _) = build_test!(&source(prefix_len, true), &[])
            .execute_for_output()
            .expect("word observe path should execute");

        assert_eq!(
            optimized.stack.get_num_elements(13),
            reference.stack.get_num_elements(13),
            "word observe-and-flush helper changed random coin state with prefix_len={prefix_len}"
        );
    }
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> VerifierData {
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel = context.parse_kernel(source_file!(&context, kernel)).unwrap();
                let kernel_lib = Assembler::new(context.source_manager())
                    .assemble_kernel("kernel", kernel, None)
                    .map(Arc::<Package>::from)
                    .unwrap();
                let assembler =
                    Assembler::with_kernel(context.source_manager(), kernel_lib.clone()).unwrap();
                let program: Program =
                    assembler.assemble_program("program", source).unwrap().unwrap_program();
                (program, Some(kernel_lib))
            },
            None => {
                let program: Program = Assembler::default()
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

    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap();
    let witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new().with_hash_fn(HashFunction::Eidos).prove(witness).unwrap();

    let program_info = ProgramInfo::from(program);
    let claim = ExecutionClaim::from_program_info(program_info, stack_inputs, stack_outputs);

    generate_advice_inputs(vm_verify_proof_root(), &proof, &claim).unwrap()
}

/// Returns the MAST root used to identify `sys::vm::verify_proof` in proof-request keys.
///
/// Operators obtain it through `CoreLibrary::vm_recursive_verifier_root`. Consumers obtain the
/// same value in MASM with `procref.vm::verify_proof`; the root belongs to the procedure itself and
/// does not depend on the program that calls it.
fn vm_verify_proof_root() -> Word {
    miden_core_lib::CoreLibrary::default().vm_recursive_verifier_root()
}

/// Test helper that copies `count` felts (a multiple of 4) from advice into memory at `dst`.
pub(crate) const COPY_ADVICE_TO_MEM: &str = "
        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                padw adv_loadw
                dup.4 mem_storew_le dropw
                add.4
                swap sub.4 swap
                dup.1 push.0 neq
            end
            drop drop
        end
";

/// Builds the consumer program: stage the claim from the consumer's own inputs, derive its
/// commitment, fetch the proof package registered under
/// `proof_request_key(verifier_root, claim_commitment)`, verify it, compute its security level, and
/// enforce the consumer's threshold. `vm::verify_proof` contains neither the estimator nor the
/// policy.
fn request_consumer_source() -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        begin
            # 1) Fill the canonical claim encoding into VM memory from the consumer's own inputs
            #    (the advice tape) and derive the commitment that names it.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR}
            exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment
            # => [CLAIM_COMMITMENT]

            # 2) Fetch the registered proof package by content: request keys name
            #    vm::verify_proof's root, derived in-VM via procref.
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw
            # => [CLAIM_COMMITMENT]

            # 3) Verify the claim; vm::verify_proof returns the common security descriptor followed
            #    by the deferred obligation.
            exec.vm::verify_proof
            # => [security_descriptor, D]

            # 4) Compute the security level and enforce the consumer's threshold.
            exec.security::compute_conjectured_security_level
            # => [conjectured_level, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            # => [D]
            exec.sys::truncate_stack
        end
        "
    )
}

/// The end-to-end guarantee of fetching by content: a proof fetched via `proof_request_key` and
/// `adv.push_mapval` verifies when it matches the consumer's claim, and is rejected when it
/// does not. No separate binding check is needed for the fetched proof package.
#[test]
fn request_flow_binds_proof_to_claim() {
    use miden_utils_testing::recursive_verifier::proof_request_key;

    let intended = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);

    let source = request_consumer_source();
    let entry = |proof_stream: &[u64]| -> (Word, Vec<Felt>) {
        let felts: Vec<Felt> = proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        (proof_request_key(vm_verify_proof_root(), intended.claim_commitment), felts)
    };

    // Control: the intended proof, registered under its key, verifies.
    let (k, v) = entry(&intended.proof_stream);
    let mut advice_map = intended.advice_map.clone();
    advice_map.push((k, v));
    let ok = build_test!(
        source.as_str(),
        &[],
        &intended.claim_advice,
        intended.store.clone(),
        advice_map
    );
    let (output, _) = ok.execute_for_output().expect("the matching proof must verify");
    ace_read_check::cross_check_ace_circuit(&output);

    // Substitution: a different claim's proof under the same key fails against the consumer's
    // claim — the advice provider cannot pass off another proof. The intended claim's own
    // content-addressed entries stay available so the kernel-witness fetch succeeds and
    // rejection happens in verification, not because of a missing key.
    let other =
        generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, log_deferred_stack_inputs(), None);
    let (k, v) = entry(&other.proof_stream);
    let mut advice_map = other.advice_map.clone();
    advice_map.extend(intended.advice_map.iter().cloned());
    advice_map.push((k, v));
    let bad = build_test!(source.as_str(), &[], &intended.claim_advice, other.store, advice_map);
    assert!(
        bad.execute_for_output().is_err(),
        "a proof for a different claim must be rejected by verification"
    );
}

/// Two independently proven executions of one program (distinct stack i/o) verified inside a
/// single consumer program — each proof is registered
/// under `proof_request_key(verifier_root, claim_commitment)` and fetched by content, independent
/// of its position in the advice. The consumer stages each claim from its own inputs and derives
/// the commitment that names the claim and addresses its proof entry, so passing requires the
/// in-VM claim-commitment, kernel-commitment, and request-key derivations to match their native
/// mirrors (a mismatch is a missing advice-map key).
#[test]
fn stark_verifier_e2f4_request_multi_proof() {
    use miden_utils_testing::{crypto::MerkleStore, recursive_verifier::proof_request_key};

    let mut inputs = fib_stack_inputs();
    let tx0 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs.clone(), None);
    inputs[13] = 7; // distinct claim: same program, different stack inputs
    let tx1 = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);

    // One advice provider for both proofs: the tape carries the claims from which the consumer
    // derives the commitments. Claim preimages, proof streams, query rows, and kernel witnesses
    // are content-addressed in the advice map.
    let verifier_root = vm_verify_proof_root();
    let mut tape = Vec::new();
    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();
    for tx in [&tx0, &tx1] {
        tape.extend(tx.claim_advice.iter().copied());
        store.extend(tx.store.inner_nodes());
        advice_map.extend(tx.advice_map.iter().cloned());
        let stream: Vec<Felt> = tx.proof_stream.iter().map(|&v| Felt::new_unchecked(v)).collect();
        advice_map.push((proof_request_key(verifier_root, tx.claim_commitment), stream));
    }

    let source = format!(
        "
        use miden::core::sys
        use miden::core::stark::security
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        proc verify_one_claim
            # Per claim: stage the fields from the consumer's own inputs, derive the
            # commitment that names the claim, fetch and verify the proof package it
            # addresses, then compute the security level and enforce the acceptance threshold.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR} exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment # => [CLAIM_COMMITMENT]
            dupw
            procref.vm::verify_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw                        # => [CLAIM_COMMITMENT]
            exec.vm::verify_proof                        # => [security_descriptor, D]
            exec.security::compute_conjectured_security_level # => [level, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            # => [D]
        end

        begin
            exec.verify_one_claim dropw
            exec.verify_one_claim dropw
            exec.sys::truncate_stack
        end
        "
    );

    let test = build_test!(source.as_str(), &[], &tape, store, advice_map);
    test.execute_for_output().expect("both content-addressed proofs must verify");
}

/// Runs `vm::verify_proof` with the claim commitment on the operand stack and the proof stream on
/// advice. This directly pins the producer and MASM consumption order.
fn vm_verify_proof_program() -> String {
    "
        use miden::core::sys
        use miden::core::sys::vm

        begin
            exec.vm::verify_proof
            # => [security_descriptor, D]
            exec.sys::truncate_stack
        end
    "
    .into()
}

fn run_recursive_verifier(data: &VerifierData) -> ProofOrder {
    use miden_air::security;

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    let (output, _host) = test.execute_for_output().expect("recursive verifier execution failed");

    // Pin the full common descriptor and deferred root so any value or ordering drift is caught
    // across every end-to-end configuration.
    let params = config::pcs_params();
    let height_start = 4 + WORD_SIZE;
    let log_max_height = data.proof_stream[height_start..height_start + MIDEN_AIR_COUNT - 1]
        .iter()
        .copied()
        .chain([u64::from(AND8_LOOKUP_LOG_HEIGHT)])
        .max()
        .expect("the MVM relation has AIR instances");
    let kernel_commitment = claim_kernel_commitment(data);
    let num_kernel_procedures = data
        .advice_map
        .iter()
        .find(|(key, _)| *key == kernel_commitment)
        .map(|(_, values)| values.len() / WORD_SIZE)
        .expect("the authenticated kernel witness must be present");

    let mut expected = vec![
        u64::from(security::LOOKUP_POW_BITS),
        u64::from(security::AIR_SHAPE.num_composed_constraints),
        u64::from(security::AIR_SHAPE.max_constraint_degree),
        u64::from(security::AIR_SHAPE.num_deep_terms.unwrap()),
        u64::from(security::AIR_SHAPE.lookup.max_message_width),
        u64::from(security::CORE_BOUNDARY_LOOKUP_TERMS) + num_kernel_procedures as u64,
        u64::from(security::AIR_SHAPE.lookup.fractions_per_row),
        log_max_height,
        params.num_queries() as u64,
        params.query_pow_bits() as u64,
        params.deep_pow_bits() as u64,
        params.folding_pow_bits() as u64,
    ];
    expected.extend_from_slice(&data.proof_stream[4..4 + WORD_SIZE]);

    let returned: Vec<u64> = output
        .stack
        .get_num_elements(expected.len())
        .iter()
        .map(Felt::as_canonical_u64)
        .collect();
    assert_eq!(returned, expected, "vm::verify_proof returned the wrong security descriptor");

    ace_read_check::assert_proof_stream_read_sections(
        &output,
        &data.proof_stream,
        &data.claim_advice,
    );

    // Cross-check: extract READ section, sanity-check values, evaluate circuit in Rust.
    ace_read_check::cross_check_ace_circuit(&output)
}

/// Derives the expected proof order from the log heights carried in the proof stream.
///
/// Proof-stream layout: 4 security parameters, the 4-felt deferred root, then the three
/// execution-dependent log heights (the And8Lookup height is verifier-fixed).
fn expected_order_from_shape(data: &VerifierData) -> ProofOrder {
    ProofOrder::from_instance_log_heights(&[
        data.proof_stream[8] as u8,
        data.proof_stream[9] as u8,
        data.proof_stream[10] as u8,
        AND8_LOOKUP_LOG_HEIGHT,
    ])
}

/// Each of the four security parameters (num_queries, query_pow_bits, deep_pow_bits,
/// folding_pow_bits) is absorbed into the Fiat-Shamir transcript, so forging any one of them in
/// the proof stream diverges the transcript and fails verification. They are the first four
/// advice values `vm::verify_proof` reads, i.e. `proof_stream[0..4]`.
#[test]
fn each_security_parameter_is_transcript_bound() {
    let source = vm_verify_proof_program();
    let base = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    for param in 0usize..4 {
        let mut data = base.clone();
        // Forge the parameter downward. In particular, the proof's original PoW nonces satisfy
        // the weaker targets, so rejection cannot be explained solely by demanding more work;
        // the changed transcript/verification schedule must invalidate the proof.
        data.proof_stream[param] -= 1;
        let test = build_test!(
            source.as_str(),
            &data.initial_stack(),
            data.advice_stack(),
            data.store.clone(),
            data.advice_map.clone()
        );
        assert!(
            test.execute_for_output().is_err(),
            "verifier accepted a forged security parameter (index {param})"
        );
    }
}

/// The fetched kernel digests must hash to the claim's K before the outer-LogUp fold uses them.
/// Check the explicit authentication failure because the later boundary check also rejects
/// tampered digests.
#[test]
fn tampered_kernel_witness_is_rejected() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    let witness = advice_map_value_mut(&mut data, k);
    // Flip one felt of the first digest while preserving the witness length.
    witness[0] = Felt::new_unchecked(witness[0].as_canonical_u64() ^ 1);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(
        test,
        "fetched kernel digests do not hash to the claim's kernel commitment"
    );
}

/// `vm::verify_proof` derives the kernel procedure count from the advice-map value length and
/// rejects a witness containing more than `KernelDescriptor::MAX_NUM_PROCEDURES` digests before
/// copying it.
#[test]
fn vm_verify_proof_rejects_oversized_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    *advice_map_value_mut(&mut data, k) =
        vec![Felt::ZERO; (KernelDescriptor::MAX_NUM_PROCEDURES + 1) * WORD_SIZE];

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(
        test,
        "number of kernel procedures exceeds KernelDescriptor::MAX_NUM_PROCEDURES"
    );
}

/// A kernel witness is a list of four-felt procedure digests.
#[test]
fn vm_verify_proof_rejects_misaligned_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    advice_map_value_mut(&mut data, k).push(Felt::ZERO);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(test, "kernel witness length must be word-aligned");
}

/// The claim preimage is untrusted advice and must match the caller-provided commitment.
#[test]
fn tampered_claim_preimage_is_rejected() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage[0] = Felt::new_unchecked(preimage[0].as_canonical_u64() ^ 1);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(
        test,
        "pipe_double_words_preimage_to_memory_with_domain: COMMITMENT does not match"
    );
}

/// The advice-map value under the claim commitment must use the canonical 40-felt encoding.
#[rstest]
#[case(NUM_CLAIM_ELEMENTS - 1)]
#[case(NUM_CLAIM_ELEMENTS + 1)]
fn malformed_claim_preimage_length_is_rejected(#[case] len: usize) {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    let claim_commitment = data.claim_commitment;
    let preimage = advice_map_value_mut(&mut data, claim_commitment);
    preimage.resize(len, Felt::ZERO);

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    expect_assert_error_code_from_msg!(test, "claim preimage has a non-canonical length");
}

/// The claim's kernel commitment K, read from felts [4, 8) of the canonical claim encoding.
fn claim_kernel_commitment(data: &VerifierData) -> Word {
    Word::new([
        Felt::new_unchecked(data.claim_advice[4]),
        Felt::new_unchecked(data.claim_advice[5]),
        Felt::new_unchecked(data.claim_advice[6]),
        Felt::new_unchecked(data.claim_advice[7]),
    ])
}

/// Mutable reference to the advice-map value stored under `key`.
fn advice_map_value_mut(data: &mut VerifierData, key: Word) -> &mut Vec<Felt> {
    let entry = data
        .advice_map
        .iter_mut()
        .find(|(k, _)| *k == key)
        .expect("advice map has an entry under the requested key");
    &mut entry.1
}

fn recursive_circuit_key(order: &ProofOrder) -> Word {
    miden_air::ace::RecursiveAceCircuitFactory::new()
        .expect("recursive-verifier ACE composition must build")
        .circuit_for_order(order)
        .expect("recursive-verifier ACE circuit must encode")
        .commitment
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

/// Tiny program where every AIR lands at its minimum height.
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

const EXAMPLE_LOG_DEFERRED: &str = "begin
        log_deferred
        dropw
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

fn log_deferred_stack_inputs() -> Vec<u64> {
    // TRUE_DIGEST is the zero word and must occupy the top four positions. A nonzero first tail
    // element makes the post-`dropw` output visibly distinct from an empty stack.
    let mut inputs = vec![0_u64; 16];
    inputs[4] = 7;
    inputs
}

// EIDOS CHALLENGER PARITY TESTS
// ================================================================================================

/// The trusted AND8 preprocessed-trace commitment for the canonical Miden statement shape, as
/// bound by `load_air_context` (must match `AND8_PREPROCESSED_TRACE_COM_*` in `sys/vm/mod.masm`).
fn and8_preprocessed_commitment() -> [Felt; WORD_SIZE] {
    let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![],
    )
    .expect("zero public inputs satisfy the Miden statement shape");
    let commitment: [u64; WORD_SIZE] = Preprocessed::build(&statement, &config)
        .expect("the Miden relation declares the AND8 preprocessed table")
        .commitment()
        .into();
    commitment.map(Felt::new_unchecked)
}

fn read_word(output: &miden_processor::ExecutionOutput, addr: u32) -> [Felt; WORD_SIZE] {
    let ctx = miden_processor::ContextId::root();
    array::from_fn(|i| {
        output
            .memory
            .read_element(ctx, Felt::from_u32(addr + i as u32))
            .expect("memory read")
    })
}

/// Step-I transcript parity: the MASM Fiat-Shamir schedule (relation digest + PCS params via
/// `init_seed`, preprocessed commitment, `[CLAIM_HASH | D]`, AIR shape as five single felts,
/// main-trace commitment) squeezes the same word as the Rust Eidos challenger fed the identical
/// observation stream.
#[test]
fn public_input_transcript_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;
    const RANDOM_COIN_BUFFER_LEN_PTR: u32 = 3223322767;
    const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3223322768;

    let log_heights = [10_u64, 11, 12];
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // The transcript binds the claim only through its commitment; the preimage merely has to be
    // staged for `stage_boundary_inputs`/`load_public_inputs` to read.
    let claim: [u64; NUM_CLAIM_ELEMENTS] = array::from_fn(|_| rng.next_u32() as u64);
    let claim_hash: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let deferred_root: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);
    let main_trace_commitment: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u32() as u64);

    let mut advice_stack = log_heights.to_vec();
    advice_stack.extend_from_slice(&claim);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&main_trace_commitment);

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            push.{num_queries} exec.constants::set_number_queries
            push.{query_pow_bits} exec.constants::set_query_pow_bits
            push.{deep_pow_bits} exec.constants::set_deep_pow_bits
            push.{folding_pow_bits} exec.constants::set_folding_pow_bits
            exec.vm::load_air_context

            # Stage the claim region and commitment the way `verify_vm_proof` leaves them.
            push.{NUM_CLAIM_ELEMENTS} exec.layout::claim_ptr exec.copy_advice_to_mem
            push.{ch3}.{ch2}.{ch1}.{ch0}
            exec.layout::claim_commitment_ptr mem_storew_le dropw
            exec.public_inputs::stage_boundary_inputs

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            # Main-trace commitment, then squeeze (the squeeze flushes the buffered stream).
            padw adv_loadw
            exec.constants::main_trace_com_ptr mem_storew_le
            exec.random_coin::observe_word
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
        ch0 = claim_hash[0],
        ch1 = claim_hash[1],
        ch2 = claim_hash[2],
        ch3 = claim_hash[3],
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    // Rust mirror over the identical observation stream.
    let config = config::eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    for &element in claim_hash.iter().chain(deferred_root.iter()) {
        challenger.observe(Felt::new_unchecked(element));
    }
    challenger.observe(Felt::new_unchecked(MIDEN_AIR_COUNT as u64));
    for log_height in
        [log_heights[0], log_heights[1], log_heights[2], AND8_LOOKUP_LOG_HEIGHT as u64]
    {
        challenger.observe(Felt::new_unchecked(log_height));
    }
    for &element in &main_trace_commitment {
        challenger.observe(Felt::new_unchecked(element));
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);

    // The squeeze left neither buffered input nor cached output behind.
    let ctx = miden_processor::ContextId::root();
    let read = |addr| output.memory.read_element(ctx, Felt::from_u32(addr)).expect("memory read");
    assert_eq!(read(RANDOM_COIN_BUFFER_LEN_PTR), Felt::ZERO);
    assert_eq!(read(RANDOM_COIN_OUTPUT_LEN_PTR), Felt::ZERO);
}

#[test]
fn eidos_init_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    let params = config::pcs_params();
    let source = format!(
        "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.{num_queries} exec.constants::set_number_queries
            push.{query_pow_bits} exec.constants::set_query_pow_bits
            push.{deep_pow_bits} exec.constants::set_deep_pow_bits
            push.{folding_pow_bits} exec.constants::set_folding_pow_bits
            exec.vm::load_air_context
            exec.random_coin::init_seed
            exec.random_coin::eidos_squeeze_word
            push.{SQUEEZED_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        num_queries = params.num_queries(),
        query_pow_bits = params.query_pow_bits(),
        deep_pow_bits = params.deep_pow_bits(),
        folding_pow_bits = params.folding_pow_bits(),
    );

    let shape = [10_u64, 11, 12];
    let test = build_test!(source.as_str(), &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = config::eidos_config(params, config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);
    // `init_seed` also stages the trusted preprocessed-trace commitment onto the buffered stream.
    for element in and8_preprocessed_commitment() {
        challenger.observe(element);
    }
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
}

#[test]
fn eidos_relation_digest_seed_matches_rust_challenger() {
    const SQUEEZED_WORD_PTR: u32 = 1000;

    // The pushed word is `Eidos::transcript_init_cv(0x00000201)`, matching the
    // `EIDOS_TRANSCRIPT_INIT_CV_*` constants in `stark/random_coin.masm`.
    let source = "
        use miden::core::sys::vm
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            exec.vm::load_air_context
            push.6225836997093344009.6615246172502583955.3539038439026260303.4361500420518448919
            padw exec.constants::relation_digest_ptr mem_loadw_le
            exec.random_coin::eidos_init_challenger
            exec.random_coin::eidos_squeeze_word
            push.1000 mem_storew_le
            dropw
        end
        ";

    let shape = [10_u64, 11, 12];
    let test = build_test!(source, &[], &shape);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let mut challenger = config.challenger();
    let expected_word = Word::new(array::from_fn(|_| challenger.sample_algebra_element()));

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
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
            exec.random_coin::eidos_clear_buffer
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

    let init_cv = Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
    ]);
    let mut challenger = miden_crypto::hash::eidos::EidosChallenger::new(init_cv);
    challenger.observe([
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

    assert_eq!(Word::new(read_word(&output, SQUEEZED_WORD_PTR)), expected_word);
}

#[test]
fn eidos_absorb_block_rejects_nonempty_buffer() {
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            push.13.12.11.10 exec.constants::random_coin_cv_ptr mem_storew_le dropw
            exec.random_coin::eidos_clear_buffer
            push.17 exec.random_coin::observe_felt

            push.8.7.6.5
            push.4.3.2.1
            exec.random_coin::eidos_absorb_block
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "eidos_absorb_block: buffer must be empty");
}

#[test]
fn eidos_hash_elements_single_block_matches_masm_compress_loop() {
    const HASH_WORD_PTR: u32 = 1000;

    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, 8);
    let source = format!(
        "
        begin
            push.{cv3}.{cv2}.{cv1}.{cv0}
            push.8.7.6.5
            push.4.3.2.1
            compress
            dropw dropw
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let elements = (1..=8).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    assert_eq!(Word::new(read_word(&output, HASH_WORD_PTR)), expected_word);
}

#[test]
fn eidos_hash_elements_adv_pipe_loop_matches_masm_compress_loop() {
    const HASH_WORD_PTR: u32 = 1000;
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, elements.len() as u32);
    let advice_stack: Vec<u64> = elements.iter().map(Felt::as_canonical_u64).collect();

    let source = format!(
        "
        begin
            push.{STREAM_PTR}
            push.{cv3}.{cv2}.{cv1}.{cv0}
            padw padw
            repeat.2
                adv_pipe
                compress
            end
            dropw dropw
            movup.4 drop
            push.{HASH_WORD_PTR} mem_storew_le
            dropw
        end
        ",
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[], &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);

    assert_eq!(Word::new(read_word(&output, HASH_WORD_PTR)), expected_word);
}

#[test]
fn eidos_hash_elements_advice_map_loop_matches_masm_compress_loop() {
    const STREAM_PTR: u32 = 1 << 16;

    let elements = (1..=16).map(Felt::new_unchecked).collect::<Vec<_>>();
    let expected_word = miden_crypto::hash::eidos::Eidos::hash_elements(&elements);
    let map_values = elements
        .iter()
        .map(Felt::as_canonical_u64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let init_cv = miden_crypto::hash::eidos::Eidos::init_chaining_word(0, elements.len() as u32);

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
                compress
            end
            dropw dropw
            movup.4 drop
            assert_eqw
        end
        ",
        key0 = expected_word[0].as_canonical_u64(),
        key1 = expected_word[1].as_canonical_u64(),
        key2 = expected_word[2].as_canonical_u64(),
        key3 = expected_word[3].as_canonical_u64(),
        map_values = map_values,
        cv0 = init_cv[0].as_canonical_u64(),
        cv1 = init_cv[1].as_canonical_u64(),
        cv2 = init_cv[2].as_canonical_u64(),
        cv3 = init_cv[3].as_canonical_u64(),
    );

    let test = build_test!(source.as_str(), &[]);
    test.execute().expect("execution failed");
}

// REDUCED INPUTS TESTS
// ================================================================================================

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
#[case(KernelDescriptor::MAX_NUM_PROCEDURES)]
fn boundary_inputs_and_outer_logup_boundary(#[case] num_kernel_procedures: usize) {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate the statement inputs.
    let stack_inputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let stack_outputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let deferred_root: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let kernel_digest_felts = generate_kernel_procedure_digests(&mut rng, num_kernel_procedures);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // 2) Initial operand stack: the kernel procedure count used by this test's setup code.
    let initial_stack = vec![num_kernel_procedures as u64];

    // 3) Build the advice stack: kernel digests (4N), the claim encoding (P, K, I, O), the deferred
    //    root, and the aux randomness used by `compute_outer_logup_correction`.
    let digest_felts: Vec<Felt> =
        kernel_digest_felts.iter().map(|&v| Felt::new_unchecked(v)).collect();
    let expected_kernel_h = miden_air::hash_kernel_digests(&digest_felts);
    let mut claim_elements = [Felt::ZERO; NUM_CLAIM_ELEMENTS];
    claim_elements[..WORD_SIZE].copy_from_slice(&program_digest.map(Felt::new_unchecked));
    claim_elements[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(&expected_kernel_h);
    claim_elements[2 * WORD_SIZE..6 * WORD_SIZE]
        .copy_from_slice(&stack_inputs.map(Felt::new_unchecked));
    claim_elements[6 * WORD_SIZE..].copy_from_slice(&stack_outputs.map(Felt::new_unchecked));
    let [claim_c0, claim_c1, claim_c2, claim_c3] =
        miden_core::program::claim_commitment(&claim_elements)
            .into_elements()
            .map(|felt| felt.as_canonical_u64());

    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&kernel_digest_felts);
    advice_stack.extend_from_slice(&program_digest);
    advice_stack.extend(expected_kernel_h.iter().map(Felt::as_canonical_u64));
    advice_stack.extend_from_slice(&stack_inputs);
    advice_stack.extend_from_slice(&stack_outputs);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    // 4) Populate verifier memory, stage the statement inputs, run process_public_inputs, then
    //    emulate step II: place the aux randomness at AUX_RAND_ELEM_PTR (where
    //    `generate_aux_randomness` samples it) and compute `c_total`.
    let source = format!(
        "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::layout
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            # Initial stack: [num_kernel_procedures].

            # Copy kernel digests (4·num_kernel_procedures felts) from advice into the witness
            # region. Build [dst=KERNEL_WITNESS_PTR, count=4N].
            dup mul.4 exec.layout::kernel_witness_ptr
            exec.copy_advice_to_mem

            # Copy the full claim encoding P | K | I | O into verifier-owned memory.
            push.{NUM_CLAIM_ELEMENTS} exec.layout::claim_ptr
            exec.copy_advice_to_mem

            exec.layout::num_kernel_procedures_ptr mem_store
            exec.public_inputs::stage_boundary_inputs

            push.10 exec.layout::set_core_trace_length_log
            push.10 exec.layout::set_chiplets_trace_length_log
            push.10 exec.layout::set_eidos_compression_trace_length_log
            push.16 exec.layout::set_and8_lookup_trace_length_log
            push.16 exec.constants::set_trace_length_log
            push.4.3.2.1 exec.constants::relation_digest_ptr mem_storew_le dropw
            push.{claim_c3}.{claim_c2}.{claim_c1}.{claim_c0}
            exec.layout::claim_commitment_ptr mem_storew_le dropw

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            padw adv_loadw exec.layout::aux_rand_elem_ptr mem_storew_le dropw
            exec.public_inputs::compute_outer_logup_correction
        end
        "
    );

    let test = build_test!(source.as_str(), &initial_stack, &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    use miden_processor::ContextId;
    let ctx = ContextId::root();
    let read_elem = |addr: u32| -> u64 {
        output
            .memory
            .read_element(ctx, Felt::from_u32(addr))
            .unwrap()
            .as_canonical_u64()
    };

    // Must match `stark/constants.masm` and `sys/vm/layout.masm`.
    const BOUNDARY_INPUTS_PTR: u32 = 3223322836;
    const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322638;
    const C_TOTAL_PTR: u32 = 3223322784;

    let pi_ptr = read_elem(PUBLIC_INPUTS_ADDRESS_PTR) as u32;

    // 4) program_digest and deferred_root pass through to the boundary-inputs block.
    for (i, &v) in program_digest.iter().chain(deferred_root.iter()).enumerate() {
        assert_eq!(
            read_elem(BOUNDARY_INPUTS_PTR + i as u32),
            v,
            "boundary-inputs window felt {i} mismatch"
        );
    }
    // 5) FLPI region holds the stack i/o as EF elements ([val, 0] per slot).
    for (i, &v) in stack_inputs.iter().chain(stack_outputs.iter()).enumerate() {
        assert_eq!(read_elem(pi_ptr + 2 * i as u32), v, "FLPI slot {i} value mismatch");
        assert_eq!(read_elem(pi_ptr + 2 * i as u32 + 1), 0, "FLPI slot {i} high coord");
    }

    // 6) Verify the outer-LogUp boundary correction c_total at C_TOTAL_PTR:
    //
    //     c_total = Σ_i 1 / ((α + γ) + msg(kernel_digest_i))
    //             + 1 / ((α + 2γ) + msg(program_digest))
    //             + 1 / (α + 3γ)
    //             − 1 / ((α + 3γ) + msg(deferred_root))
    //
    // with γ = β^16 and msg(w) = Σ w_i·β^i, mirroring `MidenMultiAir::eval_external`.
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let msg = |felts: &[u64]| -> QuadFelt {
        felts
            .iter()
            .rev()
            .fold(QuadFelt::ZERO, |acc, m| acc * beta + QuadFelt::from(Felt::new_unchecked(*m)))
    };

    #[allow(clippy::chunks_exact_to_as_chunks)]
    let kernel_corr = kernel_digest_felts
        .as_chunks::<WORD_SIZE>()
        .0
        .iter()
        .map(|digest| alpha + gamma + msg(digest))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        });
    let d_bh = alpha + gamma.double() + msg(&program_digest);
    let prefix_lp = alpha + gamma * QuadFelt::from_u8(3);
    let d_lpf = prefix_lp + msg(&deferred_root);
    let expected_c_total = kernel_corr
        + d_bh.try_inverse().expect("zero block-hash denominator")
        + prefix_lp.try_inverse().expect("zero log-deferred init denominator")
        - d_lpf.try_inverse().expect("zero log-deferred final denominator");
    let expected: &[Felt] = expected_c_total.as_basis_coefficients_slice();

    assert_eq!(
        read_elem(C_TOTAL_PTR),
        expected[0].as_canonical_u64(),
        "c_total coord 0 mismatch (nk={num_kernel_procedures})"
    );
    assert_eq!(
        read_elem(C_TOTAL_PTR + 1),
        expected[1].as_canonical_u64(),
        "c_total coord 1 mismatch (nk={num_kernel_procedures})"
    );
}

#[test]
fn quotient_recomposition_constants_match_derivation() {
    // The generated evaluator serializes values derived from two independent protocol inputs:
    // quotient arity from the AIRs, and the canonical LDE shift from the PCS configuration. The
    // VM currently has arity = blowup = 8, so deriving all three from the blowup would produce the
    // same numbers and conceal the conflation that breaks relations where they differ.
    let masm = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/asm/sys/vm/constraints_eval.masm"
    ))
    .expect("read generated VM constraints evaluator");
    let masm_const = |name: &str| -> u64 {
        masm.lines()
            .find_map(|line| {
                let (lhs, rhs) = line.trim().strip_prefix("const ")?.split_once('=')?;
                if lhs.trim() != name {
                    return None;
                }
                Some(rhs.split_whitespace().next()?.parse().expect("parse const value"))
            })
            .unwrap_or_else(|| panic!("const {name} not found in VM constraints evaluator"))
    };

    let shift_ratio = Felt::new(masm_const("QUOTIENT_SHIFT_RATIO")).unwrap();
    let first_shift = Felt::new(masm_const("QUOTIENT_FIRST_SHIFT")).unwrap();
    let first_weight = Felt::new(masm_const("QUOTIENT_FIRST_WEIGHT")).unwrap();

    let log_quotient_degree = miden_air::AIRS
        .iter()
        .map(miden_crypto::stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    let expected = miden_crypto::stark::quotient_recomposition_inputs::<Felt>(
        log_quotient_degree,
        config::pcs_params().log_blowup(),
    )
    .expect("the Miden quotient degree fits its PCS blowup");

    assert_eq!(shift_ratio, expected.shift_ratio, "QUOTIENT_SHIFT_RATIO is stale");
    assert_eq!(first_shift, expected.first_shift, "QUOTIENT_FIRST_SHIFT is stale");
    assert_eq!(first_weight, expected.first_weight, "QUOTIENT_FIRST_WEIGHT is stale");
}

/// A relation may stage per-AIR fold coefficients only once its ACE input region holds them.
///
/// `stage_air_fold_coefficients` writes one extension-field coefficient per AIR immediately after
/// the selector block, at base offsets `FIRST_SELECTOR_OFFSET + SELECTOR_STRIDE * num_airs + 2k`
/// from the relation's stark-vars base. Only the felts below `ACE_CIRCUIT_STREAM_PTR` belong to
/// that region; a coefficient past its end lands in the circuit-stream region, where the loader's
/// next `adv_pipe` silently overwrites it. The memory-map test cannot see this — it compares
/// *declared* extents, and both regions stay dense and disjoint whether or not the writes stay
/// inside them — so the bound is asserted here instead, against the procedure's real offsets.
#[test]
fn staged_fold_coefficients_fit_the_declared_ace_input_region() {
    const STAGING_PROC: &str = "stage_air_fold_coefficients";
    const ENTRY_PROC: &str = "set_up_auxiliary_inputs_ace";
    /// Base felts per staged coefficient (one quadratic-extension element).
    const COEFFICIENT_STRIDE: u32 = 2;

    let staging = include_str!("../../asm/stark/constraints_eval_inputs.masm");
    let masm_const = |source: &str, name: &str, what: &str| -> u32 {
        let prefix = format!("const {name} = ");
        source
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix)?.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing {what} constant {name}"))
    };

    let first_selector_offset = masm_const(staging, "FIRST_SELECTOR_OFFSET", "staging");
    let selector_stride = masm_const(staging, "SELECTOR_STRIDE", "staging");

    // Walk the procedure declarations rather than the raw text so a rename of either procedure
    // fails here instead of turning this guard into a silent no-op.
    let mut declares_staging = false;
    let mut in_entry = false;
    let mut stages_coefficients = false;
    for line in staging.lines() {
        let trimmed = line.trim();
        if let Some(rest) =
            trimmed.strip_prefix("pub proc ").or_else(|| trimmed.strip_prefix("proc "))
        {
            let name = rest.split(['(', ' ']).next().unwrap_or(rest);
            declares_staging |= name == STAGING_PROC;
            in_entry = name == ENTRY_PROC;
        }
        stages_coefficients |= in_entry && trimmed.contains(&format!("exec.{STAGING_PROC}"));
    }
    assert!(declares_staging, "{STAGING_PROC} is no longer declared");

    for (relation, layout_const, evaluator) in [
        (
            "vm",
            vm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/vm/constraints_eval.masm"),
        ),
        (
            "pvm",
            pvm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/pvm/constraints_eval.masm"),
        ),
    ] {
        let num_airs = masm_const(evaluator, "NUM_AIRS", relation);
        let region_felts =
            layout_const("ACE_CIRCUIT_STREAM_PTR") - layout_const("AUXILIARY_ACE_INPUTS_PTR");

        let selectors_end = first_selector_offset + selector_stride * num_airs;
        assert!(
            selectors_end <= region_felts,
            "{relation}: {num_airs} selector triples end at felt {selectors_end}, past the \
             {region_felts}-felt AUXILIARY_ACE_INPUTS_PTR region"
        );

        if stages_coefficients {
            let coefficients_end = selectors_end + COEFFICIENT_STRIDE * num_airs;
            assert!(
                coefficients_end <= region_felts,
                "{relation}: {ENTRY_PROC} stages {num_airs} fold coefficients ending at felt \
                 {coefficients_end}, past the {region_felts}-felt AUXILIARY_ACE_INPUTS_PTR \
                 region; enlarge the region before wiring the staging call in"
            );
        }
    }
}

// HELPERS
// ===============================================================================================

/// Generates kernel-procedure digest felts: 4 canonical felts per digest.
fn generate_kernel_procedure_digests<R: Rng>(
    rng: &mut R,
    num_kernel_procedures: usize,
) -> Vec<u64> {
    (0..num_kernel_procedures * WORD_SIZE).map(|_| rng.next_u64()).collect()
}

fn max_kernel_source() -> String {
    let mut source = KERNEL_SINGLE_PROC.to_owned();
    for i in 1..KernelDescriptor::MAX_NUM_PROCEDURES {
        write!(source, "\npub proc unused_{i}\n    push.{i} drop\nend").unwrap();
    }
    source
}

// CONSTANTS
// ===============================================================================================

/// The verifier-fixed And8Lookup log trace height (the full byte-pair table).
const AND8_LOOKUP_LOG_HEIGHT: u8 = 16;

/// Memory used by test consumers while deriving a claim commitment.
const CONSUMER_CLAIM_PTR: u64 = 4096;

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
