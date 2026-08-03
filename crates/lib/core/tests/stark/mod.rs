use std::{array, fmt::Write as _, sync::Arc};

use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    program::{ExecutionClaim, KernelDescriptor, NUM_CLAIM_ELEMENTS},
    proof::HashFunction,
};
use miden_mast_package::Package;
use miden_processor::{DefaultHost, ExecutionOptions, Program, ProgramInfo};
use miden_utils_testing::{
    AdviceInputs, ProvingOptions, prove_sync,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;

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
    let data = generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, fib_stack_inputs(), None);
    run_recursive_verifier(&data);
}

#[test]
fn folding_reseed_helper_matches_reference_sampler() {
    fn source(use_combined_helper: bool) -> String {
        let sample = if use_combined_helper {
            "
            push.41.31.29.23 push.17
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            "
        } else {
            "
            push.41.31.29.23 push.17
            exec.random_coin::reseed_with_felt
            exec.constants::get_folding_pow_bits
            exec.random_coin::sample_bits
            assertz
            exec.random_coin::sample_ext
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.0 exec.constants::set_folding_pow_bits
                push.109.113.127.131 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.0 exec.constants::random_coin_output_len_ptr mem_store

                {sample}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
                exec.sys::truncate_stack
            end
            "
        )
    }

    let (reference, _) = build_test!(&source(false), &[])
        .execute_for_output()
        .expect("reference sampler should execute");
    let (combined, _) = build_test!(&source(true), &[])
        .execute_for_output()
        .expect("combined sampler should execute");

    assert_eq!(
        combined.stack.get_num_elements(15),
        reference.stack.get_num_elements(15),
        "combined FRI reseed helper diverged from reference sampler"
    );
    assert_eq!(combined.stack.get_element(12), Some(Felt::from_u32(5)));
}

#[test]
fn word_observe_helpers_match_scalar_observe() {
    fn source(use_word_helpers: bool) -> String {
        let observe = if use_word_helpers {
            "
            push.11.7.5.3
            exec.random_coin::observe_word
            push.23.19.17.13
            exec.random_coin::observe_word_and_flush_buffer
            "
        } else {
            "
            push.3 exec.random_coin::observe_felt
            push.5 exec.random_coin::observe_felt
            push.7 exec.random_coin::observe_felt
            push.11 exec.random_coin::observe_felt
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            push.19 exec.random_coin::observe_felt
            push.23 exec.random_coin::observe_felt
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.8 exec.constants::random_coin_output_len_ptr mem_store

                {observe}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
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
        "word observe helpers changed random coin state"
    );
    assert_eq!(optimized.stack.get_element(12), Some(Felt::from_u32(8)));
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
                push.101.103.107.109 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.8 exec.constants::random_coin_output_len_ptr mem_store

                {prefix}
                {observe}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
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
        assert_eq!(optimized.stack.get_element(12), Some(Felt::from_u32(8)));
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

    let options = ProvingOptions::new(HashFunction::Poseidon2);

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
    let claim = ExecutionClaim::from_program_info(program_info, stack_inputs, stack_outputs);

    generate_advice_inputs(&proof, &claim).unwrap()
}

/// The MAST root of `sys::vm::verify_vm_proof` - the verifier identity request keys
/// name. The operator side is `CoreLibrary::recursive_verifier_root`; a consumer computes the
/// identical value in-VM with `procref` (a procedure's root is intrinsic to its own MAST,
/// independent of the enclosing program), so the two sides agree without any shared constant.
fn verify_vm_proof_root() -> Word {
    miden_core_lib::CoreLibrary::default().recursive_verifier_root()
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
/// `proof_request_key(verifier_root, claim_commitment)`, verify, then grade the returned security
/// parameters and assert an acceptance threshold. `verify_vm_proof` holds no estimate formula
/// and no policy; both live in the consumer.
fn request_consumer_source() -> String {
    format!(
        "
        use miden::core::sys
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
            #    verify_vm_proof's root, derived in-VM via procref.
            dupw
            procref.vm::verify_vm_proof exec.sys::proof_request_key
            adv.push_mapval dropw
            # => [CLAIM_COMMITMENT]

            # 3) Verify the claim; verify_vm_proof returns the deferred obligation and the
            #    proof's transcript-bound security parameters.
            exec.vm::verify_vm_proof
            # => [D, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]

            # 4) Grade the returned parameters and assert the consumer's acceptance
            #    threshold (>= 96 conjectured bits).
            swapw
            # => [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, D]
            exec.vm::compute_conjectured_security_level
            # => [conjectured_level, deep_pow_bits, folding_pow_bits, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            drop drop
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
        (proof_request_key(verify_vm_proof_root(), intended.claim_commitment), felts)
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
    let other = generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, fib_stack_inputs(), None);
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
    let verifier_root = verify_vm_proof_root();
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
        use miden::core::sys::vm
        use miden::core::sys::vm::claim

        {COPY_ADVICE_TO_MEM}

        proc verify_one_claim
            # Per claim: stage the fields from the consumer's own inputs, derive the
            # commitment that names the claim, fetch and verify the proof package it
            # addresses, then grade the returned parameters against the acceptance
            # threshold.
            push.{NUM_CLAIM_ELEMENTS} push.{CONSUMER_CLAIM_PTR} exec.copy_advice_to_mem
            push.{CONSUMER_CLAIM_PTR} exec.claim::claim_commitment # => [CLAIM_COMMITMENT]
            dupw
            procref.vm::verify_vm_proof exec.sys::proof_request_key
            adv.push_mapval dropw                        # => [CLAIM_COMMITMENT]
            exec.vm::verify_vm_proof                     # => [D, nq, q_pow, deep_pow, fold_pow]
            swapw exec.vm::compute_conjectured_security_level # => [level, deep_pow, fold_pow, D]
            u32lt.96 assertz.err=\"proof security level is below the accepted target\"
            drop drop                                    # => [D]
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

/// Runs `verify_vm_proof` with the claim commitment on the operand stack and the proof stream on
/// advice. This directly pins the producer and MASM consumption order.
fn verify_vm_proof_program() -> String {
    "
        use miden::core::sys
        use miden::core::sys::vm

        begin
            exec.vm::verify_vm_proof
            # => [D, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
            exec.sys::truncate_stack
        end
    "
    .into()
}

fn run_recursive_verifier(data: &VerifierData) {
    let source = verify_vm_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store.clone(),
        data.advice_map.clone()
    );
    let (output, _host) = test.execute_for_output().expect("recursive verifier execution failed");

    // `verify_vm_proof` returns [D, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits].
    // Pin D (stack positions 0..4) to the proof-stream value and the parameter tail (positions
    // 4..8) to the deployed PCS config so a change to the returned tuple's values or order is
    // caught across every e2e configuration.
    let params = miden_air::config::pcs_params();
    let returned = |i: usize| output.stack.get_element(i).map(|f| f.as_canonical_u64());
    for i in 0..WORD_SIZE {
        assert_eq!(returned(i), Some(data.proof_stream[4 + i]), "returned deferred root felt {i}");
    }
    assert_eq!(returned(4), Some(params.num_queries() as u64), "returned num_queries");
    assert_eq!(returned(5), Some(params.query_pow_bits() as u64), "returned query_pow_bits");
    assert_eq!(returned(6), Some(params.deep_pow_bits() as u64), "returned deep_pow_bits");
    assert_eq!(returned(7), Some(params.folding_pow_bits() as u64), "returned folding_pow_bits");

    // Cross-check: extract READ section, sanity-check values, evaluate circuit in Rust.
    ace_read_check::cross_check_ace_circuit(&output);
}

/// Each of the four security parameters (num_queries, query_pow_bits, deep_pow_bits,
/// folding_pow_bits) is absorbed into the Fiat-Shamir transcript, so forging any one of them in
/// the proof stream diverges the transcript and fails verification. They are the first four
/// advice values `verify_vm_proof` reads, i.e. `proof_stream[0..4]`.
#[test]
fn each_security_parameter_is_transcript_bound() {
    let source = verify_vm_proof_program();
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

    let source = verify_vm_proof_program();
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

/// `verify_vm_proof` derives the kernel procedure count from the advice-map value length and
/// rejects a witness containing more than `KernelDescriptor::MAX_NUM_PROCEDURES` digests before
/// copying it.
#[test]
fn verify_vm_proof_rejects_oversized_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    *advice_map_value_mut(&mut data, k) = vec![Felt::ZERO; 256 * WORD_SIZE];

    let source = verify_vm_proof_program();
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
fn verify_vm_proof_rejects_misaligned_kernel_witness() {
    let mut data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        fib_stack_inputs(),
        Some(KERNEL_EVEN_NUM_PROC),
    );
    let k = claim_kernel_commitment(&data);
    advice_map_value_mut(&mut data, k).push(Felt::ZERO);

    let source = verify_vm_proof_program();
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

    let source = verify_vm_proof_program();
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

    let source = verify_vm_proof_program();
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

/// Like EXAMPLE_FIB_SMALL but with a syscall, for kernel-aware tests.
const EXAMPLE_FIB_KERNEL_SMALL: &str = "begin
        syscall.foo
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

const EXAMPLE_LOG_DEFERRED: &str = "begin
        log_deferred
        dropw dropw dropw
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

// REDUCED INPUTS TESTS
// ================================================================================================

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
// 255 = KernelDescriptor::MAX_NUM_PROCEDURES, the maximum number of kernel procedures a Statement
// accepts.
#[case(255)]
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
        use miden::core::sys::vm::public_inputs

        {COPY_ADVICE_TO_MEM}

        begin
            # Initial stack: [num_kernel_procedures].

            # Copy kernel digests (4·num_kernel_procedures felts) from advice into the witness
            # region. Build [dst=KERNEL_WITNESS_PTR, count=4N].
            dup mul.4 exec.constants::kernel_witness_ptr
            exec.copy_advice_to_mem

            # Copy the full claim encoding P | K | I | O into verifier-owned memory.
            push.{NUM_CLAIM_ELEMENTS} exec.constants::claim_ptr
            exec.copy_advice_to_mem

            exec.constants::num_kernel_procedures_ptr mem_store
            exec.public_inputs::stage_boundary_inputs

            push.10 exec.constants::set_core_trace_length_log
            push.10 exec.constants::set_chiplets_trace_length_log
            push.10 exec.constants::set_poseidon2_permutation_trace_length_log
            push.10 exec.constants::set_trace_length_log
            push.4.3.2.1 exec.constants::relation_digest_ptr mem_storew_le dropw
            push.{claim_c3}.{claim_c2}.{claim_c1}.{claim_c0}
            exec.constants::claim_commitment_ptr mem_storew_le dropw

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            padw adv_loadw exec.constants::aux_rand_elem_ptr mem_storew_le dropw
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

    // Must match `crates/lib/core/asm/stark/constants.masm`.
    const BOUNDARY_INPUTS_PTR: u32 = 3223322836;
    const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322671;
    const C_TOTAL_PTR: u32 = 3223322704;

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

    let kernel_corr = kernel_digest_felts
        .chunks_exact(WORD_SIZE)
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
    // The quotient recomposition constants in `asm/stark/constants.masm` are precomputed for the
    // fixed blowup factor. Re-derive them from `BLOWUP_FACTOR_LOG` and the field so that changing
    // the blowup without regenerating the constants fails here instead of shipping stale values.

    // Goldilocks two-adicity: p - 1 = 2^32 * (2^32 - 1), so the largest power-of-two subgroup has
    // order 2^32.
    const TWO_ADICITY: u32 = 32;
    // Goldilocks multiplicative generator.
    const GENERATOR: u32 = 7;

    let masm =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/asm/stark/constants.masm"))
            .expect("read constants.masm");
    let masm_const = |name: &str| -> u64 {
        masm.lines()
            .find_map(|line| {
                let (lhs, rhs) = line.trim().strip_prefix("const ")?.split_once('=')?;
                if lhs.trim() != name {
                    return None;
                }
                Some(rhs.split_whitespace().next()?.parse().expect("parse const value"))
            })
            .unwrap_or_else(|| panic!("const {name} not found in constants.masm"))
    };

    let blowup_log = masm_const("BLOWUP_FACTOR_LOG") as u32;
    let root_unity = Felt::new(masm_const("ROOT_UNITY")).unwrap();
    let shift_ratio = Felt::new(masm_const("QUOTIENT_SHIFT_RATIO")).unwrap();
    let first_shift = Felt::new(masm_const("QUOTIENT_FIRST_SHIFT")).unwrap();
    let first_weight = Felt::new(masm_const("QUOTIENT_FIRST_WEIGHT")).unwrap();

    // With log_lde = log_trace + BLOWUP_FACTOR_LOG, both lde_g^N and offset^N collapse to one
    // exponent that is independent of the trace length N = 2^log_trace.
    let exp = 1u64 << (TWO_ADICITY - blowup_log);
    let blowup = 1u32 << blowup_log;

    // f = lde_g^N: the primitive 2^BLOWUP_FACTOR_LOG-th root of unity.
    assert_eq!(root_unity.exp_u64(exp), shift_ratio, "QUOTIENT_SHIFT_RATIO is stale");

    // s0 = offset^N with offset = GENERATOR^(2^(TWO_ADICITY - log_lde)).
    let s0 = Felt::from_u32(GENERATOR).exp_u64(exp);
    assert_eq!(s0, first_shift, "QUOTIENT_FIRST_SHIFT is stale");

    // First barycentric weight = 1 / (BLOWUP_FACTOR * s0^(BLOWUP_FACTOR - 1)); check it as a
    // reciprocal to avoid an explicit field inversion.
    let denom = Felt::from_u32(blowup) * s0.exp_u64((blowup - 1) as u64);
    assert_eq!((first_weight * denom).as_canonical_u64(), 1, "QUOTIENT_FIRST_WEIGHT is stale");
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
