//! Integration tests for the public proving lifecycle and recursive-verifier regressions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager, Linkage};
use miden_core::{
    Felt, program::ExecutionClaim, proof::ExecutionProof, utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::CoreLibrary;
use miden_utils_testing::{recursive_verifier::generate_request_inputs, stack_inputs_from_ints};
use miden_vm::{
    DefaultHost, ExecutionOptions, FastProcessor, HashFunction, ProgramInfo, Prover, StackInputs,
    StackOutputs, Verifier, advice::AdviceInputs,
};

fn masm_push_felts(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|felt| format!("push.{}", felt.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn assert_prove_verify(
    source: &str,
    hash_fn: HashFunction,
    hash_name: &str,
    print_stack_outputs: bool,
    verify_recursively: bool,
) {
    let program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();
    let stack_inputs = stack_inputs_from_ints([0, 1]);
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    println!("Proving with {hash_name}...");
    let witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("processor initialization failed")
            .execute_for_proving_sync(&program, &mut host)
            .expect("execution failed");
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new().with_hash_fn(hash_fn).prove_full(witness).expect("Proving failed");

    println!("Proof generated successfully!");
    if print_stack_outputs {
        println!("Stack outputs: {stack_outputs:?}");
    }

    if verify_recursively {
        assert_recursive_verify(program.to_info(), stack_inputs, stack_outputs, &proof);
    }

    println!("Verifying proof...");
    let claim = ExecutionClaim::from_program_info(program.into(), stack_inputs, stack_outputs);
    let outcome = Verifier::new().verify(&claim, &proof).expect("Verification failed");
    assert!(outcome.is_complete());

    println!("Verification successful! Security level: {}", outcome.security_level());
}

fn assert_recursive_verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: &ExecutionProof,
) {
    let claim = ExecutionClaim::from_program_info(program_info, stack_inputs, stack_outputs);
    let verifier_root = CoreLibrary::default().recursive_verifier_root();
    let verifier_inputs = generate_request_inputs(verifier_root, proof, &claim)
        .expect("recursive verifier request construction failed");

    let source = "
        use miden::core::sys
        use miden::core::sys::vm

        begin
            # Initial stack: [CLAIM_COMMITMENT].
            dupw
            procref.vm::verify_vm_proof exec.sys::build_proof_request_key
            adv.push_mapval dropw
            exec.vm::verify_vm_proof
            # => [D, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
            exec.sys::truncate_stack
        end
    ";

    let mut test = crate::build_test!(
        source,
        &verifier_inputs.initial_stack(),
        &verifier_inputs.advice_stack(),
        verifier_inputs.store,
        verifier_inputs.advice_map
    );
    test.libraries.push(CoreLibrary::default().package());
    test.execute().expect("recursive verifier execution failed");
}

#[test]
fn test_all_hash_functions_prove_verify() {
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    for (hash_fn, hash_name) in [
        (HashFunction::Blake3_256, "Blake3_256"),
        (HashFunction::Keccak, "Keccak"),
        (HashFunction::Rpo256, "RPO"),
        (HashFunction::Poseidon2, "Poseidon2"),
        (HashFunction::Rpx256, "RPX"),
    ] {
        assert_prove_verify(source, hash_fn, hash_name, false, false);
    }
}

#[test]
fn test_keccak_precompile_wrapper_prove_verify_final() {
    let core_lib = CoreLibrary::default();
    let input: Vec<u8> = (0u8..32).collect();
    let input = masm_push_felts(&bytes_to_packed_u32_elements(&input));
    let source = format!(
        "
        begin
            {input}
            exec.::miden::core::crypto::hashes::keccak256::hash
            dropw dropw
        end
        "
    );
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("keccak_precompile_wrapper_test", &source)
        .expect("failed to assemble Keccak precompile wrapper test")
        .unwrap_program();
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");

    let witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("processor initialization failed")
            .execute_for_proving_sync(&program, &mut host)
            .expect("failed to execute Keccak precompile program");
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Blake3_256)
        .prove_full(witness)
        .expect("failed to prove Keccak precompile execution");

    assert!(matches!(proof, ExecutionProof::Complete { precompile: Some(_), .. }));
    let claim = ExecutionClaim::from_program_info(program.into(), stack_inputs, stack_outputs);
    let outcome = Verifier::new().verify(&claim, &proof).expect("Verification failed");
    assert!(outcome.is_complete());
    assert_eq!(outcome.outstanding_precompile_root(), None);
}

/// Equal-heights regression: tiny program where every AIR lands at MIN_TRACE_LEN.
/// Catches mistakes in the MASM `air_order` reconstruction's tie-break rule.
#[test]
fn test_equal_heights_recursive() {
    let source = "
        begin
            push.1 drop
        end
    ";
    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", false, true);
}

/// Hash-heavy program where chiplets grow beyond the core trace. Regression for per-AIR-height
/// boundary handling on the sliced core trace.
#[test]
fn test_hash_heavy_divergent_heights() {
    let source = "
        begin
            padw padw padw
            repeat.20
                hperm
            end
            dropw dropw dropw
        end
    ";
    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3", false, false);
}

/// Exercises the MASM recursive verifier when the Poseidon2 permutation AIR is taller than the
/// core trace.
#[test]
fn test_hash_heavy_divergent_heights_recursive() {
    let source = "
        begin
            padw padw padw
            repeat.20
                hperm
            end
            dropw dropw dropw
        end
    ";
    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", false, true);
}

// PROVER API LIFECYCLE TESTS
// ================================================================================================

mod prover_api_lifecycle {
    use miden_assembly::Assembler;
    use miden_core::{
        Felt, Word, ZERO,
        deferred::{DeferredStateWire, Node, Tag, precompile_id},
    };
    use miden_vm::{
        DefaultHost, ExecutionClaim, ExecutionOptions, ExecutionProof, ExecutionWitness,
        FastProcessor, HashFunction, PrecompileProof, PrecompileWitness, Program, Prover,
        StackInputs, StackOutputs, StarkProof, VerificationError, Verifier, advice::AdviceInputs,
        precompile_witness_from_wire, prove_sync,
    };

    fn assemble(source: &str) -> Program {
        Assembler::default()
            .assemble_program("program", source)
            .expect("program should compile")
            .unwrap_program()
    }

    fn execute(program: &Program) -> ExecutionWitness {
        FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(program, &mut DefaultHost::default())
            .expect("execution should produce a witness")
    }

    fn word_literal(word: Word) -> String {
        format!(
            "[{}, {}, {}, {}]",
            word[0].as_canonical_u64(),
            word[1].as_canonical_u64(),
            word[2].as_canonical_u64(),
            word[3].as_canonical_u64(),
        )
    }

    fn u256_witness(value: u64) -> ExecutionWitness {
        let precompile_id = precompile_id("uint256");
        let value_tag = Tag::precompile(
            precompile_id,
            [
                Felt::new(0).expect("VALUE operation ID is a felt"),
                Felt::new(1).expect("U256 bound pointer is a felt"),
                ZERO,
            ],
        )
        .expect("uint precompile ID is not reserved");
        let mut value_chunk = [ZERO; 8];
        value_chunk[0] = Felt::new(value).expect("test U256 value is a felt");
        let value_digest = Node::value(value_tag, value_chunk)
            .expect("U256 value node should be valid")
            .digest();
        let equality_tag = Tag::precompile(
            precompile_id,
            [Felt::new(4).expect("EQ operation ID is a felt"), ZERO, ZERO],
        )
        .expect("uint precompile ID is not reserved");

        // This is the inlined equivalent of the core library's U256 `push_*_digest`, `assert_eq`,
        // `precompiles::register_expr`, and `precompiles::log_deferred` procedures. The processor's
        // built-in registry seeds the constant U256 value nodes used here.
        let source = format!(
            "begin\n\
                 push.{}\n\
                 push.{}\n\
                 push.{}\n\
                 movdnw.2\n\
                 adv.register_deferred\n\
                 hperm\n\
                 swapw.2 dropw dropw\n\
                 padw padw movdnw.2\n\
                 log_deferred\n\
                 dropw dropw dropw\n\
             end",
            word_literal(value_digest),
            word_literal(value_digest),
            word_literal(equality_tag.as_word().into()),
        );

        execute(&assemble(&source))
    }

    fn assert_complete(
        program: &Program,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        proof: &ExecutionProof,
    ) {
        let claim =
            ExecutionClaim::from_program_info(program.to_info(), stack_inputs, stack_outputs);
        let outcome = Verifier::new()
            .verify(&claim, proof)
            .expect("complete execution proof should verify");
        assert_eq!(outcome.security_level(), 96);
        assert!(outcome.is_complete());
        assert_eq!(outcome.outstanding_precompile_root(), None);
    }

    #[test]
    fn configured_prove_sync_matches_buffered_and_overlapped_routes() {
        let program = assemble("begin push.1 drop end");
        let stack_inputs = StackInputs::default();
        let prover = Prover::new().with_hash_fn(HashFunction::Blake3_256);
        let execution_options = ExecutionOptions::default()
            .with_core_trace_fragment_size(1)
            .expect("one-row trace fragments should be supported");

        let mut buffered_host = DefaultHost::default();
        let (buffered_outputs, buffered_proof) = prove_sync(
            &prover,
            &program,
            stack_inputs,
            AdviceInputs::default(),
            &mut buffered_host,
            execution_options.with_overlapped_trace_build(false),
        )
        .expect("buffered execute-and-prove should succeed");

        let mut overlapped_host = DefaultHost::default();
        let (overlapped_outputs, overlapped_proof) = prove_sync(
            &prover,
            &program,
            stack_inputs,
            AdviceInputs::default(),
            &mut overlapped_host,
            execution_options.with_overlapped_trace_build(true),
        )
        .expect("overlapped execute-and-prove should succeed");

        assert_eq!(buffered_outputs, overlapped_outputs);

        // Parallel proof-of-work grinding may select different valid witnesses, so verify both
        // proofs instead of requiring byte-identical encodings.
        assert_complete(&program, stack_inputs, buffered_outputs, &buffered_proof);
        assert_complete(&program, stack_inputs, overlapped_outputs, &overlapped_proof);
    }

    #[test]
    fn delegated_and_merged_precompile_proving_composes_across_transport() {
        let one_witness = u256_witness(1);
        let one_claim = one_witness.claim();
        let one_deferred = Prover::new()
            .with_hash_fn(HashFunction::Blake3_256)
            .prove(one_witness)
            .expect("root-one execution should produce a deferred proof");
        let ExecutionProof::Deferred { vm: one_vm, .. } = &one_deferred else {
            panic!("root-one execution should remain deferred");
        };
        let one_root = one_vm.precompile_root;
        let deferred_outcome = Verifier::new()
            .verify(&one_claim, &one_deferred)
            .expect("deferred VM proof should verify");
        assert_eq!(deferred_outcome.outstanding_precompile_root(), Some(one_root));

        let unrelated_wire = ExecutionProof::Deferred {
            vm: one_vm.clone(),
            precompile: DeferredStateWire::default(),
        };
        let unrelated_outcome = Verifier::new()
            .verify(&one_claim, &unrelated_wire)
            .expect("deferred verification should authenticate only the VM root");
        assert_eq!(unrelated_outcome.outstanding_precompile_root(), Some(one_root));

        let two_witness = u256_witness(2);
        let two_claim = two_witness.claim();
        let two_deferred = Prover::new()
            .with_hash_fn(HashFunction::Blake3_256)
            .prove(two_witness)
            .expect("root-two execution should produce a deferred proof");

        let one_encoded = one_deferred.to_bytes();
        let one_transported = ExecutionProof::read_from_bytes(&one_encoded)
            .expect("root-one deferred proof transport should decode without hydrating its wire");
        let two_transported = ExecutionProof::read_from_bytes(&two_deferred.to_bytes())
            .expect("root-two deferred proof transport should decode without hydrating its wire");

        let ExecutionProof::Deferred { precompile: one_wire, .. } = &one_transported else {
            panic!("transported root-one proof should remain deferred");
        };
        let ExecutionProof::Deferred { vm: two_vm, precompile: two_wire } = &two_transported else {
            panic!("transported root-two proof should remain deferred");
        };
        let two_root = two_vm.precompile_root;
        let one_witness = precompile_witness_from_wire(one_wire)
            .expect("transported root-one wire should hydrate under the standard registry");
        let two_witness = precompile_witness_from_wire(two_wire)
            .expect("transported root-two wire should hydrate under the standard registry");

        let merged = PrecompileWitness::merge(vec![one_witness.clone(), one_witness, two_witness])
            .expect("ordered singleton witnesses should merge");
        let ordered_roots = vec![one_root, one_root, two_root];

        let shared_precompile = Prover::new()
            .with_hash_fn(HashFunction::Poseidon2)
            .prove_precompile(&merged)
            .expect("merged precompile witness should prove once");
        assert_eq!(shared_precompile.roots, ordered_roots);

        let verifier = Verifier::new();
        assert_eq!(
            verifier
                .verify_precompile(&shared_precompile, one_root)
                .expect("shared precompile proof should directly verify root one"),
            96
        );

        assert_eq!(
            verifier
                .verify_precompile(&shared_precompile, two_root)
                .expect("compatible extra roots should directly verify root two"),
            96
        );

        let mut reordered_precompile = shared_precompile.clone();
        reordered_precompile.roots.swap(1, 2);
        assert!(matches!(
            verifier.verify_precompile(&reordered_precompile, one_root),
            Err(VerificationError::PrecompileStarkVerification(_))
        ));

        let mut missing_duplicate_precompile = shared_precompile.clone();
        missing_duplicate_precompile.roots.remove(1);
        assert!(matches!(
            verifier.verify_precompile(&missing_duplicate_precompile, one_root),
            Err(VerificationError::PrecompileStarkVerification(_))
        ));

        let mut mutated_vm_root = one_transported.clone();
        let ExecutionProof::Deferred { vm, .. } = &mut mutated_vm_root else {
            panic!("transported root-one proof should remain deferred");
        };
        vm.precompile_root = two_root;
        let mutated_vm_root = mutated_vm_root
            .complete(shared_precompile.clone())
            .expect("completion should attach a compatible precompile proof");
        assert!(matches!(
            verifier.verify(&one_claim, &mutated_vm_root),
            Err(VerificationError::StarkVerificationError(..))
        ));

        let mut trailing_vm_bytes = one_vm.proof.bytes().to_vec();
        trailing_vm_bytes.push(0);
        let trailing_vm_proof = ExecutionProof::Deferred {
            vm: miden_vm::VmProof {
                proof: StarkProof::new(trailing_vm_bytes, one_vm.proof.hash_fn()),
                precompile_root: one_root,
            },
            precompile: DeferredStateWire::default(),
        };
        assert!(matches!(
            verifier.verify(&one_claim, &trailing_vm_proof),
            Err(VerificationError::StarkVerificationError(..))
        ));

        let invalid_complete = one_transported
            .clone()
            .complete(PrecompileProof {
                proof: StarkProof::new(vec![0, 0], HashFunction::Poseidon2),
                roots: vec![one_root],
            })
            .expect("completion should only attach the precompile proof");
        let error = Verifier::new()
            .verify(&one_claim, &invalid_complete)
            .expect_err("the verifier should reject an invalid precompile STARK");
        assert!(matches!(error, VerificationError::PrecompileStarkVerification(_)));

        let one_complete = one_transported
            .complete(shared_precompile.clone())
            .expect("shared proof should complete the root-one execution");
        let two_complete = two_transported
            .complete(shared_precompile)
            .expect("shared proof should complete the root-two execution");
        let one_outcome = Verifier::new()
            .verify(&one_claim, &one_complete)
            .expect("completed root-one execution should verify");
        let two_outcome = Verifier::new()
            .verify(&two_claim, &two_complete)
            .expect("completed root-two execution should verify");
        assert!(one_outcome.is_complete());
        assert!(two_outcome.is_complete());
    }
}
