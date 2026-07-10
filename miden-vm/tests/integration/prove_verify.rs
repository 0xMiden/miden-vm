//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager, Linkage};
use miden_core::{
    Felt,
    deferred::{DeferredState, TRUE_DIGEST},
    proof::{DeferredProof, ExecutionProof},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::CoreLibrary;
use miden_processor::ExecutionOptions;
use miden_prover::{
    AdviceInputs, ProgramInfo, ProvingOptions, PublicInputs, StackInputs, StackOutputs, prove_sync,
};
use miden_utils_testing::{recursive_verifier::generate_advice_inputs, stack_inputs_from_ints};
use miden_verifier::Verifier;
use miden_vm::{DefaultHost, HashFunction};

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
    let options = ProvingOptions::with_96_bit_security(hash_fn);

    println!("Proving with {hash_name}...");
    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("Proving failed");

    println!("Proof generated successfully!");
    if print_stack_outputs {
        println!("Stack outputs: {stack_outputs:?}");
    }

    let proof = if verify_recursively {
        assert_recursive_verify(program.to_info(), stack_inputs, stack_outputs, proof)
    } else {
        proof
    };

    println!("Verifying proof...");
    let security_level = Verifier::new()
        .verify(program.into(), stack_inputs, stack_outputs, proof)
        .expect("Verification failed");

    println!("Verification successful! Security level: {security_level}");
}

fn assert_recursive_verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> ExecutionProof {
    let stark_proof = proof.miden_proof();
    let deferred_proof = proof.deferred_proof();
    assert_eq!(stark_proof.hash_fn(), HashFunction::Poseidon2);

    let final_deferred_root = match deferred_proof {
        DeferredProof::Empty => TRUE_DIGEST,
        DeferredProof::Wire(wire) => {
            DeferredState::from_wire(Arc::new(miden_precompiles::registry()), wire, usize::MAX)
                .expect("deferred wire should rehydrate under official precompiles")
                .root()
        },
        DeferredProof::Stark { .. } => {
            panic!("recursive verifier does not support deferred STARK proofs")
        },
    };
    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, final_deferred_root);
    let verifier_inputs = generate_advice_inputs(stark_proof.bytes(), pub_inputs)
        .expect("recursive verifier advice construction failed");

    let source = "
        use miden::core::sys::vm

        # Copy `count` felts (a multiple of 4) from the advice tape into memory starting at `dst`.
        #   Input:  [dst, count, ...]
        #   Output: [...]
        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                # [dst, count, ...]
                padw adv_loadw
                # [w0, w1, w2, w3, dst, count, ...]
                dup.4 mem_storew_le dropw
                # [dst, count, ...]
                add.4
                # [dst+4, count, ...]
                swap sub.4 swap
                # [dst+4, count-4, ...]
                dup.1 push.0 neq
            end
            drop drop
        end

        begin
            # Initial stack: [kernel_ptr, num_kernel_digests, stack_io_ptr, PROG0..3].

            # Copy kernel digests (4·num_kernel_digests felts) from advice into the caller region
            # (kernel_ptr = 0). Build [dst=0, count=4N].
            dup.1 mul.4 push.0
            exec.copy_advice_to_mem

            # Copy stack i/o (32 felts) from advice into the caller region (stack_io_ptr = 4096).
            # Build [dst=4096, count=32].
            push.32 push.4096
            exec.copy_advice_to_mem

            exec.vm::verify_proof
        end
    ";

    let mut test = crate::build_test!(
        source,
        &verifier_inputs.initial_stack,
        &verifier_inputs.advice_stack,
        verifier_inputs.store,
        verifier_inputs.advice_map
    );
    test.libraries.push(CoreLibrary::default().package());
    test.execute().expect("recursive verifier execution failed");

    proof
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

    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
    )
    .expect("Keccak precompile wrapper should prove");

    assert!(proof.is_final());
    assert!(matches!(proof.deferred_proof(), DeferredProof::Stark { .. }));
    Verifier::new()
        .verify(program.into(), stack_inputs, stack_outputs, proof)
        .expect("Verification failed");
}

#[test]
fn test_blake3_256_prove_verify() {
    // Compute many Fibonacci iterations to generate a trace >= 2048 rows
    let source = "
        begin
            repeat.1000
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3_256", false, false);
}

#[test]
fn test_keccak_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Keccak, "Keccak", true, false);
}

#[test]
fn test_rpo_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpo256, "RPO", true, false);
}

#[test]
fn test_poseidon2_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true, true);
}

/// Sanity test that the multi-AIR Rust prover + Rust verifier work end-to-end with Poseidon2,
/// independent of the MASM recursive verifier path.
#[test]
fn test_poseidon2_prove_verify_rust_only() {
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true, false);
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

/// Test end-to-end proving and verification with RPX
#[test]
fn test_rpx_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpx256, "RPX", true, false);
}

// ================================================================================================
// FAST PROCESSOR + PARALLEL TRACE GENERATION TESTS
// ================================================================================================

mod fast_parallel {
    use alloc::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::{
        mast::{
            BasicBlockNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder, MastForest, MastNodeExt,
        },
        operations::Operation,
        proof::{DeferredProof, ExecutionProof, HashFunction},
        Word,
    };
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, HostLibrary, StackInputs,
        advice::AdviceInputs,
        trace::build_trace,
    };
    use miden_prover::{
        ProvingOptions, TraceProvingInputs, config, prove_from_trace_sync,
        prove_partial_from_trace_sync, prove_stark,
        serde::{Deserializable, Serializable},
    };
    use miden_verifier::{VerificationError, Verifier, verify};
    use miden_vm::{Program, TraceBuildInputs};

    /// Default fragment size for parallel trace generation
    const FRAGMENT_SIZE: usize = 1024;

    fn parallel_execution_options() -> ExecutionOptions {
        ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap()
    }

    fn execute_parallel_trace_inputs(
        program: &Program,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        host: &mut DefaultHost,
    ) -> TraceBuildInputs {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, parallel_execution_options())
            .expect("processor should initialize with built-in precompiles")
            .execute_trace_inputs_sync(program, host)
            .expect("Fast processor execution failed")
    }

    fn default_source_manager_host() -> DefaultHost {
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    fn create_simple_library() -> HostLibrary {
        let mut mast_forest = MastForest::new();
        let swap_block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(swap_block);
        HostLibrary::from(Arc::new(mast_forest))
    }

    fn external_lib_proc_digest() -> Word {
        let mut forest = MastForest::new();
        let swap_block = BasicBlockNodeBuilder::new(vec![Operation::Swap, Operation::Swap])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.get_node_by_id(swap_block).unwrap().digest()
    }

    fn external_program() -> Program {
        let mut program = MastForest::new();
        let basic_block = BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop])
            .add_to_forest(&mut program)
            .unwrap();
        let external_node = ExternalNodeBuilder::new(external_lib_proc_digest())
            .add_to_forest(&mut program)
            .unwrap();
        let root = JoinNodeBuilder::new([basic_block, external_node])
            .add_to_forest(&mut program)
            .unwrap();
        program.make_root(root);
        Program::new(Arc::new(program), root)
    }

    /// Test that proves and verifies using the fast processor + parallel trace generation path.
    /// This verifies the complete code path works end-to-end.
    ///
    /// Note: We only test one hash function here since
    /// `test_trace_equivalence_slow_vs_fast_parallel` verifies trace equivalence, and the slow
    /// processor tests already cover all hash functions.
    #[test]
    fn test_fast_parallel_prove_verify() {
        // Use a program with enough iterations to generate a meaningful trace
        let source = "
            begin
                repeat.500
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = miden_utils_testing::stack_inputs_from_ints([0, 1]);
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let fast_stack_outputs = *trace_inputs.stack_outputs();

        // Build trace using parallel trace generation
        let trace = build_trace(trace_inputs).unwrap();

        // Build public inputs
        let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();

        // Per-AIR matrices for prove_multi.
        let (core_matrix, chiplets_matrix, poseidon2_matrix) = trace.to_air_matrices();

        // Generate proof using Blake3_256
        let blake3_config =
            config::blake3_256_config(config::pcs_params(), config::RELATION_DIGEST);
        let proof_bytes = prove_stark(
            &blake3_config,
            core_matrix,
            chiplets_matrix,
            poseidon2_matrix,
            &public_values,
            &aux_inputs,
        )
        .expect("Proving failed");

        assert_eq!(trace.deferred_state().root(), miden_core::deferred::TRUE_DIGEST);

        let proof =
            ExecutionProof::from_parts(proof_bytes, HashFunction::Blake3_256, DeferredProof::Empty);

        // Verify the proof
        Verifier::new()
            .verify(program.into(), stack_inputs, fast_stack_outputs, proof)
            .expect("Verification failed");
    }

    #[test]
    fn test_prove_from_trace_sync() {
        let source = "
            begin
                repeat.128
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = miden_utils_testing::stack_inputs_from_ints([0, 1]);
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        assert!(proof.is_final());
        assert_eq!(proof.deferred_proof(), &DeferredProof::Empty);
        Verifier::new()
            .verify(program.into(), stack_inputs, stack_outputs, proof)
            .expect("Verification failed");
    }

    #[test]
    fn test_trace_proving_inputs_round_trip_proves_external_library_program() {
        std::thread::Builder::new()
            .name("trace-proving-inputs-round-trip".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(trace_proving_inputs_round_trip_proves_external_library_program)
            .expect("failed to spawn round-trip test thread")
            .join()
            .expect("round-trip test thread panicked");
    }

    fn trace_proving_inputs_round_trip_proves_external_library_program() {
        let program = external_program();
        let stack_inputs = StackInputs::default();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        host.load_library(create_simple_library())
            .expect("failed to load test library into host");
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let trace_inputs_bytes = trace_inputs.to_bytes();
        let original_trace = build_trace(trace_inputs).expect("original trace inputs build trace");
        let restored_trace_inputs = TraceBuildInputs::read_from_bytes(&trace_inputs_bytes)
            .expect("trace inputs round trip");
        assert!(
            restored_trace_inputs.trace_generation_context().mast_forest_store.len() > 1,
            "expected dynamic library execution to serialize multiple MAST forests"
        );
        let restored_trace =
            build_trace(restored_trace_inputs).expect("restored trace inputs build trace");
        assert_eq!(restored_trace.stack_outputs(), original_trace.stack_outputs());
        assert_eq!(restored_trace.program_info(), original_trace.program_info());
        assert_eq!(restored_trace.trace_len_summary(), original_trace.trace_len_summary());
        assert_eq!(
            restored_trace.public_inputs().to_air_inputs(),
            original_trace.public_inputs().to_air_inputs()
        );

        let trace_inputs = TraceBuildInputs::read_from_bytes(&trace_inputs_bytes)
            .expect("trace inputs round trip");
        let proving_inputs = TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        );
        let proving_inputs_bytes = proving_inputs.to_bytes();
        let proving_inputs_budget =
            proving_inputs_bytes.len().checked_mul(4).expect("test input budget overflow");
        let mut proving_inputs_with_trailing_byte = proving_inputs_bytes.clone();
        proving_inputs_with_trailing_byte.push(0);
        let err = TraceProvingInputs::read_from_bytes_with_budget(
            &proving_inputs_with_trailing_byte,
            proving_inputs_with_trailing_byte
                .len()
                .checked_mul(4)
                .expect("test input budget overflow"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("TraceProvingInputs payload has trailing bytes"));
        let restored_proving_inputs = TraceProvingInputs::read_from_bytes_with_budget(
            &proving_inputs_bytes,
            proving_inputs_budget,
        )
        .expect("trace proving inputs round trip");

        let (stack_outputs, proof) =
            prove_from_trace_sync(restored_proving_inputs).expect("prove_from_trace_sync failed");

        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");
    }

    #[test]
    fn test_prove_partial_from_trace_sync_preserves_deferred_wire() {
        let source = "begin log_deferred end";
        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = StackInputs::default();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);
        let expected_deferred_root = trace_inputs.deferred_state().root();
        let expected_wire = trace_inputs
            .deferred_state()
            .to_wire()
            .expect("deferred state should serialize to wire");
        assert!(
            !expected_wire.entries.is_empty(),
            "log_deferred should advance the deferred root"
        );

        let (stack_outputs, proof) = prove_partial_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_partial_from_trace_sync failed");

        assert!(!proof.is_final());
        assert_eq!(proof.deferred_proof(), &DeferredProof::Wire(expected_wire.clone()));

        let err = Verifier::new()
            .verify(program.to_info(), stack_inputs, stack_outputs, proof.clone())
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::UnsupportedDeferredProof),
            "wire-backed partial proofs should be rejected by final verification, got {err:?}"
        );

        let (security_level, hydrated_state) = Verifier::new()
            .verify_partial(program.to_info(), stack_inputs, stack_outputs, proof)
            .expect("wire-backed partial proof should verify and hydrate deferred state");
        assert_eq!(security_level, 96);
        assert_eq!(hydrated_state.root(), expected_deferred_root);
        assert_eq!(
            hydrated_state.to_wire().expect("hydrated state should serialize to wire"),
            expected_wire
        );
    }
}
