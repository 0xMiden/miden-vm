//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager, Linkage};
use miden_core::{Word, deferred::DeferredStateWire, proof::ExecutionProof};
use miden_core_lib::CoreLibrary;
use miden_lifted_stark::InstanceShapes;
use miden_processor::ExecutionOptions;
use miden_prover::{
    AdviceInputs, ProgramInfo, ProvingOptions, PublicInputs, StackInputs, StackOutputs,
};
use miden_verifier::{verify, verify_with_precompiles};
use miden_vm::{DefaultHost, HashFunction, PrecompilesLibrary, Program, prove_sync};
use serde_wincode::SerdeCompat;

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
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
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

    if verify_recursively {
        assert_recursive_verify(
            program.to_info(),
            stack_inputs,
            stack_outputs,
            Word::empty(),
            &proof,
        );
    }

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {security_level}");
}

fn assert_recursive_verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    final_deferred_root: Word,
    proof: &ExecutionProof,
) {
    assert_eq!(proof.hash_fn(), HashFunction::Poseidon2);

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, final_deferred_root);
    let verifier_inputs = miden_utils_testing::recursive_verifier::generate_advice_inputs(
        proof.stark_proof(),
        pub_inputs,
    )
    .expect("recursive verifier advice construction failed");

    let source = "
        use miden::core::sys::vm
        begin
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

/// Equal-heights regression: tiny program where both AIRs land at MIN_TRACE_LEN.
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

#[test]
fn rejects_non_canonical_air_order() {
    let source = "
        begin
            push.1 drop
        end
    ";
    let program = Assembler::default().assemble_program("test", source).unwrap().unwrap_program();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);

    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("Proving failed");

    let mut tampered_proof_bytes = proof.stark_proof().to_vec();
    flip_serialized_air_order(&mut tampered_proof_bytes);
    let tampered_proof = ExecutionProof::new(
        tampered_proof_bytes,
        HashFunction::Poseidon2,
        DeferredStateWire::default(),
    );

    let result = verify(program.into(), stack_inputs, stack_outputs, tampered_proof);
    assert!(result.is_err(), "non-canonical air_order must be rejected");
}

/// Hash-heavy program where `chip_height > core_height`. Regression for the
/// per-AIR-height boundary handling on the SLICED Core trace.
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

fn flip_serialized_air_order(proof_bytes: &mut [u8]) {
    // `StarkProof` serializes `instance_shapes` first, so the wincode encoding of
    // `InstanceShapes` is a byte-exact prefix of the proof; surgically flip the embedded
    // `air_order` from the canonical `[0, 1]` to `[1, 0]`.
    let shapes: InstanceShapes =
        <SerdeCompat<InstanceShapes> as wincode::config::Deserialize<_>>::deserialize(
            proof_bytes,
            wincode::config::Configuration::default(),
        )
        .expect("instance shapes prefix");
    assert_eq!(shapes.air_order(), &[0, 1], "test assumes canonical caller order");

    let serialized_shapes =
        <SerdeCompat<InstanceShapes> as wincode::config::Serialize<_>>::serialize(
            &shapes,
            wincode::config::Configuration::default(),
        )
        .expect("serialized shapes");
    assert!(proof_bytes.starts_with(&serialized_shapes));

    let canonical_order = <SerdeCompat<Vec<u32>> as wincode::config::Serialize<_>>::serialize(
        &vec![0u32, 1],
        wincode::config::Configuration::default(),
    )
    .expect("canonical order");
    let tampered_order = <SerdeCompat<Vec<u32>> as wincode::config::Serialize<_>>::serialize(
        &vec![1u32, 0],
        wincode::config::Configuration::default(),
    )
    .expect("tampered order");
    let offset = serialized_shapes
        .windows(canonical_order.len())
        .position(|window| window == canonical_order)
        .expect("air_order in instance shape prefix");
    proof_bytes[offset..offset + tampered_order.len()].copy_from_slice(&tampered_order);
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

#[test]
fn test_precompile_proof_carries_deferred_wire() {
    let (program, stack_inputs, stack_outputs, proof) =
        prove_keccak_precompile(HashFunction::Blake3_256);

    assert!(
        !proof.deferred_state().entries.is_empty(),
        "proof must carry the deferred-state opening for logged precompile predicates"
    );

    let precompiles = miden_precompiles::registry();
    let (security_level, final_deferred_root) = verify_with_precompiles(
        program.to_info(),
        stack_inputs,
        stack_outputs,
        proof.clone(),
        &precompiles,
    )
    .expect("verification with miden-precompiles registry failed");
    assert_ne!(
        final_deferred_root,
        Word::empty(),
        "precompile proof must bind a non-empty final root"
    );

    let vm_security_level = miden_vm::verify(program.into(), stack_inputs, stack_outputs, proof)
        .expect("miden-vm default verification should load miden-precompiles");
    assert_eq!(vm_security_level, security_level);
}

#[test]
fn test_precompile_proof_rejects_tampered_deferred_wire() {
    let (program, stack_inputs, stack_outputs, proof) =
        prove_keccak_precompile(HashFunction::Blake3_256);

    let tampered_proof = ExecutionProof::new(
        proof.stark_proof().to_vec(),
        proof.hash_fn(),
        DeferredStateWire::default(),
    );

    let result = miden_vm::verify(program.into(), stack_inputs, stack_outputs, tampered_proof);
    assert!(result.is_err(), "removing the deferred wire must break proof verification");
}

#[test]
fn test_poseidon2_recursive_verify_with_final_deferred_root() {
    let (program, stack_inputs, stack_outputs, proof) =
        prove_keccak_precompile(HashFunction::Poseidon2);
    let precompiles = miden_precompiles::registry();
    let (_, final_deferred_root) = verify_with_precompiles(
        program.to_info(),
        stack_inputs,
        stack_outputs,
        proof.clone(),
        &precompiles,
    )
    .expect("verification with miden-precompiles registry failed");

    assert_recursive_verify(
        program.to_info(),
        stack_inputs,
        stack_outputs,
        final_deferred_root,
        &proof,
    );

    miden_vm::verify(program.into(), stack_inputs, stack_outputs, proof)
        .expect("miden-vm default verification should load miden-precompiles");
}

fn prove_keccak_precompile(
    hash_fn: HashFunction,
) -> (Program, StackInputs, StackOutputs, ExecutionProof) {
    let source = "
        use miden::precompiles::crypto::hashes::keccak256

        begin
            push.8.7.6.5
            push.4.3.2.1
            push.100
            exec.keccak256::hash

            push.100 mem_loadw_le
            push.104 mem_loadw_le
        end
    ";

    let mut assembler = Assembler::default();
    assembler
        .link_package(PrecompilesLibrary::default().package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles");
    let program = assembler
        .assemble_program("precompile_keccak", source)
        .expect("failed to assemble Keccak precompile program")
        .unwrap_program();

    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default()
        .with_library(&PrecompilesLibrary::default())
        .expect("failed to load miden-precompiles into host");
    let options = ProvingOptions::with_96_bit_security(hash_fn);

    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("failed to prove Keccak precompile program");

    (program, stack_inputs, stack_outputs, proof)
}

// ================================================================================================
// FAST PROCESSOR + PARALLEL TRACE GENERATION TESTS
// ================================================================================================

mod fast_parallel {
    use alloc::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::proof::{ExecutionProof, HashFunction};
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
        trace::build_trace,
    };
    use miden_prover::{
        ProvingOptions, TraceProvingInputs, config, prove_from_trace_sync, prove_stark,
    };
    use miden_verifier::verify;
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
            .expect("processor advice inputs should fit advice map limits")
            .execute_trace_inputs_sync(program, host)
            .expect("Fast processor execution failed")
    }

    fn default_source_manager_host() -> DefaultHost {
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()))
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
        let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let fast_stack_outputs = *trace_inputs.stack_outputs();

        // Build trace using parallel trace generation
        let trace = build_trace(trace_inputs).unwrap();

        // Build public inputs
        let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();

        // Multi-AIR splitting: derive Core + Chiplets matrices for prove_multi.
        let (core_matrix, chiplets_matrix) = trace.to_core_chiplets_matrices();

        // Generate proof using Blake3_256
        let blake3_config = config::blake3_256_config(config::pcs_params());
        let proof_bytes = prove_stark(
            &blake3_config,
            &core_matrix,
            &chiplets_matrix,
            &public_values,
            &kernel_felts,
        )
        .expect("Proving failed");

        let deferred_wire =
            trace.deferred_state().to_wire().expect("deferred wire serialization failed");

        let proof = ExecutionProof::new(proof_bytes, HashFunction::Blake3_256, deferred_wire);

        // Verify the proof
        verify(program.into(), stack_inputs, fast_stack_outputs, proof)
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
        let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");
    }
}
