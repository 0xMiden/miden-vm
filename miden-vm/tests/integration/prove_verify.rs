//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_prover::{AdviceInputs, HashFunction, ProvingOptions, StackInputs, prove_sync};
use miden_verifier::verify;
use miden_vm::DefaultHost;

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

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Blake3_256 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    println!("Proving with Blake3_256...");
    let (stack_outputs, proof) =
        prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Verifying proof...");

    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
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

    // Compile the program
    let program = Assembler::default().assemble_program(source).unwrap();

    // Prepare inputs - start with 0 and 1 on the stack for Fibonacci
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Keccak (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Keccak);

    // Prove the program
    println!("Proving with Keccak...");
    let (stack_outputs, proof) =
        prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    // Verify the proof
    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
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

    // Compile the program
    let program = Assembler::default().assemble_program(source).unwrap();

    // Prepare inputs - start with 0 and 1 on the stack for Fibonacci
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with RPO (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Rpo256);

    // Prove the program
    println!("Proving with RPO...");
    let (stack_outputs, proof) =
        prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    // Verify the proof
    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
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

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Poseidon2 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);

    println!("Proving with Poseidon2...");
    let (stack_outputs, proof) =
        prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
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

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with RPX (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Rpx256);

    println!("Proving with RPX...");
    let (stack_outputs, proof) =
        prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
}

// ================================================================================================
// FAST PROCESSOR + PARALLEL TRACE GENERATION TESTS
// ================================================================================================

mod fast_parallel {
    use alloc::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::Felt;
    use miden_processor::{
        AdviceInputs, ExecutionOptions, StackInputs, fast::FastProcessor, parallel::build_trace,
    };
    use miden_prover::{
        ExecutionProof, HashFunction, ProcessorAir, config, execution_trace_to_row_major, stark,
    };
    use miden_verifier::verify;
    use miden_vm::DefaultHost;

    /// Default fragment size for parallel trace generation
    const FRAGMENT_SIZE: usize = 1024;

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

        let program = Assembler::default().assemble_program(source).unwrap();
        let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
        let advice_inputs = AdviceInputs::default();
        let mut host =
            DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

        let stack_inputs_vec: Vec<Felt> = stack_inputs.into_iter().collect();

        let options = ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap();
        let fast_processor =
            FastProcessor::new_with_options(&stack_inputs_vec, advice_inputs.clone(), options);
        let (execution_output, trace_context) = fast_processor
            .execute_for_trace_sync(&program, &mut host)
            .expect("Fast processor execution failed");

        let fast_stack_outputs = execution_output.stack;

        // Build trace using parallel trace generation
        let trace =
            build_trace(execution_output, trace_context, program.hash(), program.kernel().clone());

        // Convert trace to row-major format for proving
        let trace_matrix = execution_trace_to_row_major(&trace);
        let public_values = trace.to_public_values();

        // Create AIR with aux trace builders
        let air = ProcessorAir::with_aux_builder(trace.aux_trace_builders().clone());

        // Generate proof using Blake3_256
        let config = config::create_blake3_256_config();
        let proof = stark::prove(&config, &air, &trace_matrix, &public_values);
        let proof_bytes = bincode::serialize(&proof).expect("Failed to serialize proof");

        let precompile_requests = trace.precompile_requests().to_vec();

        let proof = ExecutionProof::new(proof_bytes, HashFunction::Blake3_256, precompile_requests);

        // Verify the proof
        verify(program.into(), stack_inputs, fast_stack_outputs, proof)
            .expect("Verification failed");
    }
}
