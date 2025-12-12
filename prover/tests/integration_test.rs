//! Integration tests for the unified prove/verify flow

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_prover::{AdviceInputs, HashFunction, ProvingOptions, StackInputs, prove};
use miden_verifier::verify;
use miden_vm::DefaultHost;

extern crate alloc;

/// Test end-to-end proving and verification with Blake3
#[test]
fn test_blake3_prove_verify() {
    // Compute many Fibonacci iterations to generate a trace >= 2048 rows
    // Each iteration adds a few rows, so we need many iterations
    let source = "
        begin
            repeat.1000
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

    // Create proving options with Blake3 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    // Prove the program
    println!("Proving with Blake3...");
    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    println!("Proof generated successfully!");

    // Verify the proof
    println!("Verifying proof...");

    let result = verify(program.into(), stack_inputs, stack_outputs, proof);

    match result {
        Ok(security_level) => {
            println!("Verification successful! Security level: {}", security_level);
        },
        Err(e) => {
            println!("Verification failed with error: {:?}", e);
            panic!("Verification failed");
        },
    }
}

/// Test end-to-end proving and verification with Keccak
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
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    // Verify the proof
    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
}

/// Regression test for range checker constraints
/// This test exercises the range checker by running a longer computation that stresses
/// the V column constraints and range checker bus constraints.
#[test]
fn test_range_checker_constraints() {
    // Fibonacci computation generates a long trace with range checker activity
    // The longer trace ensures we properly test the V column boundary constraints
    // (V[0] = 0, V[last] = 65535) and the degree-8 transition constraints
    let source = "
        begin
            repeat.500
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

    // Create proving options with Blake3 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    // Prove the program
    println!("Testing range checker constraints...");
    let (stack_outputs, proof) = prove(&program, stack_inputs, advice_inputs, &mut host, options)
        .expect("Proving failed - range checker constraints may be broken");

    println!("✓ Proof generated successfully!");

    // Verify the proof
    println!("Verifying proof...");
    let security_level = verify(program.into(), stack_inputs, stack_outputs, proof)
        .expect("Verification failed - range checker constraints may be broken");

    println!("✓ Verification successful! Security level: {}", security_level);
}

/// Benchmark test with 2^16 trace length for realistic performance numbers
#[test]
#[ignore] // Run with: cargo test --release benchmark_64k -- --ignored --nocapture
fn benchmark_64k_trace() {
    // Each iteration adds ~4 rows, so we need ~16k iterations for 2^16 rows
    let source = "
        begin
            repeat.16000
                swap dup.1 add
            end
        end
    ";

    println!("\n=== Benchmark: 2^16 (~65536) trace length ===");
    println!("Running Fibonacci with 16000 iterations...\n");

    // Compile the program
    let program = Assembler::default().assemble_program(source).unwrap();

    // Prepare inputs
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Blake3 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    // Prove the program
    println!("Proving with Blake3 (96-bit security)...");
    let start = std::time::Instant::now();

    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    let proving_time = start.elapsed();
    println!("✓ Proof generated in {:.2?}", proving_time);

    // Get proof size
    let proof_size = proof.to_bytes().len();
    println!("  Proof size: {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);

    // Verify the proof
    println!("\nVerifying proof...");
    let start = std::time::Instant::now();

    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    let verification_time = start.elapsed();
    println!("✓ Verification successful in {:.2?}", verification_time);
    println!("  Security level: {}", security_level);

    println!("\n=== Benchmark Summary ===");
    println!("Proving time:      {:.2?}", proving_time);
    println!("Verification time: {:.2?}", verification_time);
    println!("Proof size:        {:.2} KB", proof_size as f64 / 1024.0);
}

/// Benchmark: Blake3 1-to-1 hash (100 iterations)
/// This matches the example from masm-examples/hashing/blake3_1to1
#[test]
#[ignore] // Run with: cargo test --release blake3_1to1_benchmark -- --ignored --nocapture
fn blake3_1to1_benchmark() {
    let source = "
        use.std::crypto::hashes::blake3
        use.std::sys

        begin
            # Push the number of iterations on the stack, and assess if we should loop
            adv_push.1 dup neq.0
            # => [0 or 1, num_iters_left, HASH_INPUTS_1, HASH_INPUTS_2]

            while.true
                # Move loop counter down
                movdn.8
                # => [HASH_INPUTS_1, HASH_INPUTS_2, num_iters_left]

                # Execute blake3 hash function
                exec.blake3::hash_1to1
                # => [HASH_INPUTS_1', HASH_INPUTS_2', num_iters_left]

                # Decrement counter, and check if we loop again
                movup.8 sub.1 dup neq.0
                # => [0 or 1, num_iters_left - 1, HASH_INPUTS_1', HASH_INPUTS_2']
            end

            # Drop counter
            drop

            # Truncate stack to make constraints happy
            exec.sys::truncate_stack
        end
    ";

    println!("\n=== Benchmark: Blake3 1-to-1 Hash (100 iterations) ===");
    println!("This benchmark matches the masm-examples/hashing/blake3_1to1 example\n");

    // Compile the program
    let program = Assembler::default().with_debug_mode(false).assemble_program(source).unwrap();

    // Prepare inputs - all 0xFFFFFFFF values on stack, 100 iterations in advice
    let stack_inputs = StackInputs::try_from_ints([
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    ])
    .unwrap();

    let advice_inputs = AdviceInputs::default().with_stack_values(vec![100]).unwrap();

    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Blake3 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    // Prove the program
    println!("Proving with Blake3 (96-bit security)...");
    let start = std::time::Instant::now();

    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    let proving_time = start.elapsed();
    println!("✓ Proof generated in {:.2?}", proving_time);

    // Get proof size
    let proof_size = proof.to_bytes().len();
    println!("  Proof size: {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);

    // Verify the proof
    println!("\nVerifying proof...");
    let start = std::time::Instant::now();

    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    let verification_time = start.elapsed();
    println!("✓ Verification successful in {:.2?}", verification_time);
    println!("  Security level: {}", security_level);

    println!("\n=== Benchmark Summary ===");
    println!("Proving time:      {:.2?}", proving_time);
    println!("Verification time: {:.2?}", verification_time);
    println!("Proof size:        {:.2} KB", proof_size as f64 / 1024.0);
}
