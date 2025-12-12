//! Integration tests for the unified prove/verify flow

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_prover::{AdviceInputs, HashFunction, ProvingOptions, StackInputs, prove};
use miden_verifier::verify;
use miden_vm::DefaultHost;

extern crate alloc;

#[test]
fn test_blake3_192_prove_verify() {
    // NOTE: Blake3_192 currently uses Blake3_256 config internally (32-byte output instead of 24-byte)
    // until Plonky3 adds support for CryptographicHasher<u8, [u8; 24]>.
    // TODO: Create an issue in 0xMiden/Plonky3 to add Blake3_192 support.

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

    // Create proving options with Blake3_192 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_192);

    println!("Proving with Blake3_192 (using Blake3_256 config)...");
    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Verifying proof...");

    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
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

    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));

    // Create proving options with Blake3_256 (96-bit security)
    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);

    println!("Proving with Blake3_256...");
    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

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
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

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

    // Create proving options with RPO (128-bit security)
    let options = ProvingOptions::with_128_bit_security(HashFunction::Rpo256);

    // Prove the program
    println!("Proving with RPO...");
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

    // Create proving options with Poseidon2 (128-bit security)
    let options = ProvingOptions::with_128_bit_security(HashFunction::Poseidon2);

    println!("Proving with Poseidon2...");
    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

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

    // Create proving options with RPX (128-bit security)
    let options = ProvingOptions::with_128_bit_security(HashFunction::Rpx256);

    println!("Proving with RPX...");
    let (stack_outputs, proof) =
        prove(&program, stack_inputs, advice_inputs, &mut host, options).expect("Proving failed");

    println!("Proof generated successfully!");
    println!("Stack outputs: {:?}", stack_outputs);

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
}
