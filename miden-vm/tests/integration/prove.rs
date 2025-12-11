use miden_utils_testing::build_test;
use miden_vm::{HashFunction, ProvingOptions};

// POSEIDON2 PROVING TESTS
// ================================================================================================
// Full end-to-end tests for Poseidon2 proving and verification.

#[test]
fn test_prove_simple_program_with_poseidon2() {
    let test = build_test!("begin push.5 push.3 add drop end");
    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);

    // This will execute, prove with Poseidon2, and verify
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_prove_arithmetic_with_poseidon2() {
    // Test various arithmetic operations
    let test = build_test!("
        begin
            push.10 push.5 add     # 15
            push.3 mul             # 45
            push.5 sub             # 40
            push.2 div             # 20
            drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_prove_loops_with_poseidon2() {
    // Test program with loops (generates more trace rows)
    let test = build_test!("
        begin
            push.0
            repeat.8
                push.1 add
            end
            drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_prove_stack_manipulation_with_poseidon2() {
    // Test stack operations
    let test = build_test!("
        begin
            push.1 push.2 push.3 push.4
            swap        # [4,3,2,1, ...]
            dup.1       # [3,4,3,2,1, ...]
            movup.2     # [2,3,4,3,1, ...]
            drop drop drop drop drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_prove_conditional_with_poseidon2() {
    // Test conditional execution
    let test = build_test!("
        begin
            push.1
            if.true
                push.10
            else
                push.20
            end
            drop drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_prove_with_stack_inputs_poseidon2() {
    // Test with initial stack inputs
    let test = build_test!("
        begin
            add  # Add top two elements from input
            drop
        end
    ", &[5, 3]);

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![5, 3], options, false);
}

#[test]

fn test_prove_fibonacci_with_poseidon2() {
    // Compute 10th Fibonacci number
    let test = build_test!("
        begin
            push.10  # n
            push.0   # fib(0)
            push.1   # fib(1)

            repeat.8
                dup.1
                add
                swap
                drop
            end

            # Result is fib(10) = 55
            # Stack: [55, 34, 10, 0...]
            drop drop drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]
#[ignore = "longer execution time"]
fn test_prove_large_program_with_poseidon2() {
    // Test with a larger program that generates more trace rows
    let test = build_test!("
        begin
            push.1
            repeat.20
                push.1 add
            end
            drop
        end
    ");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options, false);
}

#[test]

fn test_poseidon2_96_vs_128_bit_security() {
    // Test that both security levels work
    let test = build_test!("begin push.1 push.2 add drop end");

    // 96-bit security
    let options_96 = ProvingOptions::with_96_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options_96, false);

    // 128-bit security
    let options_128 = ProvingOptions::with_128_bit_security(HashFunction::Poseidon2);
    test.prove_and_verify_with_options(vec![], options_128, false);
}
