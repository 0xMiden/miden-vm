/// Reproduction test for issue #2456: DecoratorId out of bounds
///
/// This test attempts to reproduce the exact scenario from the miden-base
/// `execute_tx_view_script` test that was failing with "DecoratorId out of bounds" error.
///
/// The original failing test from miden-base:
/// - Creates a library module with an exported `foo` procedure
/// - Calls that procedure after a `push.1.2` instruction
/// - The error occurred during execution (not compilation)
/// - Adding `drop drop` after the push made the error disappear
///
/// Note: This is a simplified version that doesn't use the full miden-base
/// transaction execution infrastructure. If this test passes but the miden-base
/// test fails, the issue likely involves specifics of the transaction context.
use miden_assembly::Assembler;
use miden_processor::{AdviceInputs, DefaultHost, ExecutionOptions, StackInputs};

#[test]
fn test_issue_2456_call_after_push_simplified() {
    // Simplified version: inline procedure instead of library
    let source = "
        proc foo
            push.3.4
            add
            swapw dropw
        end

        begin
            push.1.2
            call.foo
            dropw dropw dropw dropw
        end
    ";

    let assembler = Assembler::default();
    let program = assembler.assemble_program(source).expect("Failed to assemble program");

    // Execute the program - the DecoratorId error would occur here
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let trace = miden_processor::execute(&program, stack_inputs, advice_inputs, &mut host, options)
        .expect("Execution should succeed without DecoratorId out of bounds error");

    // The main test is that execution succeeds without the DecoratorId error
    // Stack verification is secondary
    let _stack_outputs = trace.stack_outputs();
}

#[test]
fn test_issue_2456_call_after_push_with_drops_workaround() {
    // Version with the "drop drop" workaround mentioned in the issue
    let source = "
        proc foo
            push.3.4
            add
            swapw dropw
        end

        begin
            push.1.2 drop drop
            call.foo
            dropw dropw dropw dropw
        end
    ";

    let assembler = Assembler::default();
    let program = assembler.assemble_program(source).expect("Failed to assemble program");

    // Execute the program
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let trace = miden_processor::execute(&program, stack_inputs, advice_inputs, &mut host, options)
        .expect("Execution with drops workaround should succeed without DecoratorId error");

    // The main test is that execution succeeds without the DecoratorId error
    let _stack_outputs = trace.stack_outputs();
}
