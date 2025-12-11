/// Test case for issue #2456: DecoratorId out of bounds
/// This test attempts to reproduce the decorator issue by compiling
/// and EXECUTING a simple program with a call instruction.
use miden_assembly::Assembler;
use miden_processor::{AdviceInputs, DefaultHost, ExecutionOptions, StackInputs};

#[test]
fn test_call_with_push_before() {
    let assembler = Assembler::default();

    // This program should trigger the "DecoratorId out of bounds" issue
    let source = "
        proc foo
            push.1
            push.2
            add
            drop
        end

        begin
            push.1.2
            call.foo
            dropw dropw dropw dropw
        end
    ";

    let program = assembler.assemble_program(source).expect("Compilation should succeed");

    // Execute the program - this is where the DecoratorId error might occur
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let result =
        miden_processor::execute(&program, stack_inputs, advice_inputs, &mut host, options);
    assert!(result.is_ok(), "Execution should succeed but got error: {:?}", result.err());
}

#[test]
fn test_call_with_push_and_drops_before() {
    let assembler = Assembler::default();

    // This version with drops should work (as mentioned in the issue)
    let source = "
        proc foo
            push.1
            push.2
            add
            drop
        end

        begin
            push.1.2 drop drop
            call.foo
            dropw dropw dropw dropw
        end
    ";

    let program = assembler.assemble_program(source).expect("Compilation should succeed");

    // Execute the program
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let result =
        miden_processor::execute(&program, stack_inputs, advice_inputs, &mut host, options);
    assert!(result.is_ok(), "Execution should succeed: {:?}", result.err());
}
