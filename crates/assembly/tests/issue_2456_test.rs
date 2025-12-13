/// Test case for issue #2456: DecoratorId out of bounds
/// This test attempts to reproduce the decorator issue by compiling
/// and EXECUTING a simple program with a call instruction.
use miden_assembly::Assembler;
use miden_processor::{AdviceInputs, DefaultHost, ExecutionOptions, StackInputs};

#[test]
fn test_issue_2456_call_with_push_before() {
    use miden_assembly::diagnostics::NamedSource;
    use std::sync::Arc;
    use miden_assembly::DefaultSourceManager;
    use miden_core_lib::CoreLibrary;
    
    let test_module_source = "
        pub proc foo
            push.3.4
            add
            swapw dropw
        end
    ";

    let source = NamedSource::new("test::module_1", test_module_source);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut assembler = Assembler::new(source_manager)            
        .with_dynamic_library(CoreLibrary::default())
        .expect("failed to load std-lib");

    let library = assembler.clone().assemble_library([source]).unwrap();

    // This program should trigger the "DecoratorId out of bounds" issue
    let source = "
        use test::module_1
        use miden::core::sys

        begin
            push.1.2
            call.module_1::foo
            exec.sys::truncate_stack
        end
    ";

    assembler.link_static_library(library).unwrap();
    let program = assembler.assemble_program(source).unwrap();

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
fn test_issue_2456_call_with_push_and_drops_before() {
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
