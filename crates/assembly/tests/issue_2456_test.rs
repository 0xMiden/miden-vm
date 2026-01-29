/// Test case for issue #2456: DecoratorId out of bounds when calling procedures
/// from statically linked libraries.
///
/// The issue occurs because decorators aren't remapped when copying nodes from
/// statically linked libraries, causing decorator IDs from the source forest to
/// be used in the target forest where they don't exist.
use miden_assembly::Assembler;
use miden_processor::{AdviceInputs, DefaultHost, ExecutionOptions, StackInputs};

#[test]
fn test_issue_2456_statically_linked_library_call() {
    use std::sync::Arc;

    use miden_assembly::{DefaultSourceManager, diagnostics::NamedSource};

    let test_module_source = "
        pub proc foo
            push.3.4
            add
            swapw dropw
        end
    ";

    let source = NamedSource::new("test::module_1", test_module_source);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut assembler = Assembler::new(source_manager);

    let library = assembler.clone().assemble_library([source]).unwrap();

    // This program calls a procedure from a statically linked library, which
    // triggers the DecoratorId remapping issue.
    let source = "
        use test::module_1

        begin
            push.1.2
            call.module_1::foo
            dropw dropw dropw dropw
        end
    ";

    assembler.link_static_library(library).unwrap();
    let program = assembler.assemble_program(source).unwrap();

    // Execute the program - this should now succeed without DecoratorId out of bounds error
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let result =
        miden_processor::execute_sync(&program, stack_inputs, advice_inputs, &mut host, options);
    assert!(result.is_ok(), "Execution should succeed but got error: {:?}", result.err());
}
