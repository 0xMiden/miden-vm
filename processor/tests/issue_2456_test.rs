/// Test case for issue #2456: statically linked library calls should preserve valid MAST
/// structure when copying nodes between forests.
use miden_assembly::Assembler;
use miden_processor::{DefaultHost, ExecutionOptions, StackInputs, advice::AdviceInputs};

#[test]
fn test_issue_2456_statically_linked_library_call() {
    use std::sync::Arc;

    use miden_assembly::DefaultSourceManager;

    let test_module_source = "
        namespace test::module_1

        pub proc foo
            push.3.4
            add
            swapw dropw
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut assembler = Assembler::new(source_manager);

    let library = assembler
        .clone()
        .assemble_library("library", test_module_source, None::<Box<miden_assembly::ast::Module>>)
        .unwrap();

    // This program calls a procedure from a statically linked library.
    let source = "
        namespace $exec

        use test::module_1

        begin
            push.1.2
            call.module_1::foo
            dropw dropw dropw dropw
        end
    ";

    assembler.link_package(library.into(), miden_assembly::Linkage::Static).unwrap();
    let program = assembler.assemble_program("program", source).unwrap().unwrap_program();

    // Execute the program. This should succeed after static linking.
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let options = ExecutionOptions::default();

    let result =
        miden_processor::execute_sync(&program, stack_inputs, advice_inputs, &mut host, options);
    assert!(result.is_ok(), "Execution should succeed but got error: {:?}", result.err());
}
