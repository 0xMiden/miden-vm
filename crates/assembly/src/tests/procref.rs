// PROGRAM WITH PROCREF
// ================================================================================================

use super::*;

#[test]
fn procref_call() -> TestResult {
    let mut context = TestContext::default();
    // compile first module
    context.add_module(source_file!(
        &context,
        "
        namespace module::path::one

        pub proc aaa
            push.7.8
        end

        pub proc foo
            push.1.2
        end"
    ))?;

    // compile second module
    context.add_module(source_file!(
        &context,
        "
        namespace module::path::two

        use module::path::one
        pub use {foo} from module::path::one

        pub proc bar
            procref.one::aaa
        end"
    ))?;

    // compile program with procref calls
    context.assemble(source_file!(
        &context,
        "
        use module::path::two

        @locals(4)
        proc baz
            push.3.4
        end

        begin
            procref.two::bar
            procref.two::foo
            procref.baz
        end"
    ))?;
    Ok(())
}

#[test]
fn get_proc_name_of_unknown_module() -> TestResult {
    let context = TestContext::default();
    // Module `two` is unknown, our error should identify that it is undefined
    let module_source1 = source_file!(
        &context,
        "
    namespace module::path::one

    use module::path::two

    pub proc foo
        procref.two::bar
    end"
    );
    let module1 = context.parse_module(module_source1)?;

    let report = Assembler::new(context.source_manager())
        .assemble_library("test", module1, None::<Box<Module>>)
        .expect_err("expected unknown module error");

    assert_diagnostic!(&report, "undefined item 'module::path::two'");
    assert_diagnostic!(&report, "use module::path::two");
    assert_diagnostic!(&report, "you might be missing an import");

    Ok(())
}
