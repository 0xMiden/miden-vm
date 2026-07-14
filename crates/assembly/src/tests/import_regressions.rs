// IMPORT EDGE CASES AND REGRESSIONS
// ================================================================================================

use super::*;

#[test]
fn asm_import_source_digest_reexport_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        context.parse_module(source_file!(
            &context,
            "namespace m::n\n\npub use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000\n"
        ))
    }));

    assert!(parsed.is_ok(), "parser panicked, expected a structured error");
    let err = parsed
        .unwrap()
        .expect_err("expected source-level digest re-export to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn asm_import_source_digest_alias_chain_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        context.parse_module(source_file!(
            &context,
            r#"
                    namespace m::n

                    pub use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000
                    pub use {foo as bar} from m::n

                    pub proc calls_bar
                        call.bar
                    end
                "#
        ))
    }));

    assert!(parsed.is_ok(), "parser panicked, expected a structured error");
    let err = parsed
        .unwrap()
        .expect_err("expected source-level digest alias chain to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn asm_import_direct_digest_invoke_assembles_without_source_import() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let program = r#"
        begin
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::default().assemble_program("program", program)
    }));

    assert!(
        assembled.is_ok(),
        "assembly panicked, expected direct opaque digest invoke to be allowed"
    );
    assembled
        .unwrap()
        .expect("expected direct digest invocation to assemble successfully");
}

#[test]
fn asm_import_direct_digest_invoke_parses_with_warnings_as_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let program = r#"
        begin
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, program, source_manager)
        .expect("expected direct digest invocation to parse without import warnings");
}

#[test]
fn asm_import_direct_digest_forward_decl_assembles_without_source_import() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let program = r#"
        proc helper
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end

        begin
            call.helper
        end
    "#;

    Assembler::new(source_manager)
        .assemble_program("program", program)
        .expect("expected direct digest invocation in helper proc to assemble");
}

#[test]
fn forward_declared_import_used_by_type_ref_is_not_reported_unused_when_warnings_are_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        type Local = foo::Type
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by type ref to count as used");
}

#[test]
fn forward_declared_import_used_by_proc_signature_is_not_reported_unused_when_warnings_are_errors()
{
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        pub proc check(value: foo::Type) -> foo::Type
            nop
        end
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by signature type to count as used");
}

#[test]
fn kernel_import_used_by_proc_signature_is_not_reported_unused_when_warnings_are_errors() {
    let context = TestContext::new();
    context
        .parse_kernel(source_file!(
            &context,
            r#"
            namespace $kernel

            use external::module as foo

            pub proc check(value: foo::Type) -> foo::Type
                nop
            end
            "#
        ))
        .expect("expected kernel signature type import to count as used");
}

#[test]
fn forward_declared_import_used_by_constant_ref_is_not_reported_unused_when_warnings_are_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        const LOCAL = foo::BAR
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by constant ref to count as used");
}

#[test]
fn asm_import_source_digest_import_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let program = r#"
        use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000

        begin
            exec.foo
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::default().assemble_program("program", program)
    }));

    assert!(assembled.is_ok(), "assembly panicked, expected a structured error");
    let err = assembled
        .unwrap()
        .expect_err("expected source-level digest import to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn invoking_local_type_alias_returns_error_instead_of_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let masm = "type foo = u32\nbegin\n    exec.foo\nend\n";

    let result =
        catch_unwind(AssertUnwindSafe(|| Assembler::default().assemble_program("program", masm)));

    let result = result.expect("assembly panicked, expected a structured error");
    let err = result.expect_err("assembly unexpectedly succeeded");
    assert_diagnostic!(&err, "invalid symbol reference: wrong type");
    assert_diagnostic!(&err, "expected this symbol to reference a procedure item");
}

#[test]
fn invoking_local_type_alias_is_rejected_during_semantic_analysis() {
    let context = TestContext::new();
    let masm = source_file!(&context, "type foo = u32\nbegin\n    exec.foo\nend\n");

    let err = context
        .parse_program(masm)
        .expect_err("semantic analysis unexpectedly accepted invoking a local type alias");
    assert_diagnostic!(&err, "invalid symbol reference: wrong type");
    assert_diagnostic!(&err, "expected this symbol to reference a procedure item");
}

#[test]
fn invoking_imported_type_alias_returns_error_instead_of_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let lib_src = source_file!(
        &context,
        "\
namespace test::types

pub type foo = u32

pub proc fun(in: foo)
    push.1
end"
    );
    let lib = context.parse_module(lib_src).expect("library module parsing must succeed");
    let library = Assembler::new(context.source_manager())
        .assemble_library("test", lib, None::<Box<Module>>)
        .expect("library assembly must succeed");

    let mut assembler = Assembler::new(context.source_manager());
    assembler
        .link_package(Arc::from(library), Linkage::Dynamic)
        .expect("library linking must succeed");

    let program = "use test::types\nbegin\n    exec.types::foo\nend\n";
    let result = catch_unwind(AssertUnwindSafe(|| assembler.assemble_program("program", program)));

    let result = result.expect("assembly panicked, expected a structured error");
    let err = result.expect_err("assembly unexpectedly succeeded");
    assert_diagnostic!(&err, "invalid procedure reference: path refers to a non-procedure item");
    assert_diagnostic!(&err, "test::types::foo");
}
