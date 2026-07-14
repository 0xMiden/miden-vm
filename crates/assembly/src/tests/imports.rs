// IMPORTS
// ================================================================================================

use super::*;

#[test]
fn program_with_one_import_and_hex_call() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            call.0x20234ee941e53a15886e733cc8e041198c6e90d2a16ea18ce1030e8c3596dd38
        end"#
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_two_imported_procs_with_same_mast_root() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe_dup
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end

        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            exec.u256::iszero_unsafe_dup
        end"#
        )
    );
    context.assemble(source)?;
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy1", ast, [ref_ast])
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_custom_alias_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy1", ast, [ref_ast])
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE} as myu256
        begin
            push.4 push.3
            exec.myu256::checked_eqz
            exec.myu256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_another_library() -> TestResult {
    // when re-exported proc is part of a different library
    const REF_MODULE: &str = "dummy2::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        pub use {checked_eqz} from dummy2::math::u64 # re-export
        pub use {unchecked_eqz as notchecked_eqz} from dummy2::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    // We reference code in this module
    let ref_ast = context.parse_module(source_file!(
        &context,
        format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")
    ))?;
    // But only exports from this module are exposed by the library
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))?;

    let dummy_library = {
        let mut assembler = Assembler::new(source_manager);
        assembler.compile_and_statically_link(ref_ast)?;
        Arc::<Package>::from(assembler.assemble_library("dummy1", ast, None::<Box<Module>>)?)
    };

    // Now we want to use the the library we've compiled
    context.add_library(dummy_library.clone())?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);

    // We also want to assert that exports from the referenced module do not leak
    let mut context = TestContext::default();
    context.add_library(dummy_library)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {REF_MODULE}
        begin
            push.4 push.3
            exec.u64::checked_eqz
            exec.u64::notchecked_eqz
        end"#
        )
    );
    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'dummy2::math::u64'",
        regex!(r#",-\[test[\d]+:2:13\]"#),
        "1 |",
        "2 |         use dummy2::math::u64",
        "  :             ^^^^^^^^^^^^^^^^^",
        "3 |         begin",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
    Ok(())
}

#[test]
fn module_alias() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let library = Assembler::new(source_manager)
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        "
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // --- invalid module alias -----------------------------------------------
    let source = source_file!(
        &context,
        r#"
        use dummy::math::u64 as "bad name"

        begin
            push.1.0
            push.2.0
            exec."bad name"::checked_add
        end"#
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid quoted module alias to be rejected");
    assert_diagnostic!(&err, "expected an alias name after `as`");
    assert_diagnostic!(&err, "bad name");

    Ok(())
}

#[test]
//#[ignore = "disabled until unused import accuracy is improved"]
fn module_alias_unused_import() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let library = Assembler::new(source_manager)
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    // --- duplicate module import --------------------------------------------
    let source = source_file!(
        &context,
        "
        use dummy::math::u64
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected unused duplicate import to be rejected");
    assert_diagnostic!(&err, "unused import");
    assert_diagnostic!(&err, "this import is never used and can be safely removed");
    assert_diagnostic!(&err, "use dummy::math::u64");
    assert_diagnostic!(&err, "use dummy::math::u64 as bigint");

    // --- duplicate module imports with different aliases --------------------
    // TODO: Do we actually want this to be a warning/error? If the imports
    // have different aliases, there might be some use for that when refactoring
    // code or something. Anyway, I'm disabling the test that expects this to
    // fail for the time being
    /*
    let source = source_file!(
    &context,
        "
        use dummy::math::u64 as bigint
        use dummy::math::u64 as bigint2

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
            exec.bigint2::checked_add
        end"
    );
    */
    Ok(())
}

#[test]
fn program_with_import_errors() {
    let context = TestContext::default();
    // --- non-existent import ------------------------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u512
        begin \
            push.4 push.3 \
            exec.u512::iszero_unsafe \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u512'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u512",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u512::iszero_unsafe end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );

    // --- non-existent procedure in import -----------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u256
        begin \
            push.4 push.3 \
            exec.u256::foo \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u256'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u256",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u256::foo end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
}
