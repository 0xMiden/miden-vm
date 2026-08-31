// CROSS-MODULE CONSTANTS AND ITEM VISIBILITY
// ================================================================================================

use super::*;

#[test]
fn test_cross_module_constant_resolution() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            pub const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use cycle::module_a
            pub const B_VAL = module_a::A_VAL + 5  # <-- Should work but fails
            pub proc b_proc
                push.B_VAL
            end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());

    let _ = assembler.assemble_library("test", module_a, [module_b])?;

    Ok(())
}

#[test]
fn test_cross_module_constant_resolution_as_local_definition() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            pub const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());

    let _ = assembler.assemble_library("cycle", module_a, [module_b])?;

    Ok(())
}

#[test]
fn importing_private_constant_from_another_module_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private constant import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn importing_private_constant_from_another_module_by_absolute_path_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from ::cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private absolute constant import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn importing_private_type_from_another_module_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            type PrivateType = felt
            pub proc a_proc
                nop
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {PrivateType} from cycle::module_a
            pub proc b_proc(value: PrivateType)
                nop
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private type import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn public_item_import_reexporting_private_signature_is_rejected() {
    let context = TestContext::default();

    let module = context
        .parse_module(source_file!(
            &context,
            r#"
                namespace cycle::module_a

                type PrivateType = felt

                pub use {hidden as exposed} from self

                proc hidden(value: PrivateType)
                    nop
                end
            "#
        ))
        .expect("private procedure signature should be valid before public re-export");

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module, None::<Box<Module>>)
        .expect_err("expected public re-export of private signature to be rejected");

    assert_diagnostic!(&err, "private type in exported procedure signature");
    assert_diagnostic!(&err, "exported procedure signatures may only reference public types");
}

#[test]
fn public_item_import_reexporting_private_type_is_rejected() {
    let context = TestContext::default();

    let module = context
        .parse_module(source_file!(
            &context,
            r#"
                namespace cycle::module_a

                type PrivateType = felt

                pub use {PrivateType as PublicType} from self
            "#
        ))
        .expect("private type should be valid before public re-export");

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module, None::<Box<Module>>)
        .expect_err("expected public re-export of private type to be rejected");

    assert_diagnostic!(&err, "private type in exported type declaration");
    assert_diagnostic!(&err, "exported type declarations may only reference public types");
}

#[test]
fn test_cross_module_constant_reexport_chain_in_procedure_scope() -> TestResult {
    let context = TestContext::new();

    let root = parse_module!(
        &context,
        r#"
            namespace dcrc

            pub mod a
            pub mod b
            pub mod c
        "#
    );

    let a = parse_module!(
        &context,
        r#"
            namespace dcrc::a

            pub const VAL = 99
            pub proc use_val
                push.VAL
                drop
            end
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace dcrc::b

            use dcrc::a
            pub const STEP = a::VAL + 1
            pub proc dummy
                push.STEP
                drop
            end
        "#
    );

    let c = parse_module!(
        &context,
        r#"
            namespace dcrc::c

            use dcrc::b
            pub const FINAL_VAL = b::STEP + 1
            pub proc dummy
                push.FINAL_VAL
                drop
            end
        "#
    );

    let lib = Assembler::new(context.source_manager()).assemble_library("dcrc", root, [a, b, c])?;

    let src = source_file!(
        &context,
        r#"
            use dcrc::c
            const LOCAL = c::FINAL_VAL
            begin
                push.LOCAL
                drop
            end
        "#
    );

    let _program = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib), Linkage::Dynamic)?
        .assemble_program("test", src)?;

    Ok(())
}

#[test]
fn test_issue_2696_imported_constant_with_private_dependency() -> TestResult {
    let context = TestContext::new();

    let root = parse_module!(
        &context,
        r#"
            namespace wallet

            pub mod memory
            pub mod account
        "#
    );

    let memory = parse_module!(
        &context,
        r#"
            namespace wallet::memory

            const ACCOUNT_ID_AND_NONCE_OFFSET = 4
            pub const ACCOUNT_ID_SUFFIX_OFFSET = ACCOUNT_ID_AND_NONCE_OFFSET + 2
        "#
    );

    let account = parse_module!(
        &context,
        r#"
            namespace wallet::account

            use {ACCOUNT_ID_SUFFIX_OFFSET} from wallet::memory

            pub proc use_suffix
                push.ACCOUNT_ID_SUFFIX_OFFSET
                drop
            end
        "#
    );

    Assembler::new(context.source_manager()).assemble_library("wallet", root, [memory, account])?;

    Ok(())
}
