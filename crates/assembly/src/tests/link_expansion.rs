// RECURSIVE LINK EXPANSION
// ================================================================================================

use super::*;

#[test]
fn test_linking_imported_symbols_with_duplicate_prefix_components() -> TestResult {
    let context = TestContext::default();

    // The name of this library is `lib::lib` on purpose
    let lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::lib

        pub proc lib_proc
            swap
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let lib = assembler.assemble_library("lib", lib, None::<Box<Module>>)?;

    // This import's default alias is `lib`, which is also the first component of its global
    // target. That must still resolve globally rather than being mistaken for an import-through-
    // import attempt.
    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.with_package(Arc::from(lib), Linkage::Static)?.assemble_program(
        "program",
        r#"
        use lib::lib

        begin
            exec.lib::lib_proc
        end
        "#,
    )?;

    Ok(())
}

#[test]
#[ignore = "leave disabled until either symbol resolution is rewritten or path semantics are refined"]
fn test_linking_recursive_expansion() -> TestResult {
    let context = TestContext::default();

    let a_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace a

        pub use {a} from b
        pub proc x
            push.1
        end
        "#
    ))?;

    let b_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {a} from a
        pub proc foo
            exec.a::x
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.assemble_library("lib", a_lib, [b_lib])?;

    Ok(())
}

#[test]
#[ignore = "leave disabled until either symbol resolution is rewritten or path semantics are refined"]
fn test_linking_recursive_expansion_via_renamed_aliases() -> TestResult {
    let context = TestContext::default();

    let a_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace a::a

        pub use {a2} from b
        pub proc x
            push.1
        end
        "#
    ))?;

    let b_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {a as a2} from a
        pub proc foo
            exec.a2::x
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.assemble_library("lib", a_lib, [b_lib])?;

    Ok(())
}
