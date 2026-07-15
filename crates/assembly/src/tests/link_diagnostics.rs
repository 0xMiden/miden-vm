// LINK DIAGNOSTICS
// ================================================================================================

use super::*;

#[test]
fn link_diagnostic_for_missing_declared_submodule() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod missing

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, None::<Box<Module>>)
        .expect_err("declared missing child module should be rejected");

    assert_diagnostic!(&err, "undefined module '::diag::root::missing'");

    Ok(())
}

#[test]
fn link_diagnostic_for_undeclared_child_module() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("undeclared child module should be rejected");

    assert_diagnostic!(&err, "module '::diag::root::child' is not declared");
    assert_diagnostic!(&err, "`mod child` or `pub mod child`");

    Ok(())
}

#[test]
fn link_diagnostic_for_private_submodule_import() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::root::child

        pub proc entry
            exec.child::child_entry
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("private submodule import should be rejected");

    assert_diagnostic!(&err, "private submodule '::diag::root::child'");
    assert_diagnostic!(&err, "only public submodules can be imported from another module");

    Ok(())
}

#[test]
fn private_submodule_is_visible_to_descendants_of_its_parent() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod internal
        pub mod api

        pub proc entry
            nop
        end
        "#
    ))?;
    let internal = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::internal

        pub const VALUE = 1
        pub proc internal_entry
            nop
        end
        "#
    ))?;
    let api = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::api

        use {VALUE} from diag::root::internal
        use diag::root::internal as internal_api

        pub proc entry
            push.VALUE
            exec.internal_api::internal_entry
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [internal, api])?;

    Ok(())
}

#[test]
fn private_nested_submodule_is_not_visible_to_sibling_of_parent() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod parent
        pub mod sibling

        pub proc entry
            nop
        end
        "#
    ))?;
    let parent = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::parent

        mod hidden
        "#
    ))?;
    let hidden = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::parent::hidden

        pub const VALUE = 1
        "#
    ))?;
    let sibling = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::sibling

        use {VALUE} from diag::root::parent::hidden

        pub proc entry
            push.VALUE
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [parent, hidden, sibling])
        .expect_err("private nested submodule should not be visible to sibling of its parent");

    assert_diagnostic!(&err, "private submodule '::diag::root::parent::hidden'");
    assert_diagnostic!(&err, "only public submodules can be imported from another module");

    Ok(())
}

#[test]
fn link_diagnostic_for_module_reexport() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        pub use {child} from diag::root

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("module re-export should be rejected");

    assert_diagnostic!(&err, "item import target '::diag::root::child' resolved to a module");
    assert_diagnostic!(&err, "item-form imports may only import procedures, constants, or types");

    Ok(())
}

#[test]
fn link_diagnostic_for_import_target_through_import_alias() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub const VALUE = 1
        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::root::child
        use {VALUE} from child

        pub proc entry
            push.VALUE
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("import through another import should be rejected");

    assert_diagnostic!(
        &err,
        "import target 'child::VALUE' cannot be resolved through import 'child'"
    );
    assert_diagnostic!(&err, "imports are resolved independently");

    Ok(())
}

#[test]
fn pub_use_through_import_alias_is_rejected_even_when_global_path_exists() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let imported = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep::child

        pub proc p
            push.1
        end
        "#
    ))?;
    let global = context.parse_module(source_file!(
        &context,
        r#"
        namespace child

        pub proc p
            push.2
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::dep::child
        pub use {p as alias} from child

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [imported, global])
        .expect_err("pub use through another import should be rejected before global lookup");

    assert_diagnostic!(&err, "import target 'child::p' cannot be resolved through import 'child'");
    assert_diagnostic!(&err, "imports are resolved independently");

    Ok(())
}

#[test]
fn link_diagnostic_for_self_referential_module_import() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        use diag::root::child

        pub proc child_entry
            exec.child::child_entry
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("module import of itself should be rejected");

    assert_diagnostic!(&err, "self-referential import of module 'diag::root::child'");
    assert_diagnostic!(&err, "a module cannot import itself");

    Ok(())
}

#[test]
fn link_diagnostic_for_importing_same_scope_submodule_with_alias() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child
        use diag::root::child as child_api

        pub proc entry
            exec.child_api::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("same-scope submodule imports should be rejected even when aliased");

    assert_diagnostic!(&err, "cannot import submodule '::diag::root::child'");
    assert_diagnostic!(&err, "submodule-qualified path");

    Ok(())
}

#[test]
fn link_diagnostic_for_importing_same_scope_submodule_with_self_alias() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child
        use self::child as child_api

        pub proc entry
            exec.child_api::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("self-relative same-scope submodule imports should be rejected");

    assert_diagnostic!(&err, "cannot import submodule '::diag::root::child'");
    assert_diagnostic!(&err, "submodule-qualified path");

    Ok(())
}

#[test]
fn code_paths_can_reference_current_and_descendant_items_absolutely() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        proc local_helper
            nop
        end

        pub proc entry
            exec.::diag::root::local_helper
            exec.::diag::root::child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn code_paths_can_reference_local_submodules_without_imports() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        pub proc entry
            exec.child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn link_diagnostic_for_relative_global_like_code_path() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            exec.diag::root::child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("relative paths should not fall back to the global namespace");

    assert_diagnostic!(&err, "invalid relative item path 'diag::root::child::child_entry'");
    assert_diagnostic!(&err, "absolute, local, or qualified by an import or submodule");

    Ok(())
}

#[test]
fn code_paths_can_reference_imported_module_subpaths() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::dep as dep

        pub proc entry
            exec.dep::child::child_entry
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", consumer, [dep, child])?;

    Ok(())
}

#[test]
fn self_relative_import_walks_public_submodules() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        use {child_entry} from self::child

        pub proc entry
            exec.child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            push.1
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn self_relative_import_rejects_private_descendant() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        use self::child::hidden

        pub proc entry
            exec.hidden::hidden_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        mod hidden
        "#
    ))?;
    let hidden = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child::hidden

        pub proc hidden_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child, hidden])
        .expect_err("private descendant import should be rejected");

    assert_diagnostic!(&err, "private submodule '::diag::root::child::hidden'");

    Ok(())
}

#[test]
fn link_diagnostic_for_subpath_through_non_module_item() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep

        pub const VALUE = 1
        pub proc entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use {nested as NESTED} from diag::dep::VALUE

        pub proc entry
            exec.NESTED
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [dep])
        .expect_err("subpath through item should be rejected");

    assert_diagnostic!(&err, "invalid symbol path");
    assert_diagnostic!(&err, "all ancestors of a path must be modules");

    Ok(())
}

#[test]
fn imported_error_message_alias_is_resolved_without_panicking() {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };

    use miden_assembly_syntax::Parse;

    use crate::{Assembler, DefaultSourceManager};

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());

    // Library module `b` exports a string constant and an alias to it.
    let module_b_src = r#"
namespace b

pub const ERR1 = "oops"
pub const ERR2 = ERR1
"#;
    let module_b = <&str as Parse>::parse(module_b_src, false, source_manager.clone())
        .expect("module b parsing must succeed");

    // Executable module imports `ERR2` and uses it as an assertion error message.
    let module_a_src = r#"
use {ERR2} from b

begin
    assert.err=ERR2
end
"#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        let mut assembler = Assembler::new(source_manager);
        assembler
            .compile_and_statically_link(module_b)
            .expect("linking module b must succeed");
        assembler.assemble_program("test", module_a_src)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    assembled
        .unwrap()
        .expect("expected imported error message alias to assemble successfully");
}
