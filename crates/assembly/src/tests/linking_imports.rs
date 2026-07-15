// LINK-TIME IMPORT RESOLUTION
// ================================================================================================

use super::*;

#[test]
fn overlong_total_path_is_rejected_without_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::testing::TestContext;

    // Build a valid path where each component is within the per-component limit (255 bytes),
    // but the total byte length exceeds u16::MAX (the binary serialization length prefix).
    let component = "a".repeat(255);
    let num_components: usize = 300;
    let mut path_str = String::with_capacity(num_components * (component.len() + 2));
    for i in 0..num_components {
        if i > 0 {
            path_str.push_str("::");
        }
        path_str.push_str(&component);
    }

    let context = TestContext::default();
    let lib_src = format!(
        r#"
namespace {path_str}

pub proc add
    add.1
end
"#
    );

    let parsed = catch_unwind(AssertUnwindSafe(|| context.parse_module(lib_src.as_str())));

    assert!(
        parsed.is_ok(),
        "overlong total path caused a panic; expected a structured error"
    );
    let parsed = parsed.unwrap();
    let err = parsed.expect_err("expected overlong path to be rejected");
    assert_diagnostic!(err, "invalid item path: too long");
}

#[test]
fn public_item_import_exports_without_alias_symbol() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace root

        pub use {foo as bar} from dep
        "#
    ))?;
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub proc foo
            push.1
        end
        "#
    ))?;

    let library = Assembler::new(context.source_manager()).assemble_library("pkg", root, [dep])?;
    let exports = library.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert_eq!(exports.len(), 1);
    assert!(exports.contains(&Arc::from(Path::new("::root::bar"))));

    Ok(())
}

#[test]
fn link_import_module_and_item_forms_resolve() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::math

        pub const VALUE = 7
        pub type WordType = felt

        pub proc procedure
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use lib::math
        use lib::math as m
        use {procedure as imported_proc, VALUE, WordType} from lib::math

        pub const LOCAL = VALUE + 1

        pub proc entry(value: WordType)
            exec.imported_proc
            exec.math::procedure
            exec.m::procedure
            push.LOCAL
            drop
        end
        "#
    ))?;

    let package =
        Assembler::new(context.source_manager()).assemble_library("app", consumer, [dep])?;
    let exports = package.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert!(exports.contains(&Arc::from(Path::new("::app::entry"))));

    Ok(())
}

#[test]
fn link_import_single_segment_module_import_resolves() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace foo

        pub proc procedure
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use foo

        pub proc entry
            exec.foo::procedure
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", consumer, [dep])?;

    Ok(())
}

#[test]
fn link_import_item_form_rejects_submodule_target() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub mod child
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep::child

        pub proc entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {child} from dep

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [dep, child])
        .expect_err("item import of a submodule should be rejected");

    assert_diagnostic!(&err, "item import target '::dep::child' resolved to a module");

    Ok(())
}

#[test]
fn link_import_public_item_reexport_chain_resolves_order_independently() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub const VALUE = 1
        "#
    ))?;
    let mid = context.parse_module(source_file!(
        &context,
        r#"
        namespace mid

        pub use {VALUE as MID_VALUE} from dep
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {MID_VALUE as VALUE} from mid

        pub proc entry
            push.VALUE
            drop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", consumer, [mid, dep])?;

    Ok(())
}

#[test]
fn link_import_self_relative_public_item_reexport_resolves() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub proc helper
            nop
        end
        "#
    ))?;
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        pub mod child

        use {ALIAS as imported} from self::child

        pub proc entry
            exec.imported
            exec.self::child::ALIAS
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace app::child

        pub use {helper as ALIAS} from dep
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", root, [child, dep])?;

    Ok(())
}

#[test]
fn link_import_public_item_reexport_cycle_is_rejected() -> TestResult {
    let context = TestContext::new();
    let a = context.parse_module(source_file!(
        &context,
        r#"
        namespace a

        pub use {B as A} from b
        "#
    ))?;
    let b = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {A as B} from a
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {A} from a

        pub proc entry
            push.A
            drop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [a, b])
        .expect_err("public item re-export cycle should be rejected");

    assert_diagnostic!(&err, "import re-export cycle");

    Ok(())
}

#[test]
fn link_import_public_item_reexport_cycle_with_self_relative_target_is_rejected() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace root

        pub mod child
        pub use {B as A} from self::child
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace root::child

        pub use {A as B} from root
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {A} from root

        pub proc entry
            push.A
            drop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [root, child])
        .expect_err("public item re-export cycle should be rejected");

    assert_diagnostic!(&err, "import re-export cycle");

    Ok(())
}
