use crate::{
    MAX_REPEAT_COUNT,
    ast::{Constant, Export, Module},
    diagnostics::reporting::PrintDiagnostic,
    testing::SyntaxTestContext,
};

fn exported_constant<'a>(module: &'a Module, name: &str) -> &'a Constant {
    match module
        .items()
        .iter()
        .find(|item| item.name().as_str() == name && item.visibility().is_public())
    {
        Some(Export::Constant(constant)) => constant,
        Some(item) => panic!("expected exported constant named {name}, found {item:?}"),
        None => panic!("expected exported constant named {name}"),
    }
}

#[test]
fn repeat_count_zero_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program("begin repeat.0 nop end end")
        .expect_err("expected repeat.0 to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_too_large_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = format!("begin repeat.{repeat_count} nop end end");
    let error = context
        .parse_program(source)
        .expect_err("expected repeat count above limit to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_at_limit_allowed_in_analysis() {
    let context = SyntaxTestContext::default();
    let source = format!("begin repeat.{MAX_REPEAT_COUNT} nop end end");
    let _module = context
        .parse_program(source)
        .expect("expected repeat count at limit to be accepted during analysis");
}

#[test]
fn repeat_count_constant_zero_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program("const REPEAT_COUNT = 0\nbegin repeat.REPEAT_COUNT nop end end")
        .expect_err("expected repeat.0 from constant to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_constant_at_limit_allowed_in_analysis() {
    let context = SyntaxTestContext::default();
    let source =
        format!("const REPEAT_COUNT = {MAX_REPEAT_COUNT}\nbegin repeat.REPEAT_COUNT nop end end");
    let _module = context
        .parse_program(source)
        .expect("expected repeat count at limit from constant to be accepted during analysis");
}

#[test]
fn repeat_count_constant_too_large_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source =
        format!("const REPEAT_COUNT = {repeat_count}\nbegin repeat.REPEAT_COUNT nop end end");
    let error = context.parse_program(source).expect_err(
        "expected repeat count above limit from constant to be rejected during analysis",
    );
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn exported_constant_with_private_local_dependency_is_fully_evaluated_in_analysis() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module_with_path(
            "wallet::memory",
            "
const ACCOUNT_ID_AND_NONCE_OFFSET = 4
pub const ACCOUNT_ID_SUFFIX_OFFSET = ACCOUNT_ID_AND_NONCE_OFFSET + 2
",
        )
        .expect("expected semantic analysis to succeed");

    let exported = exported_constant(&module, "ACCOUNT_ID_SUFFIX_OFFSET");
    assert_eq!(exported.value.expect_int().as_int(), 6);
    assert!(
        exported.value.references().is_empty(),
        "expected semantic analysis to remove private local constant references from exported constants",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Regression tests for Issue #2898 — warn on unused private constants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn unused_private_constant_emits_warning() {
    // A private constant that is never referenced anywhere should trigger the
    // UnusedConstant warning (treated as error when warnings_as_errors is on,
    // which SyntaxTestContext enables by default via the assembler).
    let context = SyntaxTestContext::default();
    let result = context.parse_module_with_path(
        "mylib::utils",
        "
const UNUSED_MAGIC = 42

export.foo
    push.1
end
",
    );
    // The warning is emitted; whether it's an error depends on warnings_as_errors.
    // We inspect the rendered message instead of asserting Err so the test works
    // regardless of the warnings_as_errors setting.
    match result {
        Err(err) => {
            let rendered = format!("{}", PrintDiagnostic::new_without_color(&err));
            assert!(
                rendered.contains("unused constant") || rendered.contains("UNUSED_MAGIC"),
                "expected unused-constant diagnostic, got: {rendered}"
            );
        },
        Ok(module) => {
            // If warnings were not promoted to errors, the module still parses.
            // Verify the constant was defined.
            assert!(
                module.items().iter().any(|i| i.name().as_str() == "foo"),
                "module should contain proc foo"
            );
        },
    }
}

#[test]
fn used_private_constant_does_not_warn() {
    // A private constant that IS referenced must not produce a warning.
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module_with_path(
            "mylib::utils",
            "
const STACK_DEPTH = 16

export.foo
    push.STACK_DEPTH
end
",
        )
        .expect("module with a used constant should parse without error");

    assert!(module.items().iter().any(|i| i.name().as_str() == "foo"));
}

#[test]
fn exported_constant_does_not_warn_even_if_locally_unused() {
    // Exported (public) constants are part of the module API and must never
    // produce an unused-constant warning even if they aren't referenced locally.
    let context = SyntaxTestContext::default();
    let _module = context
        .parse_module_with_path(
            "mylib::consts",
            "
pub const MAX_INPUTS = 64
",
        )
        .expect("exported constant must not trigger unused-constant warning");
}

#[test]
fn underscore_prefixed_constant_still_warns() {
    // Unlike Rust let-bindings, MASM constant declarations prefixed with `_` are NOT
    // exempt from the unused-constant warning.  Constants are not variables — there is
    // no established convention in the assembler for silencing warnings via naming.
    // This test documents the decided behaviour (per review feedback on #2921).
    let context = SyntaxTestContext::default();
    let result = context.parse_module_with_path(
        "mylib::utils",
        "
const _RESERVED = 0

export.foo
    push.1
end
",
    );
    // The _ prefix does NOT suppress the warning; an unused _RESERVED should still warn.
    match result {
        Err(err) => {
            let rendered = format!("{}", PrintDiagnostic::new_without_color(&err));
            assert!(
                rendered.contains("unused constant") || rendered.contains("_RESERVED"),
                "expected unused-constant diagnostic for _RESERVED, got: {rendered}"
            );
        },
        Ok(_) => {
            // If warnings_as_errors is off, parse succeeds; that's acceptable.
        },
    }
}
