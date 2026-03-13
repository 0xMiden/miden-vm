use miden_debug_types::Span;

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

#[test]
fn alias_then_constant_name_conflict_can_reach_resolver_duplicate_error() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module(
            r#"
use ::dep::"EVENT_HASH"
const EVENT_HASH = 1
"#,
        )
        .expect("expected module to parse and pass semantic analysis");

    let err = module
        .resolve(Span::unknown("EVENT_HASH"), context.source_manager())
        .expect_err("expected duplicate symbol to be caught by resolver lookup");
    assert!(
        matches!(
            &err,
            crate::ast::SymbolResolutionError::DuplicateSymbol { symbol, .. }
                if symbol.as_ref() == "EVENT_HASH"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn alias_then_type_name_conflict_can_reach_resolver_duplicate_error() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module(
            r#"
use ::dep::"Thing"
type Thing = felt
"#,
        )
        .expect("expected module to parse and pass semantic analysis");

    let err = module
        .resolve(Span::unknown("Thing"), context.source_manager())
        .expect_err("expected duplicate symbol to be caught by resolver lookup");
    assert!(
        matches!(
            &err,
            crate::ast::SymbolResolutionError::DuplicateSymbol { symbol, .. }
                if symbol.as_ref() == "Thing"
        ),
        "unexpected error: {err}"
    );
}
