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

fn assert_symbol_conflict(error: &miden_utils_diagnostics::Report, symbol: &str) {
    let syntax_error = error
        .downcast_ref::<crate::sema::SyntaxError>()
        .expect("expected SyntaxError report");

    let (span, prev_span) = syntax_error
        .errors
        .iter()
        .find_map(|err| match err {
            crate::sema::SemanticAnalysisError::SymbolConflict { span, prev_span } => {
                Some((span, prev_span))
            },
            _ => None,
        })
        .expect("expected at least one SymbolConflict error");

    assert_ne!(span, prev_span, "conflicting definitions should point at distinct spans");
    assert_eq!(
        span.source_id(),
        prev_span.source_id(),
        "conflict spans should refer to the same source file"
    );

    let span_text = syntax_error
        .source_file
        .source_slice(*span)
        .expect("conflict span should be valid");
    let prev_span_text = syntax_error
        .source_file
        .source_slice(*prev_span)
        .expect("previous conflict span should be valid");

    assert!(
        span_text.contains(symbol),
        "conflict span should include symbol '{symbol}', got: {span_text:?}"
    );
    assert!(
        prev_span_text.contains(symbol),
        "previous conflict span should include symbol '{symbol}', got: {prev_span_text:?}"
    );
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
fn define_alias_detects_cross_kind_duplicate_with_type() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            r#"
type thing = felt
use ::dep::thing
"#,
        )
        .expect_err("expected conflicting type/alias names to be rejected during analysis");
    assert_symbol_conflict(&error, "thing");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("symbol conflict"));
    assert!(rendered.contains("thing"));
}

#[test]
fn define_procedure_detects_cross_kind_duplicate_with_type() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            r#"
type thing = felt
proc thing
    nop
end
"#,
        )
        .expect_err("expected conflicting type/procedure names to be rejected during analysis");
    assert_symbol_conflict(&error, "thing");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("symbol conflict"));
    assert!(rendered.contains("thing"));
}

#[test]
fn define_constant_detects_cross_kind_duplicate_with_alias() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            r#"
use ::dep::"THING"
const THING = 1
"#,
        )
        .expect_err("expected conflicting alias/constant names to be rejected during analysis");
    assert_symbol_conflict(&error, "THING");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("symbol conflict"));
    assert!(rendered.contains("THING"));
}

#[test]
fn define_type_detects_cross_kind_duplicate_with_procedure() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            r#"
proc thing
    nop
end
type thing = felt
"#,
        )
        .expect_err("expected conflicting procedure/type names to be rejected during analysis");
    assert_symbol_conflict(&error, "thing");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("symbol conflict"));
    assert!(rendered.contains("thing"));
}
