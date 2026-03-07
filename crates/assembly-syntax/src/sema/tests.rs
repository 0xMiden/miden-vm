use crate::{
    MAX_REPEAT_COUNT, diagnostics::reporting::PrintDiagnostic, testing::SyntaxTestContext,
};

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
