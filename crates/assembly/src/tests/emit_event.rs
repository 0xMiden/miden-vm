// EMIT EVENT SYNTAX VALIDATION
// ================================================================================================

use super::*;

#[test]
fn emit_u32_immediate_is_rejected() {
    let context = TestContext::new();
    let program_source = r#"
        begin
            emit.32
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.<u32> should be rejected; only event("...") is allowed"#);
}

#[test]
fn emit_const_must_be_event_hash() {
    let context = TestContext::new();
    // CONST defined as plain number should not be accepted by emit.CONST
    let program_source = r#"
        const BAD = 100
        begin
            emit.BAD
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.CONST should require const defined via event("...")"#);

    // CONST defined via word("...") should also be rejected by emit.CONST
    let program_source = r#"
        const BADW = word("foo")
        begin
            emit.BADW
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.CONST should require const defined via event("...")"#);
}

#[test]
#[should_panic(expected = "expected 3 lines, but got 1")]
fn assert_diagnostic_lines_rejects_missing_actual_lines() {
    assert_diagnostic_lines!(report!("the error string"), "the error string", "other", "lines");
}

#[test]
#[should_panic(expected = "expected 1 lines, but got 2")]
fn assert_diagnostic_lines_rejects_extra_actual_lines() {
    assert_diagnostic_lines!(report!("the first line\nthe second line"), "the first line");
}
