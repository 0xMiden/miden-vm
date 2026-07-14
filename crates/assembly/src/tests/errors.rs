// ERRORS
// ================================================================================================

use super::*;

#[test]
fn invalid_empty_program() {
    let context = TestContext::default();
    for _ in 0..2 {
        let err = context
            .assemble(source_file!(&context, "namespace foo"))
            .expect_err("expected empty program to be rejected");
        assert_diagnostic!(&err, "unable to assemble program: source is not an executable module");
    }
}

#[test]
fn invalid_program_unrecognized_token() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "none"))
        .expect_err("expected unexpected top-level token to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "unexpected top-level token");
    assert_diagnostic!(&err, "none");
}

#[test]
fn invalid_program_unmatched_begin() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "begin add"))
        .expect_err("expected unmatched begin to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `begin` block");
    assert_diagnostic!(&err, "begin add");
}

#[test]
fn invalid_program_invalid_top_level_token() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "begin add end mul"))
        .expect_err("expected invalid top-level token to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "unexpected top-level token");
    assert_diagnostic!(&err, "begin add end mul");
}

#[test]
fn removed_debug_instructions_are_rejected_by_assembler() {
    let context = TestContext::default();

    for spelling in ["debug.stack.4", "debug.mem", "debug.local.0.2", "debug.adv_stack.4"] {
        let source = source_file!(&context, format!("begin {spelling} end"));
        let error = context
            .assemble(source)
            .expect_err("removed debug.* instruction should be rejected");
        assert_diagnostic!(&error, "invalid instruction");
    }
}

#[test]
fn invalid_proc_missing_end_unexpected_begin() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected procedure missing end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close procedure before top-level item");
    assert_diagnostic!(&err, "proc foo add mul begin push.1 end");
}

#[test]
fn invalid_proc_missing_end_unexpected_proc() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul proc bar push.3 end begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected procedure missing end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close procedure before top-level item");
    assert_diagnostic!(&err, "proc foo add mul proc bar push.3 end begin push.1 end");
}

#[test]
fn invalid_proc_undefined_local() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul end begin push.1 exec.bar end");
    let err = context
        .assemble(source)
        .expect_err("expected undefined local proc to be rejected");
    assert_diagnostic!(&err, "undefined symbol reference");
    assert_diagnostic!(&err, "this symbol path could not be resolved");
    assert_diagnostic!(&err, "maybe you are missing an import");
    assert_diagnostic!(&err, "exec.bar");
}

#[test]
fn missing_import() {
    let context = TestContext::new();
    let source = source_file!(
        &context,
        r#"
    begin
        exec.u64::add
    end"#
    );

    let err = context.assemble(source).expect_err("expected missing import to be rejected");
    assert_diagnostic!(&err, "invalid relative item path 'u64::add'");
    assert_diagnostic!(&err, "absolute, local, or qualified by an import or submodule");
    assert_diagnostic!(&err, "exec.u64::add");
}

#[test]
fn invalid_proc_invalid_numeric_name() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc 123 add mul end begin push.1 exec.123 end");
    let err = context
        .assemble(source)
        .expect_err("expected numeric procedure name to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected a procedure name");
    assert_diagnostic!(&err, "unexpected token in block");
}

#[test]
fn invalid_proc_duplicate_procedure_name() {
    let context = TestContext::default();
    let source =
        source_file!(&context, "proc foo add mul end proc foo push.3 end begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected duplicate procedure name to be rejected");
    assert_diagnostic!(&err, "symbol conflict: found duplicate definitions of the same name");
    assert_diagnostic!(&err, "conflict occurs here");
    assert_diagnostic!(&err, "previously defined here");
    assert_diagnostic!(&err, "proc foo add mul end proc foo push.3 end begin push.1 end");
}

#[test]
fn invalid_if_missing_end_no_else() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 add if.true mul");
    let err = context.assemble(source).expect_err("expected missing if end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `if`");
    assert_diagnostic!(&err, "begin push.1 add if.true mul");
}

#[test]
fn invalid_else_with_no_if() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 add else mul end");
    let err = context.assemble(source).expect_err("expected unmatched else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `begin` block before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");

    let source = source_file!(&context, "begin push.1 while.true add else mul end end");
    let err = context.assemble(source).expect_err("expected while-local else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `while` before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");
}

#[test]
fn invalid_unmatched_else_within_if_else() {
    let context = TestContext::default();

    let source =
        source_file!(&context, "begin push.1 if.true add else mul else push.1 end end end");
    let err = context.assemble(source).expect_err("expected duplicate else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `if` before `else`");
    assert_diagnostic!(&err, "expected `end` to close `begin` block before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");
}

#[test]
fn invalid_if_else_no_matching_end() {
    let context = TestContext::default();

    let source = source_file!(&context, "begin push.1 add if.true mul else add");
    let err = context
        .assemble(source)
        .expect_err("expected missing if/else end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `if`");
    assert_diagnostic!(&err, "begin push.1 add if.true mul else add");
}

#[test]
fn invalid_repeat() {
    let context = TestContext::default();

    // unmatched repeat
    let source = source_file!(&context, "begin push.1 add repeat.10 mul");
    let err = context.assemble(source).expect_err("expected unmatched repeat to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `repeat`");
    assert_diagnostic!(&err, "begin push.1 add repeat.10 mul");

    // invalid iter count
    let source = source_file!(&context, "begin push.1 add repeat.23x3 mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected malformed repeat count to be rejected");
    assert_diagnostic!(&err, "invalid syntax: invalid instruction `x3` or malformed operands");
    assert_diagnostic!(&err, "begin push.1 add repeat.23x3 mul end end");

    // Overflow iter count
    let count: u64 = u32::MAX as u64 + 1;
    let source = source_file!(
        &context,
        format!(
            "\
            const CONSTANT = {count}
            begin
                repeat.CONSTANT
                    add
                end
            end
            "
        )
    );
    let err = context
        .assemble(source)
        .expect_err("expected overflowing repeat count to be rejected");
    assert_diagnostic!(&err, "invalid immediate: value is larger than expected range");
    assert_diagnostic!(&err, "repeat.CONSTANT");
}

#[test]
fn invalid_repeat_count_zero() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin repeat.0 nop end end");
    let error = context.assemble(source).expect_err("expected repeat.0 to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_zero_in_procedure() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
proc foo
    repeat.0
        nop
    end
end

begin
    call.foo
end"
    );
    let error = context.assemble(source).expect_err("expected repeat.0 to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_too_large() {
    let context = TestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = source_file!(&context, format!("begin repeat.{repeat_count} nop end end"));
    let error = context
        .assemble(source)
        .expect_err("expected repeat count above limit to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_constant_zero() {
    let context = TestContext::default();
    let source =
        source_file!(&context, "const REPEAT_COUNT = 0\nbegin repeat.REPEAT_COUNT nop end end");
    let error = context
        .assemble(source)
        .expect_err("expected repeat.0 from constant to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_constant_too_large() {
    let context = TestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = source_file!(
        &context,
        format!("const REPEAT_COUNT = {repeat_count}\nbegin repeat.REPEAT_COUNT nop end end")
    );
    let error = context
        .assemble(source)
        .expect_err("expected repeat count above limit from constant to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_constant_at_limit_allowed() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        format!("const REPEAT_COUNT = {MAX_REPEAT_COUNT}\nbegin repeat.REPEAT_COUNT nop end end")
    );
    context
        .parse_program(source)
        .expect("expected repeat count at limit from constant to parse and analyze");
}

#[test]
fn const_folding_modulus_aliasing_must_be_rejected() {
    let program_src = r#"
const ALIAS = 18446744069414584320+1

begin
    push.ALIAS
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected constants >= field modulus to be rejected (must not silently alias to 0)"
    );
}

#[test]
fn const_evaluator_modulus_aliasing_must_be_rejected() {
    let program_src = r#"
const X = 18446744069414584320
const Y = 1
const ALIAS = X+Y

begin
    push.ALIAS
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected out-of-range constant results to be rejected (must not silently alias via `Felt::new_unchecked`)"
    );
}

#[test]
fn const_folding_u64_overflow_must_not_panic_and_must_error() {
    let program_src = r#"
const WRAP = 18446744069414584320+18446744069414584320

begin
    push.WRAP
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while folding a constant expression with u64 overflow"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected the assembler to reject constant expressions which overflow u64 during folding"
    );
}

#[test]
fn const_folding_subtraction_underflow_must_be_rejected() {
    let program_src = r#"
const UNDERFLOW = 0-1

begin
    push.UNDERFLOW
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected subtraction underflow in constant expressions to be rejected"
    );
}

#[test]
fn const_division_slash_must_not_match_int_division() {
    let program_src = r#"
const A1 = 3/2
const B1 = 3//2

const X = 3
const Y = 2
const A2 = X/Y
const B2 = X//Y

begin
    push.A1
    push.B1
    push.A2
    push.B2
end
"#;

    let program = Assembler::default()
        .assemble_program("test", program_src)
        .expect("program assembly must succeed")
        .unwrap_program();

    let entry = program.get_node_by_id(program.entrypoint()).expect("missing entrypoint node");
    let mast = format!("{}", entry.to_display(program.mast_forest()));

    let toks: Vec<&str> = mast.split_whitespace().collect();
    let pad_incr_pairs = toks.windows(2).filter(|w| w[0] == "pad" && w[1] == "incr").count();

    assert_eq!(
        pad_incr_pairs, 2,
        "expected `/` (field division) to not fold to the same value as `//` (integer division)"
    );
}

#[test]
fn const_division_by_zero_must_error() {
    let program_src = r#"
const BAD = 1/0

begin
    push.BAD
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected division by zero in constant expressions to be rejected"
    );
}

#[test]
fn push_word_slice_u64_max_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[18446744073709551615]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[...] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[...] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn push_word_slice_range_u64_max_end_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[0..18446744073709551615]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[0..] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[0..] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn push_word_slice_range_u64_max_start_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[18446744073709551615..0]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[..0] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[..0] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn invalid_while() {
    let context = TestContext::default();

    let source = source_file!(&context, "begin push.1 add while mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected invalid while spelling to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected `while.true`");
    assert_diagnostic!(&err, "begin push.1 add while mul end end");

    let source = source_file!(&context, "begin push.1 add while.abc mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected invalid while spelling to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected `while.true`");
    assert_diagnostic!(&err, "begin push.1 add while.abc mul end end");

    let source = source_file!(&context, "begin push.1 add while.true mul");
    let err = context.assemble(source).expect_err("expected unmatched while to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `while`");
    assert_diagnostic!(&err, "begin push.1 add while.true mul");
}
