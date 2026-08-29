// PROGRAMS WITH PROCEDURES
// ================================================================================================

use super::*;

#[test]
fn program_with_one_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_nested_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        proc foo push.3 push.7 mul end \
        proc bar push.5 exec.foo add end \
        begin push.2 push.4 add exec.foo push.11 exec.bar sub end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_proc_locals() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        @locals(4) proc foo \
            loc_store.0 \
            add \
            loc_load.0 \
            mul \
        end \
        begin \
            push.10 push.9 push.8 \
            exec.foo \
        end"
    );
    let program = context.assemble(source)?;
    // Note: 18446744069414584317 == -4 (mod 2^64 - 2^32 + 1)
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_proc_locals_fail() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
proc foo
    loc_store.0
    add
    loc_load.0
    mul
end
begin
    push.4 push.3 push.2
    exec.foo
end"
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid procedure local reference to be rejected");
    assert_diagnostic!(&err, "invalid procedure local reference");
    assert_diagnostic!(&err, "the procedure local index referenced here is invalid");
    assert_diagnostic!(&err, "this procedure definition does not allocate any locals");
    assert_diagnostic!(&err, "loc_store.0");
}

#[test]
fn program_with_exported_procedure() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "pub proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected exported program procedure to be rejected");
    assert_diagnostic!(&err, "invalid program: procedure exports are not allowed");
    assert_diagnostic!(&err, "perhaps you meant to use `proc` instead of `export`");
    assert_diagnostic!(&err, "pub proc foo");
}
