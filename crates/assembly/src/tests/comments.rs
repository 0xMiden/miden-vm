// COMMENTS
// ================================================================================================

use super::*;

#[test]
fn comment_simple() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin # simple comment \n push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_in_nested_control_blocks() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(
        &context,
        "begin \
        push.1 push.2 \
        if.true \
            # nested comment \n\
            add while.true push.7 push.11 add end \
        else \
            mul repeat.2 push.8 end if.true mul end  \
            # nested comment \n\
        end
        push.3 add
        end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_before_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "# starting comment \n begin push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_after_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 push.2 add end # closing comment");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn can_push_constant_word() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
const A = 0x0200000000000000030000000000000004000000000000000500000000000000
begin
    push.A
end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_advmap_push() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A(0x0200000000000000020000000000000002000000000000000200000000000000) = [0x01]
begin push.A adv.push_mapval assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_advmap_push_nokey() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A = [0x01]
begin push.A adv.push_mapval assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_adv_has_map_key() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A(0x0200000000000000020000000000000002000000000000000200000000000000) = [0x01]
begin adv.has_mapkey assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}
