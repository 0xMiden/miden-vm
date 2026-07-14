// NESTED CONTROL BLOCKS
// ================================================================================================

use super::*;

#[test]
fn nested_control_blocks() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(
        &context,
        "begin \
        push.2 push.3 \
        if.true \
            add while.true push.7 push.11 add end \
        else \
            mul repeat.2 push.8 end if.true mul end  \
        end
        push.3 add
        end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

fn nested_if_source(depth: usize) -> String {
    let mut source = String::from("begin\n");
    for _ in 0..depth {
        source.push_str("push.1\nif.true\n");
    }
    source.push_str("push.1\n");
    for _ in 0..depth {
        source.push_str("end\n");
    }
    source.push_str("end\n");
    source
}

#[test]
fn control_flow_nesting_depth_boundary() -> TestResult {
    let context = TestContext::default();
    let source = nested_if_source(MAX_CONTROL_FLOW_NESTING);
    let source = source_file!(&context, source.as_str());
    context.assemble(source)?;
    Ok(())
}

#[test]
fn control_flow_nesting_depth_exceeded() {
    let context = TestContext::default();
    let source = nested_if_source(MAX_CONTROL_FLOW_NESTING + 1);
    let source = source_file!(&context, source.as_str());
    let error = context
        .assemble(source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");
    assert_diagnostic!(&error, "control-flow nesting depth exceeded");
}
