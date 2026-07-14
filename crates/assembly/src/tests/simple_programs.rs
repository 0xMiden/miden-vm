// SIMPLE PROGRAMS
// ================================================================================================

use super::*;

#[test]
fn simple_instructions() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.0 assertz end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    let source = source_file!(&context, "begin push.10 push.50 push.2 u32wrapping_madd end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    let source = source_file!(&context, "begin push.10 push.50 push.2 u32wrapping_add3 end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly?
#[test]
#[ignore]
fn empty_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn empty_if() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin if.true end end");
    let err = context.assemble(source).expect_err("expected empty if block to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected a non-empty `if` block");
    assert_diagnostic!(&err, "begin if.true end end");
}

#[test]
fn empty_if_true_then_branch() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin if.true nop end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly
#[test]
#[ignore]
fn empty_while() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin while.true end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly
#[test]
#[ignore]
fn empty_repeat() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin repeat.5 end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// This test ensures that all iterations of a repeat control block are merged into a single basic
/// block.
#[test]
fn repeat_basic_blocks_merged() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin mul repeat.5 add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // Also ensure that dead code elimination works properly
    assert_eq!(program.mast_forest().num_nodes(), 1);
    Ok(())
}

/// A tail-controlled `do`..`while` loop lowers to a *bare* LOOP node, with no SPLIT wrapper
/// (unlike the head-controlled `while.true`, which adds a SPLIT for the entry check). The loop
/// body merges the `body` and `condition` sections into a single basic block.
#[test]
fn do_while_lowers_to_bare_loop() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin do push.1 while eq.0 end end");
    let program = context.assemble(source)?;
    let forest = program.mast_forest();

    let num_loops = forest.nodes().iter().filter(|n| matches!(n, MastNode::Loop(_))).count();
    let num_splits = forest.nodes().iter().filter(|n| matches!(n, MastNode::Split(_))).count();
    assert_eq!(num_loops, 1, "expected exactly one LOOP node");
    assert_eq!(num_splits, 0, "expected no SPLIT node for a do-while loop");

    let loop_node = forest
        .nodes()
        .iter()
        .find_map(|n| match n {
            MastNode::Loop(loop_node) => Some(loop_node),
            _ => None,
        })
        .unwrap();
    assert_matches!(&forest[loop_node.body()], MastNode::Block(_));
    Ok(())
}

/// Ensures `repeat` supports dynamic iteration counts provided via constants.
#[test]
fn repeat_dynamic_iteration_count() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "const A = 5 begin repeat.A add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn single_basic_block() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn basic_block_and_simple_if_true() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(&context, "begin push.2 push.3 if.true add else mul end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // if without else
    let source = source_file!(&context, "begin push.2 push.3 if.true add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn basic_block_and_simple_if_false() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(&context, "begin push.2 push.3 if.false add else mul end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // if without else
    let source = source_file!(&context, "begin push.2 push.3 if.false add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}
