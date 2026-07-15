// PROGRAMS WITH DYNAMIC CODE BLOCKS
// ================================================================================================

use super::*;

#[test]
fn program_with_dynamic_code_execution() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin dynexec end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_dynamic_code_execution_in_new_context() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin dyncall end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}
