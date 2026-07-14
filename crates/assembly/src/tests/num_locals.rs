// PROCEDURE LOCALS LIMITS
// ================================================================================================

use super::*;

/// Parses a single-procedure module that uses a local (so codegen emits the frame-pointer
/// sequence), overrides the procedure's local count via the public AST API - bypassing the parser's
/// `@locals` cap - and assembles it into a library.
fn assemble_library_with_num_locals(
    context: &TestContext,
    num_locals: u16,
) -> Result<Box<Package>, Report> {
    let source = source_file!(
        &context,
        "  namespace test::repro
          @locals(1)
          pub proc foo
              loc_load.0
              drop
          end
          "
    );

    let mut module = context.parse_module(source)?;
    for proc in module.procedures_mut() {
        proc.set_num_locals(num_locals);
    }

    Assembler::new(context.source_manager()).assemble_library("test", module, None::<Box<Module>>)
}

#[test]
fn test_num_locals_above_max_is_rejected() {
    let context = TestContext::default();

    // Assembly must reject this gracefully (return Err), not overflow or panic.
    let err = assemble_library_with_num_locals(&context, 65535)
        .expect_err("assembling a procedure with 65535 locals should fail, not panic");
    assert_diagnostic!(&err, "number of procedure locals 65535 exceeds the maximum of 65532");
}

#[test]
fn test_num_locals_at_max_is_accepted() {
    let context = TestContext::default();

    // Assembly must succeed (return Ok) as long as the number of locals is up to the maximum.
    assemble_library_with_num_locals(&context, MAX_PROC_LOCALS)
        .expect("assembling a procedure with MAX_PROC_LOCALS should succeed");
}

#[test]
fn test_num_locals_one_above_max_is_rejected() {
    let context = TestContext::default();
    let err = assemble_library_with_num_locals(&context, MAX_PROC_LOCALS + 1)
        .expect_err("assembling a procedure with MAX_PROC_LOCALS + 1 should fail");
    assert_diagnostic!(&err, "number of procedure locals 65533 exceeds the maximum of 65532");
}
