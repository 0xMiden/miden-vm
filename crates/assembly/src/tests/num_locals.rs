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

/// Regression test for the AST-producer path in issue #3331.
///
/// The `@locals(..)` grammar cannot attach locals to a `begin`..`end` block, so the parser can
/// never produce an entrypoint with locals. On the contrary, the AST API can, the entrypoint
/// compiles to an ordinary procedure reachable via `Module::procedures_mut`, and
/// `Procedure::set_num_locals` bypasses the parser entirely. An entrypoint with locals is an
/// unrecoverable producer bug, so the invariant is enforced at the mutation site and must panic
/// there.
#[test]
#[should_panic(expected = "program entrypoint cannot have locals")]
fn test_entrypoint_with_locals_via_setter_panics() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 drop end");
    let mut program = context.parse_program(source).expect("failed to parse executable module");

    for proc in program.procedures_mut() {
        proc.set_num_locals(4);
    }
}

/// The assembler keeps its own assertion as a backstop for entrypoints constructed with locals
/// directly via `Procedure::new`, which bypasses the `set_num_locals` guard. This
/// mirrors how the semantic analyzer lowers a `begin`..`end` block into a `main` procedure, but
/// with a non-zero local count. See issue #3331.
#[test]
#[should_panic(expected = "program entrypoint cannot have locals")]
fn test_entrypoint_with_locals_via_constructor_panics() {
    let context = TestContext::default();

    let body = Block::new(
        SourceSpan::default(),
        Vec::from([Op::Inst(Span::unknown(Instruction::Assertz))]),
    );
    let main =
        Procedure::new(SourceSpan::default(), Visibility::Public, ProcedureName::main(), 4, body);

    let mut module = Module::new_executable();
    module
        .define_procedure(main, context.source_manager())
        .expect("failed to define entrypoint");

    let _ = Assembler::new(context.source_manager()).assemble_program("test", module);
}
