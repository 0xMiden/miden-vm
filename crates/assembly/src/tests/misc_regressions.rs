// MISC REGRESSIONS
// ================================================================================================

use super::*;

#[test]
fn test_issue_2181_locaddr_bug_assembly() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
proc some_proc
    nop
end

@locals(4)
proc main
    locaddr.0
    locaddr.0
    locaddr.0
    exec.some_proc
    dropw
end

begin
    exec.main
end"#
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// Tests conditional debug info functionality
///
/// This test is disabled because with debug mode always enabled (issue #1821),
/// we no longer have the ability to turn debug mode off. The old functionality
#[test]
fn test_assembler_debug_info_present() {
    let context = TestContext::default();
    let source = r#"
    namespace test::foo

    pub proc foo
        push.1 push.2 add
    end
    "#;

    let module = parse_module!(&context, source);

    // Test: With debug mode always enabled (issue #1821), debug info should always be present
    let assembler = Assembler::default();
    let library = assembler.assemble_library("test", module, None::<Box<Module>>).unwrap();
    // Debug info should be present since debug mode is enabled by default.
    // AssemblyOps are stored in package-owned source debug metadata.
    assert_package_has_source_asm_ops(
        &library,
        "Package-owned AssemblyOps should be present for tracking instructions",
    );
}
