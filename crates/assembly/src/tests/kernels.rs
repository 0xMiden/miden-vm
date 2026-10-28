// KERNELS AND SYSCALLS
// ================================================================================================

use super::*;

#[test]
fn can_assemble_a_multi_module_kernel() -> Result<(), Report> {
    const KERNEL: &str = r#"
        mod helpers
        use external::helpers as h
        pub proc foo
            exec.h::get_caller
            exec.helpers::get_caller
        end"#;
    const HELPERS: &str = r#"
        namespace $kernel::helpers

        pub proc get_caller
            caller
        end"#;
    const EXTERNAL_HELPERS: &str = r#"
        namespace external::helpers

        pub proc get_caller
            caller
        end"#;
    const PROGRAM: &str = r#"
        begin
            syscall.foo
        end"#;

    let context = TestContext::new();

    let kernel_lib = {
        let helpers = context.parse_module(HELPERS)?;
        let external_helpers = context.parse_module(EXTERNAL_HELPERS)?;
        let kernel = context.parse_kernel(source_file!(&context, KERNEL)).unwrap();

        let mut assembler = Assembler::new(context.source_manager());
        assembler.compile_and_statically_link(external_helpers)?;
        assembler.assemble_kernel("kernel", kernel, [helpers]).unwrap()
    };

    assert_eq!(kernel_lib.to_kernel_descriptor().ok().map(|k| k.proc_hashes().len()), Some(1));

    Assembler::with_kernel(context.source_manager(), Arc::from(kernel_lib))?
        .assemble_program("program", PROGRAM)?;

    Ok(())
}

#[test]
fn regression_empty_kernel_is_rejected() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "pub const FOO = 1\n";
    let err = Assembler::new(source_manager)
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_masm)).unwrap(),
            None,
        )
        .expect_err("expected empty kernel to be rejected");
    assert_diagnostic_lines!(err, "package must contain at least one exported procedure");
}

#[test]
fn regression_empty_kernel_with_submodule_is_rejected() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "mod sub\n\npub const FOO = 1\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(source_manager)
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected empty kernel to be rejected");
    assert_diagnostic_lines!(err, "package must contain at least one exported procedure");
}

#[test]
fn regression_empty_kernel_with_nonempty_submodule_is_rejected() {
    let context = TestContext::default();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "mod sub\n\npub use {foo} from self::sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let err = context
        .parse_kernel(source_file!(&context, kernel_masm))
        .expect_err("expected sema to reject re-export from kernel module");
    assert_diagnostic!(err, "invalid re-exported procedure");
}

#[test]
fn regression_reexport_of_kernel_procedure_from_kernel_submodule_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm =
        "namespace $kernel::sub\n\npub use {root} from $kernel\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected kernel submodule re-exporting kernel syscall to be rejected");
    assert_diagnostic!(err, "invalid re-export of kernel syscall");
}

#[test]
fn regression_exec_of_kernel_procedure_is_rejected() {
    let context = TestContext::default();

    // The root kernel module is allowed to exec other syscalls, as shown here, but submodules
    // are not allowed to do this, as procedures exported from submodules are not required to be
    // invoked with `syscall`, so we must enforce the syscall constraint on all modules other than
    // the kernel module itself
    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n\npub proc other exec.root end";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo exec.$kernel::root end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected assembler to reject exec of syscall from within kernel submodule");
    assert_diagnostic!(err, "kernel procedure '::$kernel::root' can only be invoked via syscall");
}

#[test]
fn regression_syscall_of_kernel_submodule_procedure_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo syscall.root end\n";
    let program_masm = "begin syscall.::$kernel::sub::foo end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let _kernel = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect("expected valid kernel");
    let err = context
        .parse_module(source_file!(&context, program_masm))
        .expect_err("expected sema to reject syscall of non-syscall procedure");
    assert_diagnostic!(err, "invalid syscall: callee must be resolvable to kernel module");
}

#[test]
fn test_kernel_linking_against_its_own_library() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub mod lib

        proc internal_proc
            caller
            drop
            exec.$kernel::lib::lib_proc
        end

        pub proc kernel_proc
            exec.internal_proc
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace $kernel::lib

            pub proc lib_proc
                swap
            end
            "#
    ))?;

    let _ = Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, [lib])?;

    Ok(())
}

#[test]
fn test_syscall_resolution_uses_kernel_module() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end

        pub proc bar
            caller
            drop
            push.2
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace userspace

            pub proc bar
                push.0
            end
            "#
    ))?;

    let source = source_file!(
        &context,
        r#"
        use {bar} from userspace

        proc foo
            push.0
        end

        begin
            syscall.foo
            syscall.bar
        end
        "#
    );

    let kernel =
        Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, None)?;
    let kernel_bar_root = kernel.as_ref().get_procedure_root_by_path("::$kernel::bar").unwrap();
    let kernel_foo_root = kernel.as_ref().get_procedure_root_by_path("::$kernel::foo").unwrap();

    let mut assembler = Assembler::with_kernel(context.source_manager(), Arc::from(kernel))?;
    assembler.compile_and_statically_link(lib)?;
    let program = assembler.assemble_program("program", source)?.unwrap_program();

    let mast = {
        let entry = program.get_node_by_id(program.entrypoint()).unwrap();
        format!("{}", entry.to_display(program.mast_forest()))
    };

    let expected = format!(
        r#"join
    join
        basic_block push(2147483648) push(4294967294) mstore drop noop end
        syscall.{kernel_foo_root}
    end
    syscall.{kernel_bar_root}
end"#
    );
    assert_eq!(mast, expected);

    Ok(())
}

#[test]
fn test_syscall_resolution_to_non_kernel_path_is_checked() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace userspace

            pub proc bar
                push.0
            end
            "#
    ))?;

    let source = source_file!(
        &context,
        r#"
        begin
            syscall.userspace::bar
        end
        "#
    );

    let kernel =
        Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, None)?;
    let lib = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        lib,
        None::<Box<Module>>,
    )?;

    let error = Assembler::with_kernel(context.source_manager(), Arc::from(kernel))?
        .with_package(Arc::from(lib), Linkage::Static)?
        .assemble_program("program", source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");

    assert_diagnostic!(&error, "invalid syscall: callee must be resolvable to kernel module");
    assert_diagnostic!(&error, "syscall.userspace::bar");

    Ok(())
}

#[test]
fn syscall_validation_does_not_panic_on_same_digest_userspace_procedure() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .expect("kernel assembly must succeed");

    let assembler = Assembler::with_kernel(source_manager, Arc::from(kernel_lib))
        .expect("test package should be valid");

    let program_src = r#"
proc dup
    push.1
end

begin
    exec.dup
    syscall.k1
end
"#;

    let assembled =
        catch_unwind(AssertUnwindSafe(|| assembler.assemble_program("program", program_src)));
    assert!(assembled.is_ok(), "assembler panicked while assembling a valid program");
    assert!(assembled.unwrap().is_ok(), "expected program assembly to succeed");
}

#[test]
fn syscall_by_unknown_digest_is_rejected_at_assembly_time_when_kernel_is_configured() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .expect("kernel assembly must succeed");

    let assembler = Assembler::with_kernel(source_manager, Arc::from(kernel_lib))
        .expect("test kernel should be valid");

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let err = assembler
        .assemble_program("program", program_src)
        .expect_err("expected unknown digest syscall to be rejected");
    assert_diagnostic!(err, "invalid syscall");
}

#[test]
fn syscall_without_kernel_is_rejected_at_assembly_time() {
    let context = TestContext::default();
    let assembler = Assembler::new(context.source_manager());

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let err = assembler
        .assemble_program("program", program_src)
        .expect_err("expected syscall without kernel to be rejected");
    assert_diagnostic!(err, "invalid syscall");
}

#[test]
fn regression_kernel_exports_are_syscall_only_for_all_non_syscall_entrypoints() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .map(Arc::<Package>::from)
        .expect("kernel assembly must succeed");

    let cases = vec![
        (
            "exec",
            "proc user\n    exec.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "call",
            "proc user\n    call.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "procref",
            "proc user\n    procref.::$kernel::k1\n    dropw\nend\n\nbegin\n    call.user\nend\n"
                .to_string(),
        ),
    ];

    for (kind, program_src) in cases {
        let err = Assembler::with_kernel(source_manager.clone(), Arc::clone(&kernel))
            .expect("test kernel should be valid")
            .assemble_program("program", program_src)
            .expect_err(&format!("kernel exports should be syscall-only, but {kind} succeeded"));
        assert_diagnostic!(err, "syscall");
    }
}
