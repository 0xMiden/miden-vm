// LINK CYCLES
// ================================================================================================

use super::*;

#[test]
fn imported_main_alias_self_call_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let program = r#"
        use {"$main" as alias_main} from ::$exec

        begin
            call.alias_main
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_program("test", program)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled
        .unwrap()
        .expect_err("expected self-referential alias call to be rejected");
    assert_diagnostic!(&err, "found a cycle in the call graph");
    assert_diagnostic!(&err, "::$exec::$main");
}

#[test]
fn rootless_call_cycle_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let program = r#"
        begin
            call.b
        end

        proc b
            call."$main"
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_program("test", program)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled.unwrap().expect_err("expected cyclic program to be rejected");
    assert_diagnostic!(&err, "found a cycle in the call graph");
    assert_diagnostic!(&err, "::$exec::$main");
    assert_diagnostic!(&err, "b");
}

#[test]
fn cyclic_link_retry_is_structured_error_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::linker::Linker;

    let context = TestContext::new();
    let module = context
        .parse_program(source_file!(
            &context,
            r#"
                begin
                    call.b
                end

                proc b
                    call."$main"
                end
            "#
        ))
        .expect("program parsing must succeed");
    let source_manager = context.source_manager();

    let first_attempt = catch_unwind(AssertUnwindSafe(|| {
        let mut linker = Linker::new(source_manager.clone());
        let first_err = linker
            .link([module.clone()], None::<Box<Module>>)
            .expect_err("expected cyclic program to be rejected on first link");
        let second_err = linker
            .link(core::iter::empty::<Box<Module>>(), None::<Box<Module>>)
            .expect_err("expected cyclic program to be rejected on second link");
        (first_err, second_err)
    }));

    assert!(first_attempt.is_ok(), "linker panicked while retrying a cyclic link");
    let (first_err, second_err) = first_attempt.unwrap();
    assert!(first_err.to_string().contains("found a cycle in the call graph"));
    assert!(second_err.to_string().contains("found a cycle in the call graph"));
}

#[test]
fn test_cross_module_constant_cycle_in_procedure_scope_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::a

            use cycle::b

            pub proc use_cycle
                push.A
                drop
            end

            pub const A = b::B + 1
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::b

            use cycle::a
            pub const B = a::A + 1
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled.unwrap().expect_err("expected cyclic constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const A = b::B + 1");
    assert_diagnostic!(&err, "pub const B = a::A + 1");
}

#[test]
fn imported_error_message_cycle_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::errs::a

            use cycle::errs::b

            pub proc use_cycle
                assert.err=ERR_A
            end

            pub const ERR_A = b::ERR_B
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::errs::b

            use cycle::errs::a
            pub const ERR_B = a::ERR_A
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled
        .unwrap()
        .expect_err("expected cyclic error message constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const ERR_A = b::ERR_B");
    assert_diagnostic!(&err, "pub const ERR_B = a::ERR_A");
}
