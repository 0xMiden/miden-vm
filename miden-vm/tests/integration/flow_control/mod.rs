use alloc::sync::Arc;

use miden_assembly::{Assembler, PathBuf, Report, ast::ModuleKind};
use miden_core_lib::CoreLibrary;
use miden_debug_types::{SourceLanguage, SourceManager};
use miden_processor::ExecutionError;
use miden_prover::Word;
use miden_utils_testing::{StackInputs, Test, build_test, expect_exec_error_matches, push_inputs};
use miden_vm::Module;

// SIMPLE FLOW CONTROL TESTS
// ================================================================================================

#[test]
fn conditional_execution() {
    // --- if without else ------------------------------------------------------------------------
    let source = "begin dup.1 dup.1 eq if.true add end end";

    let test = build_test!(source, &[1, 2]);
    test.expect_stack(&[2, 1]);

    let test = build_test!(source, &[3, 3]);
    test.expect_stack(&[6]);

    // --- if with else ------------------------------------------------------------------------
    let source = "begin dup.1 dup.1 eq if.true add else mul end end";

    let test = build_test!(source, &[2, 3]);
    test.expect_stack(&[6]);

    let test = build_test!(source, &[3, 3]);
    test.expect_stack(&[6]);
}

#[test]
fn conditional_loop() {
    // --- entering the loop ----------------------------------------------------------------------
    // computes sum of values from 0 to the value at the top of the stack
    let source = "
        begin
            dup push.0 movdn.2 neq.0
            while.true
                dup movup.2 add swap push.1 sub dup neq.0
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[55]);

    // --- skipping the loop ----------------------------------------------------------------------
    let source = "begin dup eq.0 while.true add end end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[10]);
}

#[test]
fn faulty_condition_from_loop() {
    let source = "
        begin
            push.1
            while.true
                push.100
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueLoop { label: _, source_file: _, value: _ }
    );
}

#[test]
fn counter_controlled_loop() {
    // --- entering the loop ----------------------------------------------------------------------
    // compute 2^10
    let source = "
        begin
            push.2
            push.1
            repeat.10
                dup.1 mul
            end
            movdn.2 drop drop
        end";

    let test = build_test!(source);
    test.expect_stack(&[1024]);
}

// NESTED CONTROL FLOW
// ================================================================================================

#[test]
fn if_in_loop() {
    let source = "
        begin
            dup push.0 movdn.2 neq.0
            while.true
                dup movup.2 dup.1 eq.5
                if.true
                    mul
                else
                    add
                end
                swap push.1 sub dup neq.0
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[210]);
}

#[test]
fn if_in_loop_in_if() {
    let source = "
        begin
            dup eq.10
            if.true
                dup push.0 movdn.2 neq.0
                while.true
                    dup movup.2 dup.1 eq.5
                    if.true
                        mul
                    else
                        add
                    end
                    swap push.1 sub dup neq.0
                end
                drop
            else
                dup mul
            end
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[210]);

    let test = build_test!(source, &[11]);
    test.expect_stack(&[121]);
}

// FUNCTION CALLS
// ================================================================================================

#[test]
fn local_fn_call() {
    // returning from a function with non-empty overflow table should result in an error
    let source = "
        proc foo
            push.1
        end

        begin
            call.foo
        end";

    let build_test = build_test!(source, &[1, 2]);
    expect_exec_error_matches!(
        build_test,
        ExecutionError::InvalidStackDepthOnReturn { depth: 17, label: _, source_file: _ }
    );

    let inputs = (1_u64..18).collect::<Vec<_>>();

    // dropping values from the stack in the current execution context should not affect values
    // in the overflow table from the parent execution context
    let source = format!(
        "
        proc foo
            repeat.20
                drop
            end
        end

        begin
            {inputs}
            push.18
            call.foo
            repeat.16
                drop
            end

            swapw dropw
        end",
        inputs = push_inputs(&inputs)
    );

    let test = build_test!(source, &[]);
    test.expect_stack(&[2, 1]);

    test.prove_and_verify(vec![], false);
}

#[test]
fn local_fn_call_with_mem_access() {
    // foo should be executed in a different memory context; thus, when we read from memory after
    // calling foo, the value saved into memory[0] before calling foo should still be there.
    let source = "
        proc foo
            mem_store.0
        end

        begin
            mem_store.0
            call.foo
            mem_load.0
            eq.7

            swap drop
        end";

    let test = build_test!(source, &[3, 7]);
    test.expect_stack(&[1]);

    test.prove_and_verify(vec![3, 7], false);
}

#[test]
fn simple_syscall() {
    let kernel_source = "
        pub proc foo
            add
        end
    ";

    let program_source = "
        begin
            syscall.foo
        end";

    // TODO: update and use macro?
    let mut test = Test::new(&format!("test{}", line!()), program_source, false);
    test.stack_inputs = StackInputs::try_from_ints([1, 2]).unwrap();
    test.kernel_source = Some(test.source_manager.load(
        SourceLanguage::Masm,
        format!("kernel{}", line!()).into(),
        kernel_source.to_string(),
    ));
    test.expect_stack(&[3]);

    test.prove_and_verify(vec![1, 2], false);
}

#[test]
fn simple_syscall_2() {
    let kernel_source = "
        pub proc foo
            add
        end
        pub proc bar
            mul
        end
    ";

    // Note: we call each twice to ensure that the multiset check handles it correctly
    let program_source = "
        begin
            syscall.foo
            syscall.foo
            syscall.bar
            syscall.bar
        end";

    // TODO: update and use macro?
    let mut test = Test::new(&format!("test{}", line!()), program_source, false);
    test.stack_inputs = StackInputs::try_from_ints([2, 2, 3, 2, 1]).unwrap();
    test.kernel_source = Some(test.source_manager.load(
        SourceLanguage::Masm,
        format!("kernel{}", line!()).into(),
        kernel_source.to_string(),
    ));
    test.expect_stack(&[24]);

    test.prove_and_verify(vec![2, 2, 3, 2, 1], false);
}

/// Tests that `CALL`ing from a syscall context works correctly, especially in terms of properly
/// handling the fmp (through procedure locals).
///
/// The flow is as follows:
/// new_ctx (program) -> first_kernel_entry (syscall) -> userland (call) -> second_kernel_entry
/// (syscall)
#[test]
fn call_in_syscall() {
    let kernel_source = "
        # USER CONTEXT FUNCTIONS (i.e. not 0)
        # ====================================================================================

        @locals(4)
        proc userland
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to memory locals, which should not affect context 0 memory
            push.5.6.7.8 loc_storew_be.0 dropw

            # Syscall back into context 0
            syscall.second_kernel_entry

            # Ensure that procedure locals were untouched
            loc_loadw_be.0 push.5.6.7.8 assert_eqw
        end

        # CONTEXT 0 FUNCTIONS
        # ====================================================================================

        @locals(4)
        pub proc second_kernel_entry
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to procedure locals. We will later ensure that this write didn't affect procedure locals
            # in first_kernel_entry.
            push.9.10.11.12 loc_storew_be.0 dropw
        end

        @locals(4)
        pub proc first_kernel_entry
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to memory locals. We will ensure at the end that these values are still present
            push.1.2.3.4 loc_storew_be.0 dropw

            # Call userland, which will syscall back into context 0
            call.userland

            # Ensure that procedure locals were untouched
            loc_loadw_be.0 push.1.2.3.4 assert_eqw
        end
    ";

    let program_source = "
        proc new_ctx
            syscall.first_kernel_entry
        end

        begin
            # Call into a new context which will syscall back into context 0.
            call.new_ctx
        end";

    let mut test = Test::new(&format!("test{}", line!()), program_source, false);
    test.kernel_source = Some(test.source_manager.load(
        SourceLanguage::Masm,
        format!("kernel{}", line!()).into(),
        kernel_source.to_string(),
    ));
    test.expect_stack(&[]);

    test.prove_and_verify(Vec::new(), false);
}

/// Tests that syscalling back into context 0 uses a different overflow table with each call.
#[test]
fn root_context_separate_overflows() {
    let kernel_source = "
    pub proc foo
        # Drop an element, which in the failing case removes the `100` from the overflow table
        drop
    end
    ";

    let program_source = "
    proc bar
        syscall.foo
    end

    begin
        # => [100]

        # push `100` on overflow stack
        swap.15 push.0

        # Call `bar`, which will syscall back into this context
        call.bar

        # Place back the 100 on top of the stack
        drop swap.15
    end";

    let mut test = Test::new(&format!("test{}", line!()), program_source, false);
    test.stack_inputs = StackInputs::try_from_ints([100]).unwrap();
    test.kernel_source = Some(test.source_manager.load(
        SourceLanguage::Masm,
        format!("kernel{}", line!()).into(),
        kernel_source.to_string(),
    ));
    test.expect_stack(&[100]);
    test.prove_and_verify(vec![100], false);
}

// DYNAMIC CODE EXECUTION
// ================================================================================================

#[test]
fn simple_dyn_exec() {
    let program_source = "
        proc foo
            add
        end

        begin
            # call foo directly
            call.foo

            # move the first result of foo out of the way
            movdn.4

            # use dynexec to call foo again via its hash, which is stored at memory location 40
            mem_storew_be.40 dropw
            push.40
            dynexec
        end";

    // The hash of foo can be obtained with:
    // let context = miden_assembly::testing::TestContext::new();
    // let program = context.assemble(program_source).unwrap();
    // let procedure_digests: Vec<Digest> = program.mast_forest().procedure_digests().collect();
    // let foo_digest = procedure_digests[0];
    // std::println!("foo digest: {foo_digest:?}");

    // As ints:
    // [7259075614730273379, 2498922176515930900, 11574583201486131710, 6285975441353882141]

    let stack_init: [u64; 7] = [
        3,
        // put the hash of foo on the stack
        7259075614730273379,
        2498922176515930900,
        11574583201486131710,
        6285975441353882141,
        1,
        2,
    ];

    let test = Test {
        stack_inputs: StackInputs::try_from_ints(stack_init).unwrap(),
        ..Test::new(&format!("test{}", line!()), program_source, true)
    };

    test.expect_stack(&[6]);

    test.prove_and_verify(stack_init.to_vec(), false);
}

#[test]
fn dynexec_with_procref() {
    let program_source = "
    use external::module

    proc foo
        push.1.2
        u32wrapping_add
    end

    begin
        procref.foo mem_storew_be.40 dropw push.40
        dynexec

        procref.module::func mem_storew_be.40 dropw push.40
        dynexec

        dup
        push.4
        assert_eq.err=\"101\"

        swap drop
    end";

    let mut test = build_test!(program_source, &[]);
    test.libraries.push(CoreLibrary::default().library().clone());
    test.add_module(
        "external::module",
        "\
        pub proc func
            u32wrapping_add.1
        end
        ",
    );

    test.expect_stack(&[4]);
}

#[test]
fn simple_dyncall() {
    let program_source = "
        proc foo
            # test that the execution context has changed
            mem_load.0 assertz

            # add the two values on top of the stack
            add
        end

        begin
            # write to memory so we can test that `call` and `dyncall` change the execution context
            push.5 mem_store.0

            # call foo directly
            call.foo

            # move the first result of foo out of the way
            movdn.4

            # use dyncall to call foo again via its hash, which is on the stack
            mem_storew_be.40 dropw
            push.40
            dyncall

            swapw dropw
        end";

    // The hash of foo can be obtained with:
    // let context = miden_assembly::testing::TestContext::new();
    // let program = context.assemble(program_source).unwrap();
    // let procedure_digests: Vec<Digest> = program.mast_forest().procedure_digests().collect();
    // let foo_digest = procedure_digests[0];
    // std::println!("foo digest: {foo_digest:?}");

    //
    // As ints:
    //   [6751154577850596602, 235765701633049111, 16334162752640292120, 7786442719091086500]

    let mut test = Test {
        stack_inputs: StackInputs::try_from_ints([
            3,
            // put the hash of foo on the stack
            6751154577850596602,
            235765701633049111,
            16334162752640292120,
            7786442719091086500,
            1,
            2,
        ])
        .unwrap(),
        libraries: vec![CoreLibrary::default().into()],
        ..Test::new(&format!("test{}", line!()), program_source, false)
    };
    test.add_event_handlers(CoreLibrary::default().handlers());

    test.expect_stack(&[6]);

    test.prove_and_verify(
        vec![
            3,
            6751154577850596602,
            235765701633049111,
            16334162752640292120,
            7786442719091086500,
            1,
            2,
        ],
        false,
    );
}

/// Calls `bar` dynamically, which issues a syscall. We ensure that the `caller` instruction in the
/// kernel procedure correctly returns the hash of `bar`.
///
/// We also populate the stack before `dyncall` to ensure that stack depth is properly restored
/// after `dyncall`.
#[test]
fn dyncall_with_syscall_and_caller() {
    let kernel_source = "
        pub proc foo
            caller
        end
    ";

    let program_source = "
        proc bar
            syscall.foo
        end

        begin
            # Populate stack before call
            push.1 push.2 push.3 push.4 padw

            # Prepare dyncall
            procref.bar mem_storew_be.40 dropw push.40
            dyncall

            # Truncate stack
            movupw.3 dropw movupw.3 dropw
        end";

    let mut test = Test::new(&format!("test{}", line!()), program_source, true);
    test.kernel_source = Some(test.source_manager.load(
        SourceLanguage::Masm,
        format!("kernel{}", line!()).into(),
        kernel_source.to_string(),
    ));
    test.expect_stack(&[
        7618101086444903432,
        9972424747203251625,
        14917526361757867843,
        9845116178182948544,
        4,
        3,
        2,
        1,
    ]);

    test.prove_and_verify(vec![], false);
}

// PROCREF INSTRUCTION
// ================================================================================================

#[test]
fn procref() -> Result<(), Report> {
    let module_source = "
    use miden::core::math::u64
    pub use u64::overflowing_add

    @locals(4)
    pub proc foo
        push.3.4
    end
    ";

    // obtain procedures' MAST roots by compiling them as module
    let mast_roots: Vec<Word> = {
        let source_manager = Arc::new(miden_assembly::DefaultSourceManager::default());
        let module_path = PathBuf::new("test::foo").unwrap();
        let mut parser = Module::parser(ModuleKind::Library);
        let module = parser.parse_str(module_path, module_source, source_manager.clone())?;
        let library = Assembler::new(source_manager)
            .with_dynamic_library(CoreLibrary::default())
            .unwrap()
            .assemble_library([module])
            .unwrap();

        let module_info = library.module_infos().next().unwrap();

        module_info.procedure_digests().collect()
    };

    let source = "
    use miden::core::math::u64
    use miden::core::sys

    @locals(4)
    proc foo
        push.3.4
    end

    begin
        procref.u64::overflowing_add
        push.0
        procref.foo

        exec.sys::truncate_stack
    end";

    let core_lib = CoreLibrary::default();
    let mut test = build_test!(source, &[]);
    test.libraries.push(core_lib.library().clone());
    test.add_event_handlers(core_lib.handlers());

    test.expect_stack(&[
        mast_roots[0][3].as_int(),
        mast_roots[0][2].as_int(),
        mast_roots[0][1].as_int(),
        mast_roots[0][0].as_int(),
        0,
        mast_roots[1][3].as_int(),
        mast_roots[1][2].as_int(),
        mast_roots[1][1].as_int(),
        mast_roots[1][0].as_int(),
    ]);

    test.prove_and_verify(vec![], false);
    Ok(())
}
