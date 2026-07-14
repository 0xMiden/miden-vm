// MAST TESTS
// ================================================================================================

use super::*;

#[test]
fn nested_blocks() -> Result<(), Report> {
    const KERNEL: &str = r#"
        pub proc foo
            add
        end"#;
    const MODULE_PROCEDURE: &str = r#"
        namespace libs::helpers

        pub proc help
            push.29
        end"#;

    let context = TestContext::new();
    let assembler = {
        let kernel_lib = Assembler::new(context.source_manager())
            .assemble_kernel("kernel", context.parse_kernel(source_file!(&context, KERNEL))?, None)
            .map(Arc::<Package>::from)
            .unwrap();

        let dummy_module = context.parse_module(MODULE_PROCEDURE)?;
        let dummy_library = Assembler::new(context.source_manager())
            .assemble_library("dummy", dummy_module, None::<Box<Module>>)
            .unwrap();

        let mut assembler = Assembler::with_kernel(context.source_manager(), kernel_lib)?;
        assembler.link_package(Arc::from(dummy_library), Linkage::Dynamic).unwrap();

        assembler
    };

    // The expected `MastForest` for the program (that we will build by hand)
    let mut expected_mast_forest_builder = MastForestBuilder::default();

    // fetch the kernel digest and store into a syscall block
    //
    // Note: this assumes the current internal implementation detail that `assembler.mast_forest`
    // contains the MAST nodes for the kernel after a call to
    // `Assembler::with_kernel_from_module()`.
    let syscall_foo_node_id = {
        let kernel_foo_node_ref = expected_mast_forest_builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![])
            .unwrap();

        expected_mast_forest_builder
            .ensure_call_node_ref(
                kernel_foo_node_ref,
                true,
                AssemblyOp::new(None, "test".into(), 1, "syscall.foo".into()),
            )
            .unwrap()
    };

    let program = r#"
    use libs::helpers

    proc foo
        push.19
    end

    proc bar
        push.17
        exec.foo
    end

    begin
        push.2
        if.true
            push.3
        else
            push.5
        end
        if.true
            if.true
                push.7
            else
                push.11
            end
        else
            push.13
            while.true
                exec.bar
                push.23
            end
        end
        exec.helpers::help
        syscall.foo
    end"#;

    let program = assembler.assemble_program("program", program).unwrap().unwrap_program();

    // basic block representing foo::bar.baz procedure
    let exec_foo_bar_baz_node_ref = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(29))], vec![], vec![])
        .unwrap();

    let fmp_initialization = expected_mast_forest_builder
        .ensure_block_ref(fmp_initialization_sequence(), vec![], vec![])
        .unwrap();

    let before = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(2))], vec![], vec![])
        .unwrap();

    let r#true1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(3))], vec![], vec![])
        .unwrap();
    let r#false1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(5))], vec![], vec![])
        .unwrap();
    let r#if1 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true1, r#false1],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let r#true3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(7))], vec![], vec![])
        .unwrap();
    let r#false3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(11))], vec![], vec![])
        .unwrap();
    let r#true2 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true3, r#false3],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let r#while = {
        let body_node_ref = expected_mast_forest_builder
            .ensure_block_ref(
                vec![
                    Operation::Push(Felt::from_u32(17)),
                    Operation::Push(Felt::from_u32(19)),
                    Operation::Push(Felt::from_u32(23)),
                ],
                vec![],
                vec![],
            )
            .unwrap();

        let asm_op = AssemblyOp::new(None, "test".into(), 1, "while.true".into());
        let loop_node_ref = expected_mast_forest_builder
            .ensure_loop_node_ref(body_node_ref, asm_op.clone())
            .unwrap();
        let noop_node_ref = expected_mast_forest_builder
            .ensure_block_ref(vec![Operation::Noop], vec![], vec![])
            .unwrap();

        expected_mast_forest_builder
            .ensure_split_node_ref([loop_node_ref, noop_node_ref], asm_op)
            .unwrap()
    };
    let push_13_basic_block_ref = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(13))], vec![], vec![])
        .unwrap();

    let r#false2 = expected_mast_forest_builder
        .join_node_refs(vec![push_13_basic_block_ref, r#while], None)
        .unwrap();
    let nested = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true2, r#false2],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let combined_node_ref = expected_mast_forest_builder
        .join_node_refs(
            vec![
                fmp_initialization,
                before,
                r#if1,
                nested,
                exec_foo_bar_baz_node_ref,
                syscall_foo_node_id,
            ],
            None,
        )
        .unwrap();

    expected_mast_forest_builder.record_procedure_root_ref(combined_node_ref);
    let (mut expected_mast_forest, node_remapping) =
        expected_mast_forest_builder.build().unwrap().into_parts();
    expected_mast_forest.make_root(node_remapping[&combined_node_ref]);
    let expected_program =
        Program::new(expected_mast_forest.into(), node_remapping[&combined_node_ref]);
    assert_eq!(expected_program.hash(), program.hash());

    // also check that the program has the right number of procedures (which excludes the dummy
    // library and kernel)
    assert_eq!(program.num_procedures(), 3);

    Ok(())
}

/// Ensures that the arguments of `emit` do indeed modify the digest of a basic block
#[test]
fn emit_instruction_digest() {
    let context = TestContext::new();

    let program_source = r#"
        const EVT1 = event("miden::test::event_one")
        const EVT2 = event("miden::test::event_two")

        proc foo
            emit.EVT1
        end

        proc bar
            emit.EVT2
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();

    let procedure_digests: Vec<Word> = program.mast_forest().procedure_digests().collect();

    // foo, bar and entrypoint
    assert_eq!(3, procedure_digests.len());

    // Ensure that foo, bar and entrypoint all have different digests
    assert_ne!(procedure_digests[0], procedure_digests[1]);
    assert_ne!(procedure_digests[0], procedure_digests[2]);
    assert_ne!(procedure_digests[1], procedure_digests[2]);
}

/// Tests that emitting events with immediate values has the same MAST representation
/// regardless of whether using emit.value or push.value emit syntax
#[test]
fn emit_syntax_equivalence() {
    let context = TestContext::new();

    // First program uses a constant
    let program1_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            emit.EVT
        end
    "#;

    // Second program uses inline emit.event("...")
    let program2_source = r#"
        begin
            emit.event("miden::test::equiv")
        end
    "#;

    // Third program uses manual emit with constant event name
    let program3_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            push.EVT
            emit
            drop
        end
    "#;

    let program1 = context.assemble(program1_source).unwrap();
    let program2 = context.assemble(program2_source).unwrap();
    let program3 = context.assemble(program3_source).unwrap();

    // Get the MAST forest digests for both programs
    let digest1 = program1.hash();
    let digest2 = program2.hash();
    let digest3 = program3.hash();

    // Both programs should have identical MAST representations
    assert_eq!(digest1, digest2, "MAST digests differ between programs 1 and 2");
    assert_eq!(digest1, digest3, "MAST digests differ between programs 1 and 3");

    // Verify the procedure count is 1 (just the entrypoint) for both programs
    assert_eq!(program1.num_procedures(), 1);
    assert_eq!(program2.num_procedures(), 1);
    assert_eq!(program3.num_procedures(), 1);
}

/// Since `foo` and `bar` have the same body, we only expect them to be added once to the program.
#[test]
fn duplicate_procedure() {
    let context = TestContext::new();

    let program_source = r#"
        proc foo
            add
            mul
        end

        proc bar
            add
            mul
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();
    // `foo` and `bar` have the same body, so they are deduplicated. The entrypoint is the second
    // procedure.
    assert_eq!(program.num_procedures(), 2);
}

#[test]
fn distinguish_grandchildren_correctly() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            while.true
                push.2
                drop
                push.1
            end
        end

        if.true
            while.true
                push.1
            end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();

    let join_node = &program.mast_forest()[program.entrypoint()].unwrap_join();

    // Make sure that both `if.true` blocks compile down to a different MAST node.
    assert_ne!(join_node.first(), join_node.second());
}

#[test]
fn explicit_fully_qualified_procedure_references() -> Result<(), Report> {
    const ROOT: &str = r#"
        namespace foo

        pub mod bar
        pub mod baz
    "#;
    const BAR: &str = r#"
        namespace foo::bar

        pub proc bar
            add
        end"#;
    const BAZ: &str = r#"
        namespace foo::baz

        pub proc baz
            exec.::foo::bar::bar
        end"#;

    let context = TestContext::default();
    let root = context.parse_module(ROOT)?;
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, root, [bar, baz]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    begin
        exec.::foo::baz::baz
    end"#;

    assert_matches!(assembler.assemble_program("program", program), Ok(_));
    Ok(())
}

#[test]
fn re_exports() -> Result<(), Report> {
    const BAR: &str = r#"
        namespace foo::bar

        pub proc baz
            add
        end"#;

    const BAZ: &str = r#"
        namespace foo::baz

        pub use {baz} from foo::bar

        pub proc qux
            push.1 push.2 add
        end"#;

    let context = TestContext::new();
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, baz, [bar]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    use foo::baz

    begin
        push.1 push.2
        exec.baz::baz
        push.3 push.4
        exec.baz::qux
    end"#;

    assert_matches!(assembler.assemble_program("test", program), Ok(_));
    Ok(())
}

#[test]
fn module_ordering_can_be_arbitrary() -> Result<(), Report> {
    const A: &str = r#"
        namespace a

        pub proc foo
            add
        end"#;

    const B: &str = r#"
        namespace b

        pub proc bar
            push.1 push.2 exec.::a::foo
        end"#;

    const C: &str = r#"
        namespace c

        pub proc baz
            exec.::b::bar
        end"#;

    let context = TestContext::new();
    let a = context.parse_module(A)?;
    let b = context.parse_module(B)?;
    let c = context.parse_module(C)?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.compile_and_statically_link(b)?.compile_and_statically_link(a)?;
    assembler.assemble_library("lib", c, None::<Box<Module>>)?;

    Ok(())
}
