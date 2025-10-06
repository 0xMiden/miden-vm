use alloc::vec::Vec;

use pretty_assertions::assert_eq;
use miden_core::{
    assert_matches, crypto::hash::RpoDigest, mast::{MastForest, MastNode}, Felt, PrimeCharacteristicRing, Program
};

use super::{Assembler, Operation};
use crate::{
    assembler::mast_forest_builder::MastForestBuilder, diagnostics::Report, testing::TestContext,
};

// TESTS
// ================================================================================================

#[test]
fn nested_blocks() -> Result<(), Report> {
    const KERNEL: &str = r#"
        export.foo
            add
        end"#;
    const MODULE: &str = "foo::bar";
    const MODULE_PROCEDURE: &str = r#"
        export.baz
            push.29
        end"#;

    let context = TestContext::new();
    let assembler = {
        let kernel_lib = Assembler::new(context.source_manager()).assemble_kernel(KERNEL).unwrap();

        let dummy_module =
            context.parse_module_with_path(MODULE.parse().unwrap(), MODULE_PROCEDURE)?;
        let dummy_library = Assembler::new(context.source_manager())
            .assemble_library([dummy_module])
            .unwrap();

        let mut assembler = Assembler::with_kernel(context.source_manager(), kernel_lib);
        assembler.add_library(dummy_library).unwrap();

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
        let kernel_foo_node_id =
            expected_mast_forest_builder.ensure_block(vec![Operation::Add], None).unwrap();

        expected_mast_forest_builder.ensure_syscall(kernel_foo_node_id).unwrap()
    };

    let program = r#"
    use.foo::bar

    proc.foo
        push.19
    end

    proc.bar
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
        exec.bar::baz
        syscall.foo
    end"#;

    let program = assembler.assemble_program(program).unwrap();

    // basic block representing foo::bar.baz procedure
    let exec_foo_bar_baz_node_id = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(29_u32))], None)
        .unwrap();

    let before = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(2))], None)
        .unwrap();

    let r#true1 = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(3))], None)
        .unwrap();
    let r#false1 = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(5))], None)
        .unwrap();
    let r#if1 = expected_mast_forest_builder.ensure_split(r#true1, r#false1).unwrap();

    let r#true3 = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(7))], None)
        .unwrap();
    let r#false3 = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(11))], None)
        .unwrap();
    let r#true2 = expected_mast_forest_builder.ensure_split(r#true3, r#false3).unwrap();

    let r#while = {
        let body_node_id = expected_mast_forest_builder
            .ensure_block(
                vec![
                    Operation::Push(Felt::from_u32(17)),
                    Operation::Push(Felt::from_u32(19)),
                    Operation::Push(Felt::from_u32(23)),
                ],
                None,
            )
            .unwrap();

        expected_mast_forest_builder.ensure_loop(body_node_id).unwrap()
    };
    let push_13_basic_block_id = expected_mast_forest_builder
        .ensure_block(vec![Operation::Push(Felt::from_u32(13))], None)
        .unwrap();

    let r#false2 = expected_mast_forest_builder
        .ensure_join(push_13_basic_block_id, r#while)
        .unwrap();
    let nested = expected_mast_forest_builder.ensure_split(r#true2, r#false2).unwrap();

    let combined_node_id = expected_mast_forest_builder
        .join_nodes(vec![before, r#if1, nested, exec_foo_bar_baz_node_id, syscall_foo_node_id])
        .unwrap();

    let mut expected_mast_forest = expected_mast_forest_builder.build().0;
    expected_mast_forest.make_root(combined_node_id);
    let expected_program = Program::new(expected_mast_forest.into(), combined_node_id);
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
        proc.foo
            emit.1
        end

        proc.bar
            emit.2
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();

    let procedure_digests: Vec<RpoDigest> = program.mast_forest().procedure_digests().collect();

    // foo, bar and entrypoint
    assert_eq!(3, procedure_digests.len());

    // Ensure that foo, bar and entrypoint all have different digests
    assert_ne!(procedure_digests[0], procedure_digests[1]);
    assert_ne!(procedure_digests[0], procedure_digests[2]);
    assert_ne!(procedure_digests[1], procedure_digests[2]);
}

/// Since `foo` and `bar` have the same body, we only expect them to be added once to the program.
#[test]
fn duplicate_procedure() {
    let context = TestContext::new();

    let program_source = r#"
        proc.foo
            add
            mul
        end

        proc.bar
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
    assert_eq!(program.num_procedures(), 2);
}

#[test]
fn distinguish_grandchildren_correctly() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            while.true
                trace.1234
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

    let join_node = match &program.mast_forest()[program.entrypoint()] {
        MastNode::Join(node) => node,
        _ => panic!("expected join node"),
    };

    // Make sure that both `if.true` blocks compile down to a different MAST node.
    assert_ne!(join_node.first(), join_node.second());
}

/// Ensures that equal MAST nodes don't get added twice to a MAST forest
#[test]
fn duplicate_nodes() {
    let context = TestContext::new().with_debug_info(false);

    let program_source = r#"
    begin
        if.true
            mul
        else
            if.true add else mul end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();

    let mut expected_mast_forest = MastForest::new();

    let mul_basic_block_id = expected_mast_forest.add_block(vec![Operation::Mul], None).unwrap();

    let add_basic_block_id = expected_mast_forest.add_block(vec![Operation::Add], None).unwrap();

    // inner split: `if.true add else mul end`
    let inner_split_id =
        expected_mast_forest.add_split(add_basic_block_id, mul_basic_block_id).unwrap();

    // root: outer split
    let root_id = expected_mast_forest.add_split(mul_basic_block_id, inner_split_id).unwrap();

    expected_mast_forest.make_root(root_id);

    let expected_program = Program::new(expected_mast_forest.into(), root_id);

    assert_eq!(expected_program, program);
}

#[test]
fn explicit_fully_qualified_procedure_references() -> Result<(), Report> {
    const BAR_NAME: &str = "foo::bar";
    const BAR: &str = r#"
        export.bar
            add
        end"#;
    const BAZ_NAME: &str = "foo::baz";
    const BAZ: &str = r#"
        export.baz
            exec.::foo::bar::bar
        end"#;

    let context = TestContext::default();
    let bar = context.parse_module_with_path(BAR_NAME.parse().unwrap(), BAR)?;
    let baz = context.parse_module_with_path(BAZ_NAME.parse().unwrap(), BAZ)?;
    let library = context.assemble_library([bar, baz]).unwrap();

    let assembler = Assembler::new(context.source_manager()).with_library(&library).unwrap();

    let program = r#"
    begin
        exec.::foo::baz::baz
    end"#;

    assert_matches!(assembler.assemble_program(program), Ok(_));
    Ok(())
}

#[test]
fn re_exports() -> Result<(), Report> {
    const BAR_NAME: &str = "foo::bar";
    const BAR: &str = r#"
        export.bar
            add
        end"#;

    const BAZ_NAME: &str = "foo::baz";
    const BAZ: &str = r#"
        use.foo::bar

        export.bar::bar

        export.baz
            push.1 push.2 add
        end"#;

    let context = TestContext::new();
    let bar = context.parse_module_with_path(BAR_NAME.parse().unwrap(), BAR)?;
    let baz = context.parse_module_with_path(BAZ_NAME.parse().unwrap(), BAZ)?;
    let library = context.assemble_library([bar, baz]).unwrap();

    let assembler = Assembler::new(context.source_manager()).with_library(&library).unwrap();

    let program = r#"
    use.foo::baz

    begin
        push.1 push.2
        exec.baz::baz
        push.3 push.4
        exec.baz::bar
    end"#;

    assert_matches!(assembler.assemble_program(program), Ok(_));
    Ok(())
}
