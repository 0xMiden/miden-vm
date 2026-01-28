use alloc::{string::ToString, sync::Arc};

use miden_assembly::{
    Assembler, DefaultSourceManager, PathBuf,
    ast::Module,
    testing::{TestContext, assert_diagnostic_lines, regex, source_file},
};
use miden_core::{
    AdviceMap,
    crypto::merkle::{MerkleStore, MerkleTree},
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
    stack::StackInputs,
};
use miden_debug_types::{SourceContent, SourceLanguage, SourceManager, Uri};
use miden_utils_testing::{
    build_debug_test, build_test, build_test_by_mode,
    crypto::{init_merkle_leaves, init_merkle_store},
};

/// Tests in this file make sure that diagnostics presented to the user are as expected.
use super::*;
use crate::fast::FastProcessor;

mod debug;
mod debug_mode_decorator_tests;

// AdviceMap inlined in the script
// ------------------------------------------------------------------------------------------------

#[test]
fn test_advice_map_inline() {
    let source = "\
adv_map A = [0x01]

begin
  push.A
  adv.push_mapval
  dropw
  adv_push.1
  push.1
  assert_eq
end";

    let build_test = build_test!(source);
    build_test.execute().unwrap();
}

// AdviceMapKeyAlreadyPresent
// ------------------------------------------------------------------------------------------------

/// In this test, we load 2 libraries which have a MAST forest with an advice map that contains
/// different values at the same key (which triggers the `AdviceMapKeyAlreadyPresent` error).
#[test]
#[ignore = "program must now call same node from both libraries (Issue #1949)"]
fn test_diagnostic_advice_map_key_already_present() {
    let test_context = TestContext::new();

    let (lib_1, lib_2) = {
        let dummy_library_source = source_file!(&test_context, "pub proc foo add end");
        let module = test_context.parse_module_with_path("foo::bar", dummy_library_source).unwrap();
        let lib = test_context.assemble_library(std::iter::once(module)).unwrap();
        let lib_1 = lib
            .clone()
            .with_advice_map(AdviceMap::from_iter([(Word::default(), vec![ZERO])]));
        let lib_2 = lib.with_advice_map(AdviceMap::from_iter([(Word::default(), vec![ONE])]));

        (lib_1, lib_2)
    };

    let mut host = DefaultHost::default();
    host.load_library(lib_1.mast_forest()).unwrap();
    host.load_library(lib_2.mast_forest()).unwrap();

    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Noop], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle",
        "x value for key 0x0000000000000000000000000000000000000000000000000000000000000000 already present in the advice map",
        "help: previous values at key were '[0]'. Operation would have replaced them with '[1]'"
    );
}

// AdviceMapKeyNotFound
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_advice_map_key_not_found_1() {
    let source = "
        begin
            swap swap trace.2 adv.push_mapval
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    // Note: The source location points to the first operation in the basic block because
    // system event errors currently don't have access to the specific operation index.
    assert_diagnostic_lines!(
        err,
        "value for key 0x0100000000000000020000000000000000000000000000000000000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             swap swap trace.2 adv.push_mapval",
        "   :             ^^^^",
        "4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_advice_map_key_not_found_2() {
    let source = "
        begin
            swap swap trace.2 adv.push_mapvaln
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    // Note: The source location points to the first operation in the basic block because
    // system event errors currently don't have access to the specific operation index.
    assert_diagnostic_lines!(
        err,
        "value for key 0x0100000000000000020000000000000000000000000000000000000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             swap swap trace.2 adv.push_mapvaln",
        "   :             ^^^^",
        "4 |         end",
        "   `----"
    );
}

// AdviceStackReadFailed
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_advice_stack_read_failed() {
    let source = "
        begin
            swap adv_push.1 trace.2
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x advice stack read failed",
        regex!(r#",-\[test[\d]+:3:18\]"#),
        " 2 |         begin",
        " 3 |             swap adv_push.1 trace.2",
        "   :                  ^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// DivideByZero
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_divide_by_zero_1() {
    let source = "
        begin
            trace.2 div
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x division by zero",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 div",
        "   :                     ^^^",
        " 4 |         end",
        "   `----",
        "  help: ensure the divisor (second stack element) is non-zero before division or modulo operations"
    );
}

#[test]
fn test_diagnostic_divide_by_zero_2() {
    let source = "
        begin
            trace.2 u32div
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x division by zero",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 u32div",
        "   :                     ^^^^^^",
        " 4 |         end",
        "   `----",
        "  help: ensure the divisor (second stack element) is non-zero before division or modulo operations"
    );
}

// DynamicNodeNotFound
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_dynamic_node_not_found_1() {
    let source = "
        begin
            trace.2 dynexec
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x failed to execute dynamic code block; block with root 0x0000000000000000000000000000000000000000000000000000000000000000 could not be found",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 dynexec",
        "   :                     ^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_dynamic_node_not_found_2() {
    let source = "
        begin
            trace.2 dyncall
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x failed to execute dynamic code block; block with root 0x0000000000000000000000000000000000000000000000000000000000000000 could not be found",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 dyncall",
        "   :                     ^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// FailedAssertion
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_failed_assertion() {
    // No error message
    let source = "
        begin
            push.1.2
            assertz
            push.3.4
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x assertion failed with error code: 0",
        regex!(r#",-\[test[\d]+:4:13\]"#),
        " 3 |             push.1.2",
        " 4 |             assertz",
        "   :             ^^^^^^^",
        " 5 |             push.3.4",
        "   `----",
        "  help: assertions validate program invariants. Review the assertion condition and ensure all prerequisites are met"
    );

    // With error message
    let source = "
        begin
            push.1.2
            assertz.err=\"some error message\"
            push.3.4
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x assertion failed with error message: some error message",
        regex!(r#",-\[test[\d]+:4:13\]"#),
        " 3 |             push.1.2",
        " 4 |             assertz.err=\"some error message\"",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 5 |             push.3.4",
        "   `----",
        "  help: assertions validate program invariants. Review the assertion condition and ensure all prerequisites are met"
    );

    // With error message as constant
    let source = "
        const ERR_MSG = \"some error message\"
        begin
            push.1.2
            assertz.err=ERR_MSG
            push.3.4
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x assertion failed with error message: some error message",
        regex!(r#",-\[test[\d]+:5:13\]"#),
        " 4 |             push.1.2",
        " 5 |             assertz.err=ERR_MSG",
        "   :             ^^^^^^^^^^^^^^^^^^^",
        " 6 |             push.3.4",
        "   `----",
        "  help: assertions validate program invariants. Review the assertion condition and ensure all prerequisites are met"
    );
}

#[test]
fn test_diagnostic_merkle_path_verification_failed() {
    // No message
    let source = "
        begin
            mtree_verify
        end";

    let index = 3_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
        // Intentionally choose the wrong index to trigger the error
        (index + 1) as u64,
        tree.depth() as u64,
        leaves[index][0].as_canonical_u64(),
        leaves[index][1].as_canonical_u64(),
        leaves[index][2].as_canonical_u64(),
        leaves[index][3].as_canonical_u64(),
    ];

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store);
    let err = build_test.execute().expect_err("expected error");
    // With LE sponge, the root hash changes and lookup fails at root level instead of path
    // verification
    assert_diagnostic_lines!(
        err,
        "failed to lookup value in Merkle store",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mtree_verify",
        "   :             ^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // With message - same error format change applies
    let source = "
        begin
            mtree_verify.err=\"some error message\"
        end";

    let index = 3_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
        // Intentionally choose the wrong index to trigger the error
        (index + 1) as u64,
        tree.depth() as u64,
        leaves[index][0].as_canonical_u64(),
        leaves[index][1].as_canonical_u64(),
        leaves[index][2].as_canonical_u64(),
        leaves[index][3].as_canonical_u64(),
    ];

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store);
    let err = build_test.execute().expect_err("expected error");
    // With LE sponge, the root hash changes and lookup fails at root level
    assert_diagnostic_lines!(
        err,
        "failed to lookup value in Merkle store",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mtree_verify.err=\"some error message\"",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// InvalidMerkleTreeNodeIndex
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_invalid_merkle_tree_node_index() {
    let source = "
        begin
            mtree_get
        end";

    let depth = 4;
    let index = 16;

    let build_test = build_test_by_mode!(true, source, &[depth, index]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x provided node index 16 is out of bounds for a merkle tree node at depth 4",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mtree_get",
        "   :             ^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// InvalidStackDepthOnReturn
// ------------------------------------------------------------------------------------------------

/// Ensures that the proper `ExecutionError::InvalidStackDepthOnReturn` diagnostic is generated when
/// the stack depth is invalid on return from a call.
#[test]
fn test_diagnostic_invalid_stack_depth_on_return_call() {
    // returning from a function with non-empty overflow table should result in an error
    // Note: we add the `trace.2` to ensure that asm ops co-exist well with other decorators.
    let source = "
        proc foo
            push.1
        end

        begin
            trace.2 call.foo
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x when returning from a call, stack depth must be 16, but was 17",
        regex!(r#",-\[test[\d]+:7:21\]"#),
        " 6 |         begin",
        " 7 |             trace.2 call.foo",
        "   :                     ^^^^^^^^",
        " 8 |         end",
        "   `----"
    );
}

/// Ensures that the proper `ExecutionError::InvalidStackDepthOnReturn` diagnostic is generated when
/// the stack depth is invalid on return from a dyncall.
#[test]
fn test_diagnostic_invalid_stack_depth_on_return_dyncall() {
    // returning from a function with non-empty overflow table should result in an error
    let source = "
        proc foo
            push.1
        end

        begin
            procref.foo mem_storew_le.100 dropw push.100
            dyncall
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x when returning from a call, stack depth must be 16, but was 17",
        regex!(r#",-\[test[\d]+:8:13\]"#),
        " 7 |             procref.foo mem_storew_le.100 dropw push.100",
        " 8 |             dyncall",
        "   :             ^^^^^^^",
        " 9 |         end",
        "   `----"
    );
}

// LogArgumentZero
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_log_argument_zero() {
    // taking the log of 0 should result in an error
    let source = "
        begin
            trace.2 ilog2
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x attempted to calculate integer logarithm with zero argument",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 ilog2",
        "   :                     ^^^^^",
        " 4 |         end",
        "   `----",
        "  help: ilog2 requires a non-zero argument"
    );
}

// MemoryError
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_unaligned_word_access() {
    // mem_storew_be
    let source = "
        proc foo add end
        begin
            exec.foo mem_storew_be.3
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2, 3, 4]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "word access at memory address 3 in context 0 is unaligned",
        regex!(r#",-\[test[\d]+:4:22\]"#),
        " 3 |         begin",
        " 4 |             exec.foo mem_storew_be.3",
        "   :                      ^^^^^^^^^^^^^^^",
        " 5 |         end",
        "   `----",
        "help: ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    );

    // mem_loadw_be
    let source = "
        begin
            mem_loadw_be.3
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2, 3, 4]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "word access at memory address 3 in context 0 is unaligned",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mem_loadw_be.3",
        "   :             ^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----",
        "help: ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    );
}

#[test]
fn test_diagnostic_address_out_of_bounds() {
    // mem_store
    let source = "
        begin
            mem_store
        end";

    let build_test = build_test_by_mode!(true, source, &[u32::MAX as u64 + 1_u64]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "memory address cannot exceed 2^32 but was 4294967296",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mem_store",
        "   :             ^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // mem_storew_be
    let source = "
        begin
            mem_storew_be
        end";

    let build_test = build_test_by_mode!(true, source, &[u32::MAX as u64 + 1_u64]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "memory address cannot exceed 2^32 but was 4294967296",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mem_storew_be",
        "   :             ^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // mem_load
    let source = "
        begin
            swap swap mem_load push.1 drop
        end";

    let build_test = build_test_by_mode!(true, source, &[u32::MAX as u64 + 1_u64]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "memory address cannot exceed 2^32 but was 4294967296",
        regex!(r#",-\[test[\d]+:3:23\]"#),
        " 2 |         begin",
        " 3 |             swap swap mem_load push.1 drop",
        "   :                       ^^^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // mem_loadw_be
    let source = "
        begin
            swap swap mem_loadw_be push.1 drop
        end";

    let build_test = build_test_by_mode!(true, source, &[u32::MAX as u64 + 1_u64]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "memory address cannot exceed 2^32 but was 4294967296",
        regex!(r#",-\[test[\d]+:3:23\]"#),
        " 2 |         begin",
        " 3 |             swap swap mem_loadw_be push.1 drop",
        "   :                       ^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// MerkleStoreLookupFailed
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_merkle_store_lookup_failed() {
    let source = "
        begin
            mtree_set
        end";

    let leaves = &[1, 2, 3, 4];
    let merkle_tree = MerkleTree::new(init_merkle_leaves(leaves)).unwrap();
    let merkle_root = merkle_tree.root();
    let merkle_store = MerkleStore::from(&merkle_tree);
    let advice_stack = Vec::new();

    let stack = {
        let log_depth = 10;
        let index = 0;

        &[
            log_depth, // depth at position 0 (top)
            index,
            merkle_root[3].as_canonical_u64(),
            merkle_root[2].as_canonical_u64(),
            merkle_root[1].as_canonical_u64(),
            merkle_root[0].as_canonical_u64(),
            1, // new value V
        ]
    };

    let build_test = build_test_by_mode!(true, source, stack, &advice_stack, merkle_store);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "failed to lookup value in Merkle store",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mtree_set",
        "   :             ^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// NoMastForestWithProcedure
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_no_mast_forest_with_procedure_call() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        let uri = Uri::from("src.masm");
        let content = SourceContent::new(SourceLanguage::Masm, uri.clone(), src);
        let source_file = source_manager.load_from_raw_parts(uri.clone(), content);
        Module::parse(
            PathBuf::new(module_name).unwrap(),
            miden_assembly::ast::ModuleKind::Library,
            source_file,
            source_manager.clone(),
        )
        .unwrap()
    };

    let program_source = "
        use foo::bar

        begin
            call.bar::dummy_proc
        end
    ";

    let library = Assembler::new(source_manager.clone()).assemble_library([lib_module]).unwrap();

    let program = Assembler::new(source_manager.clone())
        .with_dynamic_library(&library)
        .unwrap()
        .assemble_program(program_source)
        .unwrap();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new_debug(StackInputs::default(), AdviceInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "no MAST forest contains the procedure with root digest 0xc85d62dad9e9a4195dcd2d75f1deb32116ee4d6ed3d8cc3948c6e7cf1142c7f4",
        regex!(r#",-\[::\$exec:5:13\]"#),
        " 4 |         begin",
        " 5 |             call.bar::dummy_proc",
        "   :             ^^^^^^^^^^^^^^^^^^^^",
        " 6 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_no_mast_forest_with_procedure_loop() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        let uri = Uri::from("src.masm");
        let content = SourceContent::new(SourceLanguage::Masm, uri.clone(), src);
        let source_file = source_manager.load_from_raw_parts(uri.clone(), content);
        Module::parse(
            PathBuf::new(module_name).unwrap(),
            miden_assembly::ast::ModuleKind::Library,
            source_file,
            source_manager.clone(),
        )
        .unwrap()
    };

    let program_source = "
        use foo::bar

        begin
            push.1
            while.true
                exec.bar::dummy_proc
            end
        end
    ";

    let library = Assembler::new(source_manager.clone()).assemble_library([lib_module]).unwrap();

    let program = Assembler::new(source_manager.clone())
        .with_dynamic_library(&library)
        .unwrap()
        .assemble_program(program_source)
        .unwrap();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new_debug(StackInputs::default(), AdviceInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "no MAST forest contains the procedure with root digest 0xc85d62dad9e9a4195dcd2d75f1deb32116ee4d6ed3d8cc3948c6e7cf1142c7f4",
        regex!(r#",-\[::\$exec:6:13\]"#),
        "  5 |                 push.1",
        "  6 | ,->             while.true",
        "  7 | |                   exec.bar::dummy_proc",
        "  8 | `->             end",
        "  9 |             end",
        "    `----"
    );
}

#[test]
fn test_diagnostic_no_mast_forest_with_procedure_split() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        let uri = Uri::from("src.masm");
        let content = SourceContent::new(SourceLanguage::Masm, uri.clone(), src);
        let source_file = source_manager.load_from_raw_parts(uri.clone(), content);
        Module::parse(
            PathBuf::new(module_name).unwrap(),
            miden_assembly::ast::ModuleKind::Library,
            source_file,
            source_manager.clone(),
        )
        .unwrap()
    };

    let program_source = "
        use foo::bar

        begin
            push.1
            if.true
                exec.bar::dummy_proc
            else
                push.2
            end
        end
    ";

    let library = Assembler::new(source_manager.clone()).assemble_library([lib_module]).unwrap();

    let program = Assembler::new(source_manager.clone())
        .with_dynamic_library(&library)
        .unwrap()
        .assemble_program(program_source)
        .unwrap();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new_debug(StackInputs::default(), AdviceInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "no MAST forest contains the procedure with root digest 0xc85d62dad9e9a4195dcd2d75f1deb32116ee4d6ed3d8cc3948c6e7cf1142c7f4",
        regex!(r#",-\[::\$exec:6:13\]"#),
        "  5 |                 push.1",
        "  6 | ,->             if.true",
        "  7 | |                   exec.bar::dummy_proc",
        "  8 | |               else",
        "  9 | |                   push.2",
        " 10 | `->             end",
        " 11 |             end",
        "    `----"
    );
}

// NotBinaryValue
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_not_binary_value_split_node() {
    let source = "
        begin
            if.true swap else dup end
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x if statement expected a binary value on top of the stack, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             if.true swap else dup end",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_not_binary_value_loop_node() {
    let source = "
        begin
            while.true swap dup end
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x loop condition must be a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             while.true swap dup end",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----",
        "  help: this could happen either when first entering the loop, or any subsequent iteration"
    );
}

#[test]
fn test_diagnostic_not_binary_value_cswap_cswapw() {
    // cswap
    let source = "
        begin
            cswap
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             cswap",
        "   :             ^^^^^",
        " 4 |         end",
        "   `----"
    );

    // cswapw
    let source = "
        begin
            cswapw
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             cswapw",
        "   :             ^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_not_binary_value_binary_ops() {
    // and
    let source = "
        begin
            and trace.2
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             and trace.2",
        "   :             ^^^",
        " 4 |         end",
        "   `----"
    );

    // or
    let source = "
        begin
            or trace.2
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             or trace.2",
        "   :             ^^",
        " 4 |         end",
        "   `----"
    );
}

// NotU32Values
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_not_u32_value() {
    // u32and
    let source = "
        begin
            u32and trace.2
        end";

    let big_value = u32::MAX as u64 + 1_u64;
    let build_test = build_test_by_mode!(true, source, &[big_value]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected u32 values, but got values: [4294967296]",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             u32and trace.2",
        "   :             ^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // u32madd
    let source = "
        begin
            u32overflowing_add3 trace.2
        end";

    let big_value = u32::MAX as u64 + 1_u64;
    let build_test = build_test_by_mode!(true, source, &[big_value]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected u32 values, but got values: [4294967296]",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             u32overflowing_add3 trace.2",
        "   :             ^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// SyscallTargetNotInKernel
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_syscall_target_not_in_kernel() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let kernel_source = "
        pub proc dummy_proc
            push.1 drop
        end
    ";

    let program_source = "
        begin
            syscall.dummy_proc
        end
    ";

    let kernel_library =
        Assembler::new(source_manager.clone()).assemble_kernel(kernel_source).unwrap();

    let program = {
        let program = Assembler::with_kernel(source_manager.clone(), kernel_library)
            .assemble_program(program_source)
            .unwrap();

        // Note: we do not provide the kernel to trigger the error
        Program::with_kernel(program.mast_forest().clone(), program.entrypoint(), Kernel::default())
    };

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new_debug(StackInputs::default(), AdviceInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "syscall failed: procedure with root 0x90b881ddd998a6d2212b04620e312285df8fadec251aebb3f3096da501ca8f78 was not found in the kernel",
        regex!(r#",-\[::\$exec:3:13\]"#),
        " 2 |         begin",
        " 3 |             syscall.dummy_proc",
        "   :             ^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// Tests that the original error message is reported to the user together with
// the error code in case of assert failure.
#[test]
fn test_assert_messages() {
    let source = "
        const NONZERO = \"Value is not zero\"
        begin
            push.1
            assertz.err=NONZERO
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        "  x assertion failed with error message: Value is not zero",
        regex!(r#",-\[test[\d]+:5:13\]"#),
        " 4 |             push.1",
        " 5 |             assertz.err=NONZERO",
        "   :             ^^^^^^^^^^^^^^^^^^^",
        " 6 |         end",
        "   `----",
        "  help: assertions validate program invariants. Review the assertion condition and ensure all prerequisites are met"
    );
}

// Test the original issue with debug.stack.12 to see if it shows all items
//
// Updated in 2296: removed the 4 initial instructions, which are now inserted by the assembler for
// initializing the FMP.
#[test]
fn test_debug_stack_issue_2295_original_repeat() {
    let source = "
    begin
        repeat.12
            push.42
        end

        debug.stack.12  # <=== should show first 12 elements as 42
        dropw dropw dropw dropw
    end";

    // Execute with debug buffer
    let test = build_debug_test!(source);
    let (_stack, output) = test.execute_with_debug_buffer().expect("execution failed");

    // Test if debug.stack.12 shows all 12 push.42 items correctly
    insta::assert_snapshot!(output, @r"
    Stack state in interval [0, 11] before step 22:
    ├──  0: 42
    ├──  1: 42
    ├──  2: 42
    ├──  3: 42
    ├──  4: 42
    ├──  5: 42
    ├──  6: 42
    ├──  7: 42
    ├──  8: 42
    ├──  9: 42
    ├── 10: 42
    ├── 11: 42
    └── (16 more items)
    ");
}
