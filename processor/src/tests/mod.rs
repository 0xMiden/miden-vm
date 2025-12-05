/// Tests in this file make sure that diagnostics presented to the user are as expected.
use alloc::string::ToString;

use miden_assembly::{
    Assembler, DefaultSourceManager, PathBuf,
    ast::Module,
    testing::{TestContext, assert_diagnostic_lines, regex, source_file},
};
use miden_core::{
    AdviceMap,
    crypto::merkle::{MerkleStore, MerkleTree},
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
};
use miden_debug_types::{SourceContent, SourceLanguage, SourceManager, Uri};
use miden_utils_testing::{
    build_debug_test, build_test, build_test_by_mode,
    crypto::{init_merkle_leaves, init_merkle_store},
};

use super::*;

mod debug;
mod decorator_execution_tests;

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

    let err = Process::new(
        Kernel::default(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .execute(&program, &mut host)
    .unwrap_err();

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
    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle 8",
        "value for key 0x0000000000000000000000000000000001000000000000000200000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:31\]"#),
        " 2 |         begin",
        " 3 |             swap swap trace.2 adv.push_mapval",
        "   :                               ^^^^^^^^^^^^^^^",
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
    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle 8",
        "value for key 0x0000000000000000000000000000000001000000000000000200000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:31\]"#),
        " 2 |         begin",
        " 3 |             swap swap trace.2 adv.push_mapvaln",
        "   :                               ^^^^^^^^^^^^^^^^",
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
        "advice provider error at clock cycle 6",
        "stack read failed",
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
        "division by zero at clock cycle 5",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 div",
        "   :                     ^^^",
        " 4 |         end",
        "   `----"
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
        "division by zero at clock cycle 5",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 u32div",
        "   :                     ^^^^^^",
        " 4 |         end",
        "   `----"
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
        "failed to execute the dynamic code block provided by the stack with root 0x0000000000000000000000000000000000000000000000000000000000000000; the block could not be found",
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
        "failed to execute the dynamic code block provided by the stack with root 0x0000000000000000000000000000000000000000000000000000000000000000; the block could not be found",
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
        "assertion failed at clock cycle 9",
        regex!(r#",-\[test[\d]+:4:13\]"#),
        " 3 |             push.1.2",
        " 4 |             assertz",
        "   :             ^^^^^^^",
        " 5 |             push.3.4",
        "   `----"
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
        "assertion failed at clock cycle 9 with error message: some error message",
        regex!(r#",-\[test[\d]+:4:13\]"#),
        " 3 |             push.1.2",
        " 4 |             assertz.err=\"some error message\"",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 5 |             push.3.4",
        "   `----"
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
        "assertion failed at clock cycle 9 with error message: some error message",
        regex!(r#",-\[test[\d]+:5:13\]"#),
        " 4 |             push.1.2",
        " 5 |             assertz.err=ERR_MSG",
        "   :             ^^^^^^^^^^^^^^^^^^^",
        " 6 |             push.3.4",
        "   `----"
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
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        // Intentionally choose the wrong index to trigger the error
        (index + 1) as u64,
        tree.depth() as u64,
        leaves[index][0].as_int(),
        leaves[index][1].as_int(),
        leaves[index][2].as_int(),
        leaves[index][3].as_int(),
    ];

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "merkle path verification failed for value 0400000000000000000000000000000000000000000000000000000000000000 at index 4 in the Merkle tree with root",
        "| c9b007301fbe49f9c96698ea31f251b61d51674c892fbb2d8d349280bbd4a273 (error code: 0)",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mtree_verify",
        "   :             ^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // With message
    let source = "
        begin
            mtree_verify.err=\"some error message\"
        end";

    let index = 3_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        // Intentionally choose the wrong index to trigger the error
        (index + 1) as u64,
        tree.depth() as u64,
        leaves[index][0].as_int(),
        leaves[index][1].as_int(),
        leaves[index][2].as_int(),
        leaves[index][3].as_int(),
    ];

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "merkle path verification failed for value 0400000000000000000000000000000000000000000000000000000000000000 at index 4 in the Merkle tree with root",
        "| c9b007301fbe49f9c96698ea31f251b61d51674c892fbb2d8d349280bbd4a273 (error message: some error message)",
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

    let build_test = build_test_by_mode!(true, source, &[index, depth]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle 6",
        "provided node index 16 is out of bounds for a merkle tree node at depth 4",
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
        "when returning from a call or dyncall, stack depth must be 16, but was 17",
        regex!(r#",-\[test[\d]+:7:21\]"#),
        " 6 |         begin",
        " 7 |             trace.2 call.foo",
        "   :                     ^^^^|^^^",
        "   :                         `-- when returning from this call site",
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
            procref.foo mem_storew_be.100 dropw push.100
            dyncall
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "when returning from a call or dyncall, stack depth must be 16, but was 17",
        regex!(r#",-\[test[\d]+:8:13\]"#),
        " 7 |             procref.foo mem_storew_be.100 dropw push.100",
        " 8 |             dyncall",
        "   :             ^^^|^^^",
        "   :                `-- when returning from this call site",
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
        "attempted to calculate integer logarithm with zero argument at clock cycle 6",
        regex!(r#",-\[test[\d]+:3:21\]"#),
        " 2 |         begin",
        " 3 |             trace.2 ilog2",
        "   :                     ^^^^^",
        " 4 |         end",
        "   `----"
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
        "word memory access at address 3 in context 0 is unaligned at clock cycle 7",
        regex!(r#",-\[test[\d]+:4:22\]"#),
        " 3 |         begin",
        " 4 |             exec.foo mem_storew_be.3",
        "   :                      ^^^^^^^|^^^^^^^",
        "   :                             `-- tried to access memory address 3",
        " 5 |         end",
        "   `----",
        "  help: ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
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
        "word memory access at address 3 in context 0 is unaligned at clock cycle 6",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mem_loadw_be.3",
        "   :             ^^^^^^^|^^^^^^",
        "   :                    `-- tried to access memory address 3",
        " 4 |         end",
        "   `----",
        "  help: ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
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
            1,
            merkle_root[0].as_int(),
            merkle_root[1].as_int(),
            merkle_root[2].as_int(),
            merkle_root[3].as_int(),
            index,
            log_depth,
        ]
    };

    let build_test = build_test_by_mode!(true, source, stack, &advice_stack, merkle_store);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle 6",
        "failed to lookup value in Merkle store",
        "|",
        "`-> node Word([1, 0, 0, 0]) with index `depth=10, value=0` not found",
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
fn test_diagnostic_no_mast_forest_with_procedure() {
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

    let mut process = Process::new(
        Kernel::default(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_debugging(true),
    );
    let err = process.execute(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "no MAST forest contains the procedure with root digest 0x1b0a6d4b3976737badf180f3df558f45e06e6d1803ea5ad3b95fa7428caccd02",
        regex!(r#",-\[::\$exec:5:13\]"#),
        " 4 |         begin",
        " 5 |             call.bar::dummy_proc",
        "   :             ^^^^^^^^^^^^^^^^^^^^",
        " 6 |         end",
        "   `----"
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
        "if statement expected a binary value on top of the stack, but got 2",
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
        "loop condition must be a binary value, but got 2",
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
        "operation expected a binary value, but got 2",
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
        "operation expected a binary value, but got 2",
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
        "operation expected a binary value, but got 2",
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
        "operation expected a binary value, but got 2",
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
        "operation expected u32 values, but got values: [4294967296]",
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
        "operation expected u32 values, but got values: [4294967296]",
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

    let program = Assembler::with_kernel(source_manager.clone(), kernel_library)
        .assemble_program(program_source)
        .unwrap();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    // Note: we do not provide the kernel to trigger the error
    let mut process = Process::new(
        Kernel::default(),
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_debugging(true),
    );
    let err = process.execute(&program, &mut host).unwrap_err();
    assert_diagnostic_lines!(
        err,
        "syscall failed: procedure with root d754f5422c74afd0b094889be6b288f9ffd2cc630e3c44d412b1408b2be3b99c was not found in the kernel",
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
        "Value is not zero",
        regex!(r#",-\[test[\d]+:5:13\]"#),
        "4 |             push.1",
        "5 |             assertz.err=NONZERO",
        "  :             ^^^^^^^^^^^^^^^^^^^",
        "6 |         end",
        "  `----"
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

// Debug Mode Flag Propagation Test
// ------------------------------------------------------------------------------------------------

#[test]
fn test_debug_mode_flag_propagation() {
    use miden_core::stack::StackInputs;

    use crate::{AdviceInputs, ExecutionOptions, Kernel};

    // Test case 1: Both debugging and tracing disabled
    let exec_options_disabled = ExecutionOptions::default();
    let kernel = Kernel::new(&[]).expect("Failed to create kernel");
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();

    let process_disabled = Process::initialize(
        kernel.clone(),
        stack_inputs.clone(),
        advice_inputs.clone(),
        exec_options_disabled,
    );

    // Test case 2: Only tracing enabled
    let exec_options_tracing = ExecutionOptions::default().with_tracing();
    let process_tracing = Process::initialize(
        kernel.clone(),
        stack_inputs.clone(),
        advice_inputs.clone(),
        exec_options_tracing,
    );

    // Test case 3: Only debugging enabled
    let exec_options_debugging = ExecutionOptions::default().with_debugging(true);
    let process_debugging = Process::initialize(
        kernel.clone(),
        stack_inputs.clone(),
        advice_inputs.clone(),
        exec_options_debugging,
    );

    // Test case 4: Both tracing and debugging enabled
    let exec_options_both = ExecutionOptions::default().with_tracing().with_debugging(true);
    let process_both = Process::initialize(
        kernel.clone(),
        stack_inputs.clone(),
        advice_inputs.clone(),
        exec_options_both,
    );

    // Test case 5: Process::new_debug() method
    let process_new_debug = Process::new_debug(kernel, stack_inputs, advice_inputs);

    // Verify that in_debug_mode is false when neither is enabled
    assert!(
        !process_disabled.decoder.in_debug_mode(),
        "Debug mode should be disabled when neither debugging nor tracing is enabled"
    );

    // According to the task description, in_debug_mode should be true when tracing is enabled
    // But currently this will fail because the logic is incorrect
    // This test will help us verify our fix
    assert!(
        process_tracing.decoder.in_debug_mode(),
        "Debug mode should be enabled when tracing is enabled"
    );

    // Verify that in_debug_mode is true when debugging is enabled
    assert!(
        process_debugging.decoder.in_debug_mode(),
        "Debug mode should be enabled when debugging is enabled"
    );

    // Verify that in_debug_mode is true when both are enabled
    assert!(
        process_both.decoder.in_debug_mode(),
        "Debug mode should be enabled when both debugging and tracing are enabled"
    );

    // Verify that Process::new_debug() correctly enables debug mode
    assert!(
        process_new_debug.decoder.in_debug_mode(),
        "Debug mode should be enabled when using Process::new_debug()"
    );
}
