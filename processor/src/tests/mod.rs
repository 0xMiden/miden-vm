use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly::{
    Assembler, DefaultSourceManager, Path, PathBuf,
    ast::{Module, ModuleKind},
    testing::{Pattern, TestContext, regex, source_file},
};
use miden_core::{
    crypto::merkle::{MerkleStore, MerkleTree},
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, error_code_from_msg},
};
use miden_debug_types::{Location, SourceFile, SourceManager, SourceSpan};
use miden_utils_testing::crypto::{init_merkle_leaves, init_merkle_store};

/// Tests in this file make sure that diagnostics presented to the user are as expected.
use crate::{
    BaseHost, DefaultHost, FastProcessor, Kernel, LoadedMastForest, ONE, ProcessorState, Program,
    StackInputs, SyncHost, Word, ZERO,
    advice::{AdviceInputs, AdviceMap, AdviceMutation},
    event::{EventError, EventHandler, EventName},
    operation::Operation,
};

macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected:expr),+ $(,)?) => {{
        let actual = format!(
            "{}",
            miden_assembly::diagnostics::reporting::PrintDiagnostic::new_without_color(&$diagnostic)
        );

        $(
            Pattern::from($expected).assert_match_with_context(&actual, &actual);
        )+
    }};
}

#[derive(Debug, thiserror::Error)]
#[error("dummy host event failure")]
struct DummyHostEventError;

struct AlwaysFailEventHandler;

impl EventHandler for AlwaysFailEventHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Err(DummyHostEventError.into())
    }
}

struct DuplicateMapMutationHandler;

impl EventHandler for DuplicateMapMutationHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![AdviceMutation::extend_map(AdviceMap::from_iter([(
            Word::default(),
            vec![ONE],
        )]))])
    }
}

fn parse_library_module(
    source_manager: Arc<dyn SourceManager>,
    module_name: &str,
    body: &str,
) -> Box<Module> {
    let path = PathBuf::new(module_name).unwrap();
    let source = format!("namespace {module_name}\n{body}");
    let mut parser = Module::parser(None);
    parser.parse_str(Some(path.as_path()), source, source_manager).unwrap()
}

fn parse_kernel_module(source_manager: Arc<dyn SourceManager>, source: &str) -> Box<Module> {
    let mut parser = Module::parser(Some(ModuleKind::Kernel));
    parser.parse_str(Some(Path::KERNEL), source, source_manager).unwrap()
}

macro_rules! build_test {
    ($source:expr) => {{
        miden_utils_testing::build_test!($source)
    }};
    ($source:expr, $($tail:tt)+) => {{
        miden_utils_testing::build_test!($source, $($tail)+)
    }};
}

macro_rules! build_test_by_mode {
    ($mode:expr, $source:expr) => {{
        miden_utils_testing::build_test_by_mode!($mode, $source)
    }};
    ($mode:expr, $source:expr, $($tail:tt)+) => {{
        miden_utils_testing::build_test_by_mode!($mode, $source, $($tail)+)
    }};
}

struct MalformedMastForestHost {
    source_manager: Arc<DefaultSourceManager>,
    mast_forest: Arc<MastForest>,
}

impl BaseHost for MalformedMastForestHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl SyncHost for MalformedMastForestHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        Some(LoadedMastForest::new(self.mast_forest.clone()))
    }

    fn on_event(&mut self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

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
  adv_push
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
        let dummy_library_source =
            source_file!(&test_context, "namespace foo::bar\n\npub proc foo add end");
        let module = test_context.parse_module(dummy_library_source).unwrap();
        let mut lib_2 = test_context
            .assemble_library("lib2", None, module, None::<Box<Module>>)
            .unwrap();
        lib_2.extend_advice_map(AdviceMap::from_iter([(Word::default(), vec![ZERO])]));
        let mut lib_1 = lib_2.clone();
        lib_1.name = "lib1".into();
        lib_1.extend_advice_map(AdviceMap::from_iter([(Word::default(), vec![ONE])]));

        (lib_1, lib_2)
    };

    let mut host = DefaultHost::default();
    host.load_library(lib_1.mast_forest()).unwrap();
    host.load_library(lib_2.mast_forest()).unwrap();

    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_diagnostic_lines!(
        err,
        "advice provider error at clock cycle",
        "x value for key 0x0000000000000000000000000000000000000000000000000000000000000000 already present in the advice map: previous values were '[0]', attempted replacement values were '[1]'"
    );
}

// AdviceMapKeyNotFound
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_advice_map_key_not_found_1() {
    let source = "
        begin
            swap swap adv.push_mapval
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "value for key 0x0100000000000000020000000000000000000000000000000000000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:23\]"#),
        " 2 |         begin",
        " 3 |             swap swap adv.push_mapval",
        "   :                       ^^^^^^^^^^^^^^^",
        "4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_advice_map_key_not_found_2() {
    let source = "
        begin
            swap swap adv.push_mapvaln
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "value for key 0x0100000000000000020000000000000000000000000000000000000000000000 not present in the advice map",
        regex!(r#",-\[test[\d]+:3:23\]"#),
        " 2 |         begin",
        " 3 |             swap swap adv.push_mapvaln",
        "   :                       ^^^^^^^^^^^^^^^^",
        "4 |         end",
        "   `----"
    );
}

// Host event diagnostics
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_host_event_error_uses_emit_location() {
    let event = EventName::new("test::host_event_error");
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "
        begin
            push.1 emit.event(\"{event}\")
        end"
    );
    let package = Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();
    let mut host = DefaultHost::default().with_source_manager(source_manager);
    host.register_handler(event.clone(), Arc::new(AlwaysFailEventHandler)).unwrap();

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .expect_err("expected error");
    #[rustfmt::skip]
    assert_diagnostic_lines!(
        err,
        format!("  x error during processing of event '{event}' (ID: {})", event.to_event_id()),
        "  `-> dummy host event failure",
        regex!(r#",-\[.*:3:20\]"#),
        " 2 |         begin",
      r#" 3 |             push.1 emit.event("test::host_event_error")"#,
        "   :                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_host_event_advice_error_uses_emit_location() {
    let event = EventName::new("test::host_event_advice_error");
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "
        begin
            push.1 emit.event(\"{event}\")
        end"
    );
    let package = Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();
    let mut host = DefaultHost::default().with_source_manager(source_manager);
    host.register_handler(event, Arc::new(DuplicateMapMutationHandler)).unwrap();

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_map([(Word::default(), vec![ZERO])]))
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .expect_err("expected error");
    #[rustfmt::skip]
    assert_diagnostic_lines!(
        err,
        "  x value for key 0x0000000000000000000000000000000000000000000000000000000000000000 already present in the advice map: previous values were '[0]', attempted replacement values were '[1]'",
        regex!(r#",-\[.*:3:20\]"#),
        " 2 |         begin",
      r#" 3 |             push.1 emit.event("test::host_event_advice_error")"#,
        "   :                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// AdviceStackReadFailed
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_advice_stack_read_failed() {
    let source = "
        begin
            swap adv_push
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x advice stack read failed",
        regex!(r#",-\[test[\d]+:3:18\]"#),
        " 2 |         begin",
        " 3 |             swap adv_push",
        "   :                  ^^^^^^^^",
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
            div
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x division by zero: divisor must be non-zero for division or modulo operations",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             div",
        "   :             ^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_divide_by_zero_2() {
    let source = "
        begin
            u32div
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x division by zero: divisor must be non-zero for division or modulo operations",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             u32div",
        "   :             ^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// ProcedureNotFound (dynexec/dyncall)
// ------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_procedure_not_found_dynexec() {
    let source = "
        begin
            dynexec
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x0000000000000000000000000000000000000000000000000000000000000000 could not be found",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             dynexec",
        "   :             ^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_procedure_not_found_dyncall() {
    let source = "
        begin
            dyncall
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x0000000000000000000000000000000000000000000000000000000000000000 could not be found",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             dyncall",
        "   :             ^^^^^^^",
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
    let (_, _, debug_info) = build_test.compile().expect("test source should compile");
    let debug_info = debug_info.expect("debug-mode assembly should emit package debug info");
    assert_eq!(
        debug_info
            .error_message(error_code_from_msg("some error message").as_canonical_u64())
            .as_deref(),
        Some("some error message")
    );
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x assertion failed with error message: some error message",
        regex!(r#",-\[test[\d]+:4:13\]"#),
        " 3 |             push.1.2",
        r#" 4 |             assertz.err="some error message""#,
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
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
        "  x assertion failed with error message: some error message",
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

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store.clone());
    let (_, _, debug_info) = build_test.compile().expect("test source should compile");
    let debug_info = debug_info.expect("debug-mode assembly should emit package debug info");
    assert_eq!(
        debug_info
            .error_message(error_code_from_msg("some error message").as_canonical_u64())
            .as_deref(),
        Some("some error message")
    );
    let err = build_test.execute().expect_err("expected error");
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

    // With a node-first stack, the advice lookup succeeds and Merkle verification fails.
    let stack_inputs = [
        leaves[index][0].as_canonical_u64(),
        leaves[index][1].as_canonical_u64(),
        leaves[index][2].as_canonical_u64(),
        leaves[index][3].as_canonical_u64(),
        tree.depth() as u64,
        // Intentionally choose the wrong index to trigger Merkle path verification failure.
        (index + 1) as u64,
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
    ];

    let build_test = build_test_by_mode!(true, source, &stack_inputs, &[], store);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "merkle path verification failed",
        "error message: some error message",
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
    let source = "
        proc foo
            push.1
        end

        begin
            call.foo
        end";

    let build_test = build_test_by_mode!(true, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x when returning from a call, stack depth must be 16, but was 17",
        regex!(r#",-\[test[\d]+:7:13\]"#),
        " 6 |         begin",
        " 7 |             call.foo",
        "   :             ^^^^^^^^",
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
            ilog2
        end";

    let build_test = build_test_by_mode!(true, source, &[]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x ilog2 requires a non-zero argument",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             ilog2",
        "   :             ^^^^^",
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
        "word access at memory address 3 in context 0 is unaligned: word accesses require addresses that are multiples of 4",
        regex!(r#",-\[test[\d]+:4:22\]"#),
        " 3 |         begin",
        " 4 |             exec.foo mem_storew_be.3",
        "   :                      ^^^^^^^^^^^^^^^",
        " 5 |         end",
        "   `----"
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
        "word access at memory address 3 in context 0 is unaligned: word accesses require addresses that are multiples of 4",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             mem_loadw_be.3",
        "   :             ^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
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

// ProcedureNotFound (external node resolution)
// -------------------------------------------------------------------------------------------------

#[test]
fn test_diagnostic_procedure_not_found_call() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        parse_library_module(source_manager.clone(), module_name, src)
    };

    let program_source = "
        use foo::bar

        begin
            call.bar::dummy_proc
        end
    ";

    let library = Assembler::new(source_manager.clone())
        .assemble_library("lib", lib_module, None::<Box<Module>>)
        .unwrap();

    let package = Assembler::new(source_manager.clone())
        .with_package(library.into(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", program_source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .unwrap_err();
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x6c0c95a9f04e21fe073801b42748ef0639eebd0467afd64c3d317b537451454d could not be found",
        regex!(r#",-\[.*:5:13\]"#),
        " 4 |         begin",
        " 5 |             call.bar::dummy_proc",
        "   :             ^^^^^^^^^^^^^^^^^^^^",
        " 6 |         end",
        "   `----"
    );
}

#[test]
fn test_diagnostic_procedure_not_found_join() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        parse_library_module(source_manager.clone(), module_name, src)
    };

    let program_source = "
        use foo::bar

        begin
            exec.bar::dummy_proc
            call.bar::dummy_proc
        end
    ";

    let library = Assembler::new(source_manager.clone())
        .assemble_library("library", lib_module, None::<Box<Module>>)
        .unwrap();

    let package = Assembler::new(source_manager.clone())
        .with_package(library.into(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", program_source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .unwrap_err();
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x6c0c95a9f04e21fe073801b42748ef0639eebd0467afd64c3d317b537451454d could not be found",
        regex!(r#",-\[.*:4:9\]"#),
        " 3 |",
        " 4 | ,->         begin",
        " 5 | |               exec.bar::dummy_proc",
        " 6 | |               call.bar::dummy_proc",
        " 7 | `->         end",
        " 8 |",
        "   `----"
    );
}

#[test]
fn test_diagnostic_procedure_not_found_loop() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        parse_library_module(source_manager.clone(), module_name, src)
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

    let library = Assembler::new(source_manager.clone())
        .assemble_library("library", lib_module, None::<Box<Module>>)
        .unwrap();

    let package = Assembler::new(source_manager.clone())
        .with_package(library.into(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", program_source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .unwrap_err();
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x6c0c95a9f04e21fe073801b42748ef0639eebd0467afd64c3d317b537451454d could not be found",
        regex!(r#",-\[.*:6:13\]"#),
        "  5 |                 push.1",
        "  6 | ,->             while.true",
        "  7 | |                   exec.bar::dummy_proc",
        "  8 | `->             end",
        "  9 |             end",
        "    `----"
    );
}

#[test]
fn test_diagnostic_procedure_not_found_split() {
    let source_manager = Arc::new(DefaultSourceManager::default());

    let lib_module = {
        let module_name = "foo::bar";
        let src = "
        pub proc dummy_proc
            push.1
        end
    ";
        parse_library_module(source_manager.clone(), module_name, src)
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

    let library = Assembler::new(source_manager.clone())
        .assemble_library("library", lib_module, None::<Box<Module>>)
        .unwrap();

    let package = Assembler::new(source_manager.clone())
        .with_package(library.into(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", program_source)
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .unwrap_err();
    assert_diagnostic_lines!(
        err,
        "procedure with root digest 0x6c0c95a9f04e21fe073801b42748ef0639eebd0467afd64c3d317b537451454d could not be found",
        regex!(r#",-\[.*:6:13\]"#),
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

#[test]
fn test_diagnostic_malformed_mast_forest_in_host() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager.clone())
        .assemble_program(
            "program",
            "
            begin
                dyncall
            end",
        )
        .unwrap();
    let debug_info = package.debug_info().unwrap().unwrap();
    let program = package.unwrap_program();

    let mut malformed_forest = MastForest::new();
    let unexpected_root = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut malformed_forest)
        .unwrap();
    malformed_forest.make_root(unexpected_root);

    let mut host = MalformedMastForestHost {
        source_manager,
        mast_forest: malformed_forest.into(),
    };

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor
        .execute_with_package_debug_info_sync(&program, &debug_info, &mut host)
        .unwrap_err();

    assert_diagnostic_lines!(
        err,
        "  x MAST forest in host indexed by procedure root 0x0000000000000000000000000000000000000000000000000000000000000000 doesn't contain that root",
        regex!(r#",-\[.*:3:17\]"#),
        " 2 |             begin",
        " 3 |                 dyncall",
        "   :                 ^^^^^^^",
        " 4 |             end",
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
    // The entry-check error originates from the SPLIT that the assembler wraps around the LOOP
    // when desugaring `while.true`, so the message reads "if statement". The source pointer is
    // still the `while.true` token because the SPLIT carries that asm_op. The iteration-check
    // (REPEAT/END) still produces a loop-context `NotBinaryValue` error — see
    // masm_errors_consistency case_2 for that path.
    assert_diagnostic_lines!(
        err,
        "  x if statement expected a binary value on top of the stack, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             while.true swap dup end",
        "   :             ^^^^^^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
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
            and
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             and",
        "   :             ^^^",
        " 4 |         end",
        "   `----"
    );

    // or
    let source = "
        begin
            or
        end";

    let build_test = build_test_by_mode!(true, source, &[2]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected a binary value, but got 2",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             or",
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
            u32and
        end";

    let big_value = u32::MAX as u64 + 1_u64;
    let build_test = build_test_by_mode!(true, source, &[big_value]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected u32 values, but got values: [4294967296]",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             u32and",
        "   :             ^^^^^^",
        " 4 |         end",
        "   `----"
    );

    // u32madd
    let source = "
        begin
            u32overflowing_add3
        end";

    let big_value = u32::MAX as u64 + 1_u64;
    let build_test = build_test_by_mode!(true, source, &[big_value]);
    let err = build_test.execute().expect_err("expected error");
    assert_diagnostic_lines!(
        err,
        "  x operation expected u32 values, but got values: [4294967296]",
        regex!(r#",-\[test[\d]+:3:13\]"#),
        " 2 |         begin",
        " 3 |             u32overflowing_add3",
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

    let kernel = parse_kernel_module(source_manager.clone(), kernel_source);
    let kernel_library = Assembler::new(source_manager.clone())
        .assemble_kernel("kernel", kernel, None)
        .unwrap();

    let program = {
        let package = Assembler::with_kernel(source_manager.clone(), kernel_library.into())
            .unwrap()
            .assemble_program("program", program_source)
            .unwrap();
        let debug_info = package.debug_info().unwrap().unwrap();
        let program = package.unwrap_program();

        // Note: we do not provide the kernel to trigger the error
        (
            Program::with_kernel(
                program.mast_forest().clone(),
                program.entrypoint(),
                Kernel::default(),
            ),
            debug_info,
        )
    };

    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default())
        .expect("advice inputs should fit advice map limits");
    let err = processor
        .execute_with_package_debug_info_sync(&program.0, &program.1, &mut host)
        .unwrap_err();
    assert_diagnostic_lines!(
        err,
        "syscall failed: procedure with root 0xcf69b6e65f586c6957de45a4a4188a9582251aca77a7d441cd040bfbcdfb192a was not found in the kernel",
        regex!(r#",-\[.*:3:13\]"#),
        " 2 |         begin",
        " 3 |             syscall.dummy_proc",
        "   :             ^^^^^^^^^^^^^^^^^^",
        " 4 |         end",
        "   `----"
    );
}

// Tests that assertion messages are not recovered without package debug info.
#[test]
fn test_assert_message_without_debug_info_reports_error_code() {
    let source = "
        const NONZERO = \"Value is not zero\"
        begin
            push.1
            assertz.err=NONZERO
        end";

    let build_test = build_test_by_mode!(false, source, &[1, 2]);
    let err = build_test.execute().expect_err("expected error");

    assert_diagnostic_lines!(
        err,
        format!(
            "  x assertion failed with error code: {}",
            error_code_from_msg("Value is not zero")
        )
    );

    let diagnostic = format!(
        "{}",
        miden_assembly::diagnostics::reporting::PrintDiagnostic::new_without_color(&err)
    );
    assert!(
        !diagnostic.contains("assertion failed with error message: Value is not zero"),
        "non-debug execution should not recover package debug assertion messages:\n{diagnostic}"
    );
}

/// Verifies assembly instruction cycle fixtures referenced by user docs.
#[test]
fn user_doc_assembly_cycle_fixtures_match_documentation() {
    for case in load_assembly_cycle_fixtures() {
        let measured = measure_program_cycles(&case.program, case.stack_inputs.as_deref());
        let baseline = case
            .baseline_program
            .as_deref()
            .map(|program| measure_program_cycles(program, case.stack_inputs.as_deref()))
            .unwrap_or(0);
        let delta = measured.saturating_sub(baseline);
        assert_eq!(
            delta, case.expected_cycles,
            "fixture {}: program should measure {} cycles (measured {measured}, baseline {baseline})",
            case.id, case.expected_cycles,
        );
    }
}

struct AssemblyCycleFixture {
    id: String,
    program: String,
    baseline_program: Option<String>,
    stack_inputs: Option<Vec<u64>>,
    expected_cycles: u8,
}

fn load_assembly_cycle_fixtures() -> Vec<AssemblyCycleFixture> {
    const FIXTURES: &str = include_str!("../../../scripts/assembly-cycle-fixtures.toml");

    let table: toml::Table =
        FIXTURES.parse().expect("assembly cycle fixtures should be valid TOML");
    let cases = table
        .get("case")
        .and_then(toml::Value::as_array)
        .expect("assembly-cycle-fixtures.toml should contain a [[case]] array");

    cases
        .iter()
        .map(|case| {
            let case = case.as_table().expect("each [[case]] entry should be a table");
            let expected = case
                .get("expected")
                .and_then(toml::Value::as_str)
                .expect("fixture should declare expected cycle text");
            let expected_cycles = expected
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("could not parse cycle count from {expected:?}"));

            AssemblyCycleFixture {
                id: case.get("id").and_then(toml::Value::as_str).expect("id").to_string(),
                program: case
                    .get("program")
                    .and_then(toml::Value::as_str)
                    .expect("program")
                    .to_string(),
                baseline_program: case
                    .get("baseline_program")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                stack_inputs: case.get("stack_inputs").and_then(|value| {
                    value.as_array().map(|items| {
                        items
                            .iter()
                            .map(|item| {
                                item.as_integer().expect("stack input should be an integer") as u64
                            })
                            .collect()
                    })
                }),
                expected_cycles,
            }
        })
        .collect()
}

fn measure_program_cycles(program: &str, stack_inputs: Option<&[u64]>) -> u8 {
    use miden_utils_testing::Test;

    const TRUNCATE_STACK: &str = r"@locals(4)
proc truncate_stack
    loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end
";

    let source = if program.contains("proc truncate_stack") {
        program.to_string()
    } else {
        format!("{TRUNCATE_STACK}{program}")
    };

    let mut test = Test::new("program", &source, false);
    if let Some(stack_inputs) = stack_inputs {
        test = test.with_stack_inputs(stack_inputs);
    }

    let outputs = test.get_last_stack_state();
    let measured = outputs
        .iter()
        .next()
        .expect("program should leave a cycle delta on the stack")
        .as_canonical_u64();
    u8::try_from(measured).expect("measured cycle count should fit in u8")
}
