use alloc::{format, string::ToString, sync::Arc, vec};
use core::{assert_matches, str::FromStr};

use miden_air::trace::MIN_TRACE_LEN;
use miden_assembly::{
    Assembler, DefaultSourceManager, Linkage, Path,
    ast::{Module, ModuleKind, QualifiedProcedureName},
};
use miden_core::{
    ONE, Word,
    events::SystemEvent,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
        MastForestContributor, MastNodeExt, SplitNodeBuilder,
    },
    operations::Operation,
    program::StackInputs,
    serde::{Deserializable, Serializable},
    testing::precompile::Hash,
};
use miden_debug_types::{
    ByteIndex, Location, SourceContent, SourceFile, SourceLanguage, SourceManager, SourceSpan, Uri,
};
use miden_mast_package::{
    Package, PackageExport, PackageId, ProcedureExport, Section, SectionId, TargetType, Version,
    debug_info::{
        DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceNode,
        DebugSourceNodeId, PackageDebugInfo,
    },
};
use miden_utils_testing::{build_test, stack_inputs_from_ints};
use rstest::rstest;

use super::*;
use crate::{
    AdviceInputs, BaseHost, DefaultHost, LoadedMastForest, ProcessorState, SyncHost,
    advice::AdviceMutation,
    event::EventError,
    operation::OperationError,
    processor::{StackInterface, SystemInterface},
};

mod advice_provider;
mod all_ops;
mod masm_consistency;
mod memory;

fn parse_kernel_source(source_manager: Arc<dyn SourceManager>, source: &str) -> Box<Module> {
    let mut parser = Module::parser(Some(ModuleKind::Kernel));
    parser.parse_str(Some(Path::KERNEL), source, source_manager).unwrap()
}

#[test]
fn stack_get_word_out_of_bounds_read() {
    // This event reads a word whose last felt is at index 16, which we will set to be out of bounds
    // in the stack buffer.
    const SYS_HQWORD_TO_MAP_EVENT_ID: u64 = SystemEvent::HqwordToMap.event_id().as_u64();

    let program_source = format!(
        "
    begin
        repeat.{} drop end

        push.{SYS_HQWORD_TO_MAP_EVENT_ID}
        swap
        drop

        emit
    end
    ",
        INITIAL_STACK_TOP_IDX - MIN_STACK_DEPTH
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program("program", &program_source)
        .expect("program should assemble")
        .unwrap_program();

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::default());

    // Should not panic
    processor.execute_sync(&program, &mut host).unwrap();
}

#[test]
fn with_options_preserves_installed_deferred_precompiles() {
    let options = ExecutionOptions::default().with_max_deferred_elements(128);
    let processor = FastProcessor::new(StackInputs::default())
        .with_deferred_precompiles(PrecompileRegistry::default().with_precompile(Hash))
        .expect("hash precompile should install")
        .with_options(options)
        .expect("options should preserve deferred precompile registry");

    assert!(processor.deferred_state().decode(Hash::digest_tag()).is_ok());
}

#[test]
fn stack_get_safe_boundary() {
    let inputs = stack_inputs_from_ints(1..=16_u64);
    let processor = FastProcessor::new(inputs);

    // idx == stack_top_idx: out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX), ZERO);

    // idx == stack_top_idx - 1: below the stack (buffer index 0 is zeroed), should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX - 1), ZERO);

    // idx == stack_top_idx + 1: out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(INITIAL_STACK_TOP_IDX + 1), ZERO);

    // idx == usize::MAX: far out of bounds, should return ZERO.
    assert_eq!(processor.stack_get_safe(usize::MAX), ZERO);
}

#[test]
fn stack_get_word_safe_partial_read() {
    let inputs = stack_inputs_from_ints(1..=16_u64);
    let processor = FastProcessor::new(inputs);

    // The stack has 16 elements (indices 0..=15). Reading a word at start_idx=15 means we want
    // elements at indices 15, 16, 17, 18. Only index 15 is valid; the rest should be ZERO.
    let word = processor.stack_get_word_safe(15);
    // Index 15 is the bottom of the stack (value 16, since inputs are in stack order: top first).
    assert_eq!(word, [Felt::new_unchecked(16), ZERO, ZERO, ZERO].into());
}

#[test]
fn stack_get_word_safe_usize_max() {
    let processor = FastProcessor::new(StackInputs::default());
    let word = processor.stack_get_word_safe(usize::MAX);
    assert_eq!(word, Word::default());
}

/// Ensures that the stack is correctly reset in the buffer when the stack is reset in the buffer
/// as a result of underflow.
///
/// Also checks that 0s are correctly pulled from the stack overflow table when it's empty.
#[test]
fn test_reset_stack_in_buffer_from_drop() {
    let asm = format!(
        "
    begin
        repeat.{}
            movup.15 assertz
        end
    end
    ",
        INITIAL_STACK_TOP_IDX * 5
    );

    let initial_stack: [u64; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let final_stack: Vec<u64> = initial_stack.to_vec();

    let test = build_test!(asm, &initial_stack);
    test.expect_stack(&final_stack);
}

/// Similar to `test_reset_stack_in_buffer_from_drop`, but here we test that the stack is correctly
/// reset in the buffer when the stack is reset in the buffer as a result of an execution context
/// being restored (and the overflow table restored back in the stack buffer).
#[test]
fn test_reset_stack_in_buffer_from_restore_context() {
    /// Number of values pushed onto the stack initially.
    const NUM_INITIAL_PUSHES: usize = INITIAL_STACK_TOP_IDX * 2;
    /// This moves the stack in the stack buffer to the left, close enough to the edge that when we
    /// restore the context, we will have to copy the overflow table values back into the stack
    /// buffer.
    const NUM_DROPS_IN_NEW_CONTEXT: usize = NUM_INITIAL_PUSHES + (INITIAL_STACK_TOP_IDX / 2);
    /// The called function will have dropped all 16 of the pushed values, so when we return to
    /// the caller, we expect the overflow table to contain all the original values, except for
    /// the 16 that were dropped by the callee.
    const NUM_EXPECTED_VALUES_IN_OVERFLOW: usize = NUM_INITIAL_PUSHES - MIN_STACK_DEPTH;

    let asm = format!(
        "
        proc fn_in_new_context
            repeat.{NUM_DROPS_IN_NEW_CONTEXT} drop end
        end

    begin
        # Create a big overflow table
        repeat.{NUM_INITIAL_PUSHES} push.42 end

        # Call a proc to create a new execution context
        call.fn_in_new_context

        # Drop the stack top coming back from the called proc; these should all
        # be 0s pulled from the overflow table
        repeat.{MIN_STACK_DEPTH} drop end

        # Make sure that the rest of the pushed values were properly restored
        repeat.{NUM_EXPECTED_VALUES_IN_OVERFLOW} push.42 assert_eq end
    end
    "
    );

    let initial_stack: [u64; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let final_stack: Vec<u64> = initial_stack.to_vec();

    let test = build_test!(asm, &initial_stack);
    test.expect_stack(&final_stack);
}

/// Tests that a syscall fails when the syscall target is not in the kernel.
#[test]
fn test_syscall_fail() {
    let mut host = DefaultHost::default();

    // set the initial FMP to a value close to FMP_MAX
    let stack_inputs = StackInputs::new(&[Felt::from_u32(5)]).unwrap();
    let program = {
        let mut program = MastForest::new();
        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut program)
            .unwrap();
        let root_id = CallNodeBuilder::new_syscall(basic_block_id)
            .add_to_forest(&mut program)
            .unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    let processor = FastProcessor::new(stack_inputs);

    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    // Check that the error is due to the syscall target not being in the kernel
    assert_matches!(
        err,
        ExecutionError::OperationError {
            err: OperationError::SyscallTargetNotInKernel { .. },
            ..
        }
    );
}

#[test]
fn untrusted_debug_stripped_child_bearing_package_executes_without_debug_info() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program(
            "program",
            "
        proc add_one
            push.1 add
        end

        begin
            dup.0 eq.3
            if.true
                call.add_one
            else
                push.2 mul
            end
        end
        ",
        )
        .expect("program should assemble");

    assert!(package.debug_info().unwrap().is_some());

    let package = Package::read_from_bytes(&package.to_bytes()).unwrap();
    assert!(package.debug_info().unwrap().is_none());

    let program = package.unwrap_program();
    let output = FastProcessor::new(StackInputs::new(&[Felt::new_unchecked(3)]).unwrap())
        .execute_sync(&program, &mut DefaultHost::default())
        .unwrap();

    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(4)));
}

#[test]
fn host_loaded_package_debug_info_reports_loaded_source_span() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, loaded_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (program, caller_debug_info) = external_program_for_digest(target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(loaded_source_file.id(), 0u32..11)
            && actual_source_file.id() == loaded_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn host_loaded_package_debug_info_requires_source_aware_execution() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, loaded_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (program, _) = external_program_for_digest(target_digest);
    let mut plain_host = DefaultHost::default()
        .with_source_manager(source_manager.clone())
        .with_library(Arc::new(loaded_package.clone()))
        .expect("loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut plain_host)
        .unwrap_err();
    assert_matches!(
        err,
        ExecutionError::OperationError {
            source_file: None,
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::from_u32(9)
    );

    let caller_debug_info = PackageDebugInfo::default();
    let mut source_aware_host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");
    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut source_aware_host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(loaded_source_file.id(), 0u32..11)
            && actual_source_file.id() == loaded_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn host_loaded_package_debug_info_survives_missing_caller_entrypoint_root() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, loaded_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (program, _) = external_program_for_digest(target_digest);
    let caller_debug_info = PackageDebugInfo::default();
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(loaded_source_file.id(), 0u32..11)
            && actual_source_file.id() == loaded_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn host_loaded_package_debug_info_survives_step_execution() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, loaded_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (program, caller_debug_info) = external_program_for_digest(target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_by_step_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(loaded_source_file.id(), 0u32..11)
            && actual_source_file.id() == loaded_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn direct_step_with_package_debug_info_seeds_initial_resume_context() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, loaded_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (program, caller_debug_info) = external_program_for_digest(target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut resume_ctx = processor
        .get_initial_resume_context(&program)
        .expect("initial context should build");

    let err = loop {
        match processor.step_with_package_debug_info_sync(&mut host, resume_ctx, &caller_debug_info)
        {
            Ok(Some(next_resume_ctx)) => resume_ctx = next_resume_ctx,
            Ok(None) => panic!("program should fail before completing"),
            Err(err) => break err,
        }
    };

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(loaded_source_file.id(), 0u32..11)
            && actual_source_file.id() == loaded_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn host_loaded_stripped_package_executes_without_loaded_debug_info() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, _) =
        host_loaded_package_fixture(source_manager.clone(), vec![Operation::Add], true);
    let stripped_package =
        loaded_package.without_debug_info().expect("debug stripping should succeed");
    assert!(stripped_package.debug_info().unwrap().is_none());

    let (program, caller_debug_info) = external_program_for_digest(target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(stripped_package))
        .expect("stripped loaded package should register");

    let output =
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(6), Felt::from_u32(7)]).unwrap())
            .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
            .expect("stripped loaded package should execute without loaded debug info");

    assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(13)));
}

#[test]
fn host_loaded_stripped_package_restores_caller_debug_info() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (loaded_package, target_digest, _) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Pad, Operation::Drop],
        true,
    );
    let stripped_package =
        loaded_package.without_debug_info().expect("debug stripping should succeed");
    let (program, caller_debug_info, caller_source_file) =
        external_then_fail_program_for_digest(source_manager.clone(), target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(stripped_package))
        .expect("stripped loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(caller_source_file.id(), 12u32..23)
            && actual_source_file.id() == caller_source_file.id()
            && err_code == Felt::from_u32(11)
    );
}

#[test]
fn host_loaded_debug_info_survives_stripped_intermediate_package() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (leaf_package, leaf_digest, leaf_source_file) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        true,
    );
    let (forwarder_package, forwarder_digest) = host_loaded_forwarder_package(leaf_digest);
    assert!(forwarder_package.debug_info().unwrap().is_none());

    let (program, caller_debug_info) = external_program_for_digest(forwarder_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(forwarder_package))
        .expect("forwarder package should register")
        .with_library(Arc::new(leaf_package))
        .expect("leaf package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(leaf_source_file.id(), 0u32..11)
            && actual_source_file.id() == leaf_source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn host_loaded_ambiguous_debug_root_drops_precise_loaded_source_span() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let (mut loaded_package, target_digest, _) = host_loaded_package_fixture(
        source_manager.clone(),
        vec![Operation::Assert(Felt::from_u32(9))],
        false,
    );
    let root_id = loaded_package
        .mast_forest()
        .find_procedure_root(target_digest)
        .expect("root exists");
    let source_a = DebugSourceNodeId::from(0);
    let source_b = DebugSourceNodeId::from(1);
    loaded_package.sections = vec![Section::new(
        SectionId::DEBUG_SOURCE_GRAPH,
        DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, Vec::new(), 0, 1),
                DebugSourceNode::new(root_id, Vec::new(), 0, 1),
            ],
            vec![source_a, source_b],
        )
        .to_bytes(),
    )];

    let (program, caller_debug_info) = external_program_for_digest(target_digest);
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_library(Arc::new(loaded_package))
        .expect("loaded package should register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &caller_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            source_file: None,
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::from_u32(9)
    );
}

#[test]
fn package_source_debug_static_call_selects_identical_proc_from_called_file() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let root = source_manager.load(
        SourceLanguage::Masm,
        Uri::from("lib/root.masm"),
        r#"
        namespace lib

        pub mod a
        pub mod b
        "#
        .to_string(),
    );
    let a = source_manager.load(
        SourceLanguage::Masm,
        Uri::from("lib/a.masm"),
        r#"
        namespace lib::a

        pub proc same
            push.1 add
        end
        "#
        .to_string(),
    );
    let b = source_manager.load(
        SourceLanguage::Masm,
        Uri::from("lib/b.masm"),
        r#"
        namespace lib::b

        pub proc same
            push.1 add
        end
        "#
        .to_string(),
    );
    let lib = Assembler::new(source_manager.clone())
        .assemble_library("lib", root, [a, b])
        .map(Arc::<Package>::from)
        .expect("library should assemble");
    let lib_debug_info = lib
        .debug_info()
        .expect("library debug info should decode")
        .expect("library should contain debug info");
    let mut same_digest_roots = lib_debug_info
        .source_graph()
        .expect("library should have a source graph")
        .roots()
        .iter()
        .map(|root| lib_debug_info.source_node(*root).unwrap().exec_node)
        .collect::<Vec<_>>();
    same_digest_roots.sort_unstable();
    same_digest_roots.dedup();
    assert_eq!(
        same_digest_roots.len(),
        1,
        "the two library exports should reduce to the same executable node",
    );

    let main = source_manager.load(
        SourceLanguage::Masm,
        Uri::from("main.masm"),
        r#"
        use lib::b

        begin
            call.b::same
        end
        "#
        .to_string(),
    );
    let package = Assembler::new(source_manager)
        .with_package(lib, Linkage::Static)
        .expect("library should link statically")
        .assemble_program("program", main)
        .expect("program should assemble");
    let package_debug_info = package
        .debug_info()
        .expect("program debug info should decode")
        .expect("program should contain debug info");
    let source_map = package_debug_info.source_map().expect("program should have a source map");
    let selected_row_found = source_map.asm_ops().iter().any(|row| {
        row.location
            .as_ref()
            .is_some_and(|location| location.uri().as_str() == "lib/b.masm")
    });

    assert!(selected_row_found, "the selected call should keep lib/b.masm metadata");
    assert!(
        !source_map.asm_ops().iter().any(|row| {
            row.location
                .as_ref()
                .is_some_and(|location| location.uri().as_str() == "lib/a.masm")
        }),
        "the uncalled identical procedure should not leak into the executable source map",
    );

    let program = package.unwrap_program();
    let output = FastProcessor::new(StackInputs::new(&[Felt::new_unchecked(41)]).unwrap())
        .execute_with_package_debug_info_sync(
            &program,
            &package_debug_info,
            &mut DefaultHost::default(),
        )
        .expect("duplicate executable roots should not make source-aware execution fail");

    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(42)));
}

#[test]
fn package_source_debug_execution_distinguishes_same_exec_node_split_children() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(7))])
        .add_to_forest(&mut forest)
        .unwrap();
    let root_id = SplitNodeBuilder::new([block_id, block_id]).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let program = Program::new(forest.into(), root_id);

    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/same-node.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "true;\nfalse;\n"),
    );
    let mut host = DefaultHost::default().with_source_manager(source_manager);

    let source_root = DebugSourceNodeId::from(0);
    let source_true = DebugSourceNodeId::from(1);
    let source_false = DebugSourceNodeId::from(2);
    let package_debug_info = PackageDebugInfo::with_source_debug(
        DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, vec![source_true, source_false], 0, 1),
                DebugSourceNode::new(block_id, vec![], 0, 1),
                DebugSourceNode::new(block_id, vec![], 0, 1),
            ],
            vec![source_root],
        ),
        DebugSourceMapSection::from_parts(
            vec![
                DebugSourceAsmOp::new(
                    source_true,
                    0,
                    Some(Location::new(uri.clone(), ByteIndex::new(0), ByteIndex::new(5))),
                    "true_branch".into(),
                    "assert".into(),
                    1,
                ),
                DebugSourceAsmOp::new(
                    source_false,
                    0,
                    Some(Location::new(uri, ByteIndex::new(6), ByteIndex::new(12))),
                    "false_branch".into(),
                    "assert".into(),
                    2,
                ),
            ],
            Vec::new(),
        ),
    );

    let processor = FastProcessor::new(StackInputs::default());
    let err = processor
        .execute_with_package_debug_info_sync(&program, &package_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(source_file.id(), 6u32..12)
            && actual_source_file.id() == source_file.id()
            && err_code == Felt::from_u32(7)
    );
}

#[test]
fn package_source_debug_execution_uses_manifest_entrypoint_source_node() {
    let fixture =
        same_digest_entrypoint_fixture(vec![Operation::Assert(Felt::from_u32(9))], "assert");
    assert!(
        fixture
            .debug_info
            .unique_source_root_for_exec_node(fixture.program.entrypoint())
            .is_err(),
        "debug info alone cannot pick the manifest-selected same-digest entrypoint"
    );

    let mut host = DefaultHost::default().with_source_manager(fixture.source_manager);
    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_at_source_node_sync(
            &fixture.program,
            &fixture.debug_info,
            fixture.entrypoint_source_node_id,
            &mut host,
        )
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::FailedAssertion { err_code, .. },
        } if label == SourceSpan::new(fixture.source_file.id(), 9u32..17)
            && actual_source_file.id() == fixture.source_file.id()
            && err_code == Felt::from_u32(9)
    );
}

#[test]
fn package_source_debug_trace_and_step_use_manifest_entrypoint_source_node() {
    let fixture = same_digest_entrypoint_fixture(vec![Operation::Add], "add");
    assert!(
        fixture
            .debug_info
            .unique_source_root_for_exec_node(fixture.program.entrypoint())
            .is_err(),
        "debug info alone cannot pick the manifest-selected same-digest entrypoint"
    );

    let mut trace_host = DefaultHost::default();
    let trace_inputs =
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(3), Felt::from_u32(4)]).unwrap())
            .execute_trace_inputs_with_package_debug_info_at_source_node_sync(
                &fixture.program,
                &fixture.debug_info,
                fixture.entrypoint_source_node_id,
                &mut trace_host,
            )
            .unwrap();
    assert_eq!(trace_inputs.stack_outputs().get_element(0), Some(Felt::from_u32(7)));

    let mut step_host = DefaultHost::default();
    let stack_outputs =
        FastProcessor::new(StackInputs::new(&[Felt::from_u32(3), Felt::from_u32(4)]).unwrap())
            .execute_by_step_with_package_debug_info_at_source_node_sync(
                &fixture.program,
                &fixture.debug_info,
                fixture.entrypoint_source_node_id,
                &mut step_host,
            )
            .unwrap();
    assert_eq!(stack_outputs.get_element(0), Some(Felt::from_u32(7)));
}

#[test]
fn package_source_debug_execution_degrades_ambiguous_local_dyn_root() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program(
            "program",
            "
        proc foo
            push.7 swap drop
        end

        begin
            procref.foo mem_storew_le.100 dropw push.100
            dynexec
        end
        ",
        )
        .expect("program should assemble")
        .unwrap_program();

    let entrypoint = program.entrypoint();
    let callee_root = program
        .mast_forest()
        .procedure_roots()
        .iter()
        .copied()
        .find(|&root| root != entrypoint)
        .expect("program should contain a callee procedure root");

    let source_entry = DebugSourceNodeId::from(0);
    let source_callee_a = DebugSourceNodeId::from(1);
    let source_callee_b = DebugSourceNodeId::from(2);
    let package_debug_info =
        PackageDebugInfo::default().with_source_graph(DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(entrypoint, vec![], 0, 1),
                DebugSourceNode::new(callee_root, vec![], 0, 1),
                DebugSourceNode::new(callee_root, vec![], 0, 1),
            ],
            vec![source_entry, source_callee_a, source_callee_b],
        ));

    let processor = FastProcessor::new(StackInputs::default());
    let output = processor
        .execute_with_package_debug_info_sync(
            &program,
            &package_debug_info,
            &mut DefaultHost::default(),
        )
        .unwrap();

    assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(7)));
}

fn absolute_path(name: &str) -> Arc<Path> {
    Arc::from(Path::validate(&format!("::{name}")).unwrap())
}

fn host_loaded_package_fixture(
    source_manager: Arc<DefaultSourceManager>,
    operations: Vec<Operation>,
    include_debug_info: bool,
) -> (Package, Word, Arc<SourceFile>) {
    let mut forest = MastForest::new();
    let op_end = operations.len() as u32;
    let root_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let target_digest = forest[root_id].digest();

    let export_path = absolute_path("loaded::target");
    let export = PackageExport::Procedure(
        ProcedureExport::new(export_path, Some(root_id), target_digest, None)
            .with_source_node(Some(DebugSourceNodeId::from(0))),
    );
    let mut package = Package::create(
        PackageId::from("loaded"),
        Version::new(1, 0, 0),
        TargetType::Library,
        Arc::new(forest),
        [export],
        None,
    )
    .unwrap();

    let uri = Uri::new("file://loaded/target.masm");
    let source_file = source_manager
        .load_from_raw_parts(uri.clone(), SourceContent::new("masm", uri.clone(), "assert.fail"));

    if include_debug_info {
        let source_node_id = DebugSourceNodeId::from(0);
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![DebugSourceNode::new(root_id, Vec::new(), 0, op_end)],
            vec![source_node_id],
        );
        let source_map = DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(
                source_node_id,
                0,
                Some(Location::new(uri, ByteIndex::new(0), ByteIndex::new(11))),
                "loaded::target".into(),
                "assert.fail".into(),
                1,
            )],
            Vec::new(),
        );
        package.sections = vec![
            Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()),
            Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()),
        ];
        assert!(package.debug_info().unwrap().is_some());
    }

    (package, target_digest, source_file)
}

fn host_loaded_forwarder_package(target_digest: Word) -> (Package, Word) {
    let mut forest = MastForest::new();
    let root_id = ExternalNodeBuilder::new(target_digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let forwarder_digest = forest[root_id].digest();

    let export_path = absolute_path("forwarder::target");
    let export = PackageExport::Procedure(ProcedureExport::new(
        export_path,
        Some(root_id),
        forwarder_digest,
        None,
    ));
    let package = Package::create(
        PackageId::from("forwarder"),
        Version::new(1, 0, 0),
        TargetType::Library,
        Arc::new(forest),
        [export],
        None,
    )
    .unwrap();

    (package, forwarder_digest)
}

fn external_program_for_digest(target_digest: Word) -> (Program, PackageDebugInfo) {
    let mut forest = MastForest::new();
    let external_id = ExternalNodeBuilder::new(target_digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(external_id);
    let program = Program::new(forest.into(), external_id);
    let source_node_id = DebugSourceNodeId::from(0);
    let package_debug_info =
        PackageDebugInfo::default().with_source_graph(DebugSourceGraphSection::from_parts(
            vec![DebugSourceNode::new(external_id, Vec::new(), 0, 1)],
            vec![source_node_id],
        ));
    (program, package_debug_info)
}

fn external_then_fail_program_for_digest(
    source_manager: Arc<DefaultSourceManager>,
    target_digest: Word,
) -> (Program, PackageDebugInfo, Arc<SourceFile>) {
    let mut forest = MastForest::new();
    let external_id = ExternalNodeBuilder::new(target_digest).add_to_forest(&mut forest).unwrap();
    let fail_id = BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(11))])
        .add_to_forest(&mut forest)
        .unwrap();
    let root_id = JoinNodeBuilder::new([external_id, fail_id]).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let program = Program::new(forest.into(), root_id);

    let uri = Uri::new("file://caller/main.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "exec.loaded\nassert.fail"),
    );

    let source_root = DebugSourceNodeId::from(0);
    let source_external = DebugSourceNodeId::from(1);
    let source_fail = DebugSourceNodeId::from(2);
    let package_debug_info = PackageDebugInfo::with_source_debug(
        DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, vec![source_external, source_fail], 0, 1),
                DebugSourceNode::new(external_id, Vec::new(), 0, 1),
                DebugSourceNode::new(fail_id, Vec::new(), 0, 1),
            ],
            vec![source_root],
        ),
        DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(
                source_fail,
                0,
                Some(Location::new(uri, ByteIndex::new(12), ByteIndex::new(23))),
                "caller::main".into(),
                "assert.fail".into(),
                2,
            )],
            Vec::new(),
        ),
    );
    (program, package_debug_info, source_file)
}

struct SameDigestEntrypointFixture {
    program: Program,
    debug_info: PackageDebugInfo,
    entrypoint_source_node_id: DebugSourceNodeId,
    source_manager: Arc<DefaultSourceManager>,
    source_file: Arc<SourceFile>,
}

fn same_digest_entrypoint_fixture(
    operations: Vec<Operation>,
    op_name: &str,
) -> SameDigestEntrypointFixture {
    let mut forest = MastForest::new();
    let op_end = operations.len() as u32;
    let block_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);
    let digest = forest[block_id].digest();

    let source_alias_a = DebugSourceNodeId::from(0);
    let source_alias_b = DebugSourceNodeId::from(1);
    let exports = [("app::alias_a", source_alias_a), ("app::alias_b", source_alias_b)]
        .into_iter()
        .map(|(path, source_node_id)| {
            let path = absolute_path(path);
            PackageExport::Procedure(
                ProcedureExport::new(path, Some(block_id), digest, None)
                    .with_source_node(Some(source_node_id)),
            )
        });

    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/same-digest-entrypoint.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "alias_a;\nalias_b;\n"),
    );
    let source_graph = DebugSourceGraphSection::from_parts(
        vec![
            DebugSourceNode::new(block_id, vec![], 0, op_end),
            DebugSourceNode::new(block_id, vec![], 0, op_end),
        ],
        vec![source_alias_a, source_alias_b],
    );
    let source_map = DebugSourceMapSection::from_parts(
        vec![
            DebugSourceAsmOp::new(
                source_alias_a,
                0,
                Some(Location::new(uri.clone(), ByteIndex::new(0), ByteIndex::new(8))),
                "alias_a".into(),
                op_name.into(),
                1,
            ),
            DebugSourceAsmOp::new(
                source_alias_b,
                0,
                Some(Location::new(uri, ByteIndex::new(9), ByteIndex::new(17))),
                "alias_b".into(),
                op_name.into(),
                1,
            ),
        ],
        vec![],
    );

    let mut package = Package::create(
        PackageId::from("app"),
        Version::new(1, 0, 0),
        TargetType::Library,
        Arc::new(forest),
        exports,
        None,
    )
    .unwrap();
    package.sections = vec![
        Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()),
        Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()),
    ];
    let executable = package
        .make_executable(&QualifiedProcedureName::from_str("app::alias_b").unwrap())
        .unwrap();
    let entrypoint_source_node_id = executable
        .entrypoint_source_node()
        .expect("entrypoint source node should be present");
    assert_eq!(entrypoint_source_node_id, source_alias_b);

    SameDigestEntrypointFixture {
        program: executable.unwrap_program(),
        debug_info: executable.debug_info().unwrap().unwrap(),
        entrypoint_source_node_id,
        source_manager,
        source_file,
    }
}

fn missing_external_package_source_debug_fixture() -> (
    Program,
    PackageDebugInfo,
    DefaultHost,
    Arc<DefaultSourceManager>,
    SourceSpan,
    Arc<SourceFile>,
) {
    let mut forest = MastForest::new();
    let missing_digest = Word::from([ONE, ONE, ONE, ONE]);
    let external_id = ExternalNodeBuilder::new(missing_digest).add_to_forest(&mut forest).unwrap();
    let root_id = CallNodeBuilder::new(external_id).add_to_forest(&mut forest).unwrap();
    forest.make_root(root_id);
    let program = Program::new(forest.into(), root_id);

    let source_manager = Arc::new(DefaultSourceManager::default());
    let uri = Uri::new("file://pkg/missing-external.masm");
    let source_file = source_manager.load_from_raw_parts(
        uri.clone(),
        SourceContent::new("masm", uri.clone(), "begin\n    call.missing::proc\nend\n"),
    );
    let host = DefaultHost::default().with_source_manager(source_manager.clone());

    let source_root = DebugSourceNodeId::from(0);
    let source_external = DebugSourceNodeId::from(1);
    let expected_span = SourceSpan::new(source_file.id(), 10u32..28);
    let package_debug_info = PackageDebugInfo::with_source_debug(
        DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, vec![source_external], 0, 1),
                DebugSourceNode::new(external_id, vec![], 0, 1),
            ],
            vec![source_root],
        ),
        DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(
                source_external,
                0,
                Some(Location::new(uri, ByteIndex::new(10), ByteIndex::new(28))),
                "external_call".into(),
                "call.missing::proc".into(),
                2,
            )],
            Vec::new(),
        ),
    );

    (program, package_debug_info, host, source_manager, expected_span, source_file)
}

struct MalformedExternalHost {
    source_manager: Arc<DefaultSourceManager>,
    loaded_mast_forest: LoadedMastForest,
}

impl BaseHost for MalformedExternalHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let source_file = self.source_manager.get_by_uri(location.uri());
        let label = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (label, source_file)
    }
}

impl SyncHost for MalformedExternalHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        Some(self.loaded_mast_forest.clone())
    }

    fn on_event(&mut self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

#[test]
fn package_source_debug_missing_external_preserves_external_source_span() {
    let (program, package_debug_info, mut host, _, expected_span, source_file) =
        missing_external_package_source_debug_fixture();

    let err = FastProcessor::new(StackInputs::default())
        .execute_with_package_debug_info_sync(&program, &package_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::ProcedureNotFound {
            label,
            source_file: Some(actual_source_file),
            ..
        } if label == expected_span && actual_source_file.id() == source_file.id()
    );
}

#[test]
fn package_source_debug_malformed_external_preserves_external_source_span() {
    let (program, package_debug_info, _, source_manager, expected_span, source_file) =
        missing_external_package_source_debug_fixture();

    let mut wrong_forest = MastForest::new();
    let wrong_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut wrong_forest)
        .unwrap();
    wrong_forest.make_root(wrong_root);

    let mut host = MalformedExternalHost {
        source_manager,
        loaded_mast_forest: LoadedMastForest::new(Arc::new(wrong_forest)),
    };

    let err = FastProcessor::new(StackInputs::new(&[Felt::ONE, Felt::ONE]).unwrap())
        .execute_with_package_debug_info_sync(&program, &package_debug_info, &mut host)
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::MalformedMastForestInHost { .. },
        } if label == expected_span && actual_source_file.id() == source_file.id()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn package_source_debug_malformed_external_preserves_external_source_span_async() {
    let (program, package_debug_info, _, source_manager, expected_span, source_file) =
        missing_external_package_source_debug_fixture();

    let mut wrong_forest = MastForest::new();
    let wrong_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut wrong_forest)
        .unwrap();
    wrong_forest.make_root(wrong_root);

    let mut host = MalformedExternalHost {
        source_manager,
        loaded_mast_forest: LoadedMastForest::new(Arc::new(wrong_forest)),
    };

    let err = FastProcessor::new(StackInputs::new(&[Felt::ONE, Felt::ONE]).unwrap())
        .execute_with_package_debug_info(&program, &package_debug_info, &mut host)
        .await
        .unwrap_err();

    assert_matches!(
        err,
        ExecutionError::OperationError {
            label,
            source_file: Some(actual_source_file),
            err: OperationError::MalformedMastForestInHost { .. },
        } if label == expected_span && actual_source_file.id() == source_file.id()
    );
}

#[test]
fn test_stack_write_word_max_start_idx() {
    let stack_inputs = StackInputs::new(&[]).unwrap();
    let mut processor = FastProcessor::new(stack_inputs);

    let word =
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]);
    let start_idx = MIN_STACK_DEPTH - WORD_SIZE;

    processor.stack_write_word(start_idx, &word);

    assert_eq!(processor.stack_get_word(start_idx), word);
}

/// Tests that `ExecutionError::CycleLimitExceeded` is correctly emitted when a program exceeds the
/// number of allowed cycles.
#[test]
fn test_cycle_limit_exceeded() {
    let mut host = DefaultHost::default();

    let options = ExecutionOptions::new(
        Some(MIN_TRACE_LEN as u32),
        MIN_TRACE_LEN as u32,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .unwrap();

    // Note: when executing, the processor executes `SPAN`, `END` and `HALT` operations, and hence
    // the total number of operations is certain to be greater than `MIN_TRACE_LEN`.
    let program = simple_program_with_ops(vec![Operation::Swap; MIN_TRACE_LEN]);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_matches!(err, ExecutionError::CycleLimitExceeded(max_cycles) if max_cycles == MIN_TRACE_LEN as u32);
}

/// Tests that a program using exactly `max_cycles` cycles succeeds.
///
/// This is a regression test for the off-by-one error where the cycle limit check used `>=`
/// instead of `>`, causing programs that used exactly `max_cycles` cycles to fail.
#[test]
fn test_cycle_limit_exactly_max_cycles_succeeds() {
    let mut host = DefaultHost::default();

    // With 2018 Noop operations, the program uses exactly MIN_TRACE_LEN (2048) cycles.
    // 2018 operations result in 29 operation batches, and this requires executing 28 `RESPAN`
    // operations. So, we get 2018 + 28 = 2046. All of these operations are executed in a single
    // basic block, and we need 2 more operations for block start (`BEGIN`) and block end (`END`).
    // Before the fix (clk >= max_cycles): this failed because 2048 >= 2048 is true.
    // After the fix (clk > max_cycles): this succeeds because 2048 > 2048 is false.
    const NUM_OPS: usize = 2018;
    let program = simple_program_with_ops(vec![Operation::Noop; NUM_OPS]);

    let options = ExecutionOptions::new(
        Some(2048),
        MIN_TRACE_LEN as u32,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .unwrap();

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let result = processor.execute_sync(&program, &mut host);

    // The program should succeed since it uses exactly max_cycles cycles.
    assert!(
        result.is_ok(),
        "Program using exactly max_cycles should succeed, but got: {result:?}"
    );
}

#[test]
fn test_assert() {
    let mut host = DefaultHost::default();

    // Case 1: the stack top is ONE
    {
        let stack_inputs = StackInputs::new(&[ONE]).unwrap();
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(stack_inputs);
        let result = processor.execute_sync(&program, &mut host);

        // Check that the execution succeeds
        assert!(result.is_ok());
    }

    // Case 2: the stack top is not ONE
    {
        let stack_inputs = StackInputs::new(&[ZERO]).unwrap();
        let program = simple_program_with_ops(vec![Operation::Assert(ZERO)]);

        let processor = FastProcessor::new(stack_inputs);
        let err = processor.execute_sync(&program, &mut host).unwrap_err();

        // Check that the error is due to a failed assertion
        assert_matches!(
            err,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { .. },
                ..
            }
        );
    }
}

/// Tests all valid inputs for the `And` operation.
///
/// The `test_basic_block()` test already covers the case where the stack top doesn't contain binary
/// values.
#[rstest]
#[case(vec![ZERO, ZERO], ZERO)]
#[case(vec![ZERO, ONE], ZERO)]
#[case(vec![ONE, ZERO], ZERO)]
#[case(vec![ONE, ONE], ONE)]
fn test_valid_combinations_and(#[case] stack_inputs: Vec<Felt>, #[case] expected_output: Felt) {
    let program = simple_program_with_ops(vec![Operation::And]);

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    assert_eq!(stack_outputs.get_num_elements(1)[0], expected_output);
}

/// Tests all valid inputs for the `Or` operation.
///
/// The `test_basic_block()` test already covers the case where the stack top doesn't contain binary
/// values.
#[rstest]
#[case(vec![ZERO, ZERO], ZERO)]
#[case(vec![ZERO, ONE], ONE)]
#[case(vec![ONE, ZERO], ONE)]
#[case(vec![ONE, ONE], ONE)]
fn test_valid_combinations_or(#[case] stack_inputs: Vec<Felt>, #[case] expected_output: Felt) {
    let program = simple_program_with_ops(vec![Operation::Or]);

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let stack_outputs = processor.execute_sync(&program, &mut host).unwrap().stack;

    assert_eq!(stack_outputs.get_num_elements(1)[0], expected_output);
}

/// Tests a valid set of inputs for the `Frie2f4` operation. This test reuses most of the logic of
/// `op_fri_ext2fold4` in `Process`.
#[test]
fn test_frie2f4() {
    let mut host = DefaultHost::default();

    // --- build stack inputs ---------------------------------------------
    // FastProcessor::new expects inputs in natural order: first element goes to top.
    // After Push(42), the stack layout becomes:
    //   [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, p, poe, pe0, pe1, a0, a1, cptr, ...]
    //    ^0   1   2   3   4   5   6   7    8     9  10   11   12   13  14   15
    //
    // p is the bit-reversed tree index; the instruction computes d_seg = p & 3.
    // With p=38 (d_seg=2, f_pos=9), query_values[2] = (v4, v5) must equal prev_value = (pe0, pe1).
    let previous_value: [Felt; 2] = [Felt::from_u32(10), Felt::from_u32(11)];
    let stack_inputs = StackInputs::new(&[
        Felt::from_u32(16), // pos 0 -> pos 1 (v1) after push
        Felt::from_u32(15), // pos 1 -> pos 2 (v2) after push
        Felt::from_u32(14), // pos 2 -> pos 3 (v3) after push
        previous_value[0],  // pos 3 -> pos 4 (v4) after push: must match pe0
        previous_value[1],  // pos 4 -> pos 5 (v5) after push: must match pe1
        Felt::from_u32(11), // pos 5 -> pos 6 (v6) after push
        Felt::from_u32(10), // pos 6 -> pos 7 (v7) after push
        Felt::from_u32(9),  // pos 7 -> pos 8 (f_pos) after push
        Felt::from_u32(38), // pos 8 -> pos 9 (p=4*9+2=38, d_seg=2) after push
        Felt::from_u32(7),  // pos 9 -> pos 10 (poe) after push
        previous_value[0],  // pos 10 -> pos 11 (pe0) after push
        previous_value[1],  // pos 11 -> pos 12 (pe1) after push
        Felt::from_u32(2),  // pos 12 -> pos 13 (a0) after push
        Felt::from_u32(3),  // pos 13 -> pos 14 (a1) after push
        Felt::from_u32(1),  // pos 14 -> pos 15 (cptr) after push
        Felt::from_u32(0),  // pos 15 -> overflow after push
    ])
    .unwrap();

    let program = simple_program_with_ops(vec![
        Operation::Push(Felt::new_unchecked(42_u64)),
        Operation::FriE2F4,
    ]);

    // fast processor
    let fast_processor = FastProcessor::new(stack_inputs);
    let stack_outputs = fast_processor.execute_sync(&program, &mut host).unwrap().stack;

    insta::assert_debug_snapshot!(stack_outputs);
}

#[test]
fn test_call_node_preserves_stack_overflow_table() {
    let mut host = DefaultHost::default();

    // equivalent to:
    // proc foo
    //   add
    // end
    //
    // begin
    //   # stack: [1, 2, 3, 4, ..., 16]
    //   push.10 push.20
    //   # stack: [10, 20, 1, 2, ..., 15, 16], 15 and 16 on overflow
    //   call.foo
    //   # => stack: [30, 1, 2, 3, 4, 5, ..., 14, 0, 15, 16]
    //   swap drop swap drop
    //   # => stack: [30, 3, 4, 5, 6, ..., 14, 0, 15, 16]
    // end
    let program = {
        let mut program = MastForest::new();
        // foo proc
        let foo_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut program)
            .unwrap();

        // before call
        let push10_push20_id = BasicBlockNodeBuilder::new(vec![
            Operation::Push(Felt::from_u32(10)),
            Operation::Push(Felt::from_u32(20)),
        ])
        .add_to_forest(&mut program)
        .unwrap();

        // call
        let call_node_id = CallNodeBuilder::new(foo_id).add_to_forest(&mut program).unwrap();
        // after call
        let swap_drop_swap_drop = BasicBlockNodeBuilder::new(vec![
            Operation::Swap,
            Operation::Drop,
            Operation::Swap,
            Operation::Drop,
        ])
        .add_to_forest(&mut program)
        .unwrap();

        // joins
        let join_call_swap = JoinNodeBuilder::new([call_node_id, swap_drop_swap_drop])
            .add_to_forest(&mut program)
            .unwrap();
        let root_id = JoinNodeBuilder::new([push10_push20_id, join_call_swap])
            .add_to_forest(&mut program)
            .unwrap();

        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    // initial stack: (top) [1, 2, 3, 4, ..., 16] (bot)
    let mut processor = FastProcessor::new(
        StackInputs::new(&[
            Felt::from_u32(1),
            Felt::from_u32(2),
            Felt::from_u32(3),
            Felt::from_u32(4),
            Felt::from_u32(5),
            Felt::from_u32(6),
            Felt::from_u32(7),
            Felt::from_u32(8),
            Felt::from_u32(9),
            Felt::from_u32(10),
            Felt::from_u32(11),
            Felt::from_u32(12),
            Felt::from_u32(13),
            Felt::from_u32(14),
            Felt::from_u32(15),
            Felt::from_u32(16),
        ])
        .unwrap(),
    );

    // Execute the program
    let result = processor.execute_mut_sync(&program, &mut host).unwrap();

    assert_eq!(
        result.get_num_elements(16),
        &[
            // the sum from the call to foo
            Felt::from_u32(30),
            // rest of the stack
            Felt::from_u32(3),
            Felt::from_u32(4),
            Felt::from_u32(5),
            Felt::from_u32(6),
            Felt::from_u32(7),
            Felt::from_u32(8),
            Felt::from_u32(9),
            Felt::from_u32(10),
            Felt::from_u32(11),
            Felt::from_u32(12),
            Felt::from_u32(13),
            Felt::from_u32(14),
            // the 0 shifted in during `foo`
            Felt::from_u32(0),
            // the preserved overflow from before the call
            Felt::from_u32(15),
            Felt::from_u32(16),
        ]
    );
}

#[test]
fn stack_depth_default_limit_exact_boundary_succeeds() {
    let mut host = DefaultHost::default();

    let pushes_to_default_limit = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_to_default_limit));

    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("using the full default stack depth limit should succeed");
}

#[test]
fn stack_depth_default_limit_exceeded_returns_typed_error() {
    let mut host = DefaultHost::default();

    let pushes_past_default_limit = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + 1;
    let program = simple_program_with_ops(vec![Operation::Pad; pushes_past_default_limit]);

    let err = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect_err("pushing past the default stack depth limit should fail");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max: DEFAULT_MAX_STACK_DEPTH,
        } if depth == DEFAULT_MAX_STACK_DEPTH + 1
    );
}

#[test]
fn stack_depth_small_custom_limit_fails_before_buffer_growth() {
    let mut host = DefaultHost::default();
    let max_stack_depth = MIN_STACK_DEPTH + 1;
    let program = simple_program_with_ops(vec![Operation::Pad; 2]);
    let options = ExecutionOptions::default().with_max_stack_depth(max_stack_depth).unwrap();

    let err =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_sync(&program, &mut host)
            .expect_err("small configured stack depth limit should fail before buffer growth");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max,
        } if depth == max_stack_depth + 1 && max == max_stack_depth
    );
}

#[test]
fn issue_2818_fast_processor_stack_grows_past_initial_buffer_by_multiple_elements() {
    const GROWTH_MARGIN: usize = 4;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor advice inputs should fit advice map limits")
        .execute_sync(&program, &mut host)
        .expect("stack growth multiple elements past the initial buffer should succeed");
}

#[test]
fn issue_2818_traced_execution_stack_grows_past_initial_buffer() {
    const GROWTH_MARGIN: usize = 2;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    let trace_inputs =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_trace_inputs_sync(&program, &mut host)
            .expect("traced execution should grow the stack buffer past the initial buffer");

    crate::trace::build_trace(trace_inputs)
        .expect("trace replay should accept the same operand stack depth limit");
}

#[test]
fn issue_2818_step_execution_stack_grows_past_initial_buffer() {
    const GROWTH_MARGIN: usize = 2;

    let mut host = DefaultHost::default();

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();

    FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
        .expect("processor advice inputs should fit advice map limits")
        .execute_by_step_sync(&program, &mut host)
        .expect("step execution should grow the stack buffer past the initial buffer");
}

#[test]
fn issue_2818_restore_context_grows_stack_buffer_for_suspended_caller() {
    let caller_overflow_len = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + 1;
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + 1)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    assert_eq!(processor.stack.len(), INITIAL_STACK_BUFFER_SIZE);
    processor
        .stack_overflow_save_stack
        .push(vec![Felt::from_u32(42); caller_overflow_len]);
    // Keep the aggregate-overflow accounting consistent with the manually injected suspended
    // caller, mirroring what `start_context` would have done.
    processor.saved_overflow_len += caller_overflow_len;
    processor.system_call_state_stack.push(SystemCallState {
        ctx: processor.ctx,
        caller_hash: processor.caller_hash,
    });

    // The active callee context is still at the minimum stack depth and the storage has not grown.
    // Restoring this suspended caller is what requires moving the active stack and growing storage.
    StackInterface::restore_context(&mut processor)
        .expect("restoring a suspended caller should grow the stack buffer when needed");
    SystemInterface::restore_call_state(&mut processor)
        .expect("restoring system call state should succeed");
    assert!(
        processor.stack.len() > INITIAL_STACK_BUFFER_SIZE,
        "context restore should have grown the stack buffer"
    );
    assert_eq!(processor.stack_size(), MIN_STACK_DEPTH + caller_overflow_len);
}

#[test]
fn stack_buffer_is_not_preallocated_to_operand_stack_depth_limit() {
    const GROWTH_MARGIN: usize = 2;

    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH + GROWTH_MARGIN)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    assert_eq!(
        processor.stack.len(),
        INITIAL_STACK_BUFFER_SIZE,
        "processor should start with the initial stack buffer, not the full depth limit"
    );

    let mut host = DefaultHost::default();
    processor
        .execute_mut_sync(
            &simple_program_with_ops(vec![Operation::Pad, Operation::Drop]),
            &mut host,
        )
        .expect("ordinary shallow stack use should succeed");
    assert_eq!(
        processor.stack.len(),
        INITIAL_STACK_BUFFER_SIZE,
        "ordinary shallow stack use should not grow the buffer"
    );

    let pushes_past_initial_buffer = DEFAULT_MAX_STACK_DEPTH - MIN_STACK_DEPTH + GROWTH_MARGIN;
    let program = simple_program_with_ops(pad_then_drop_ops(pushes_past_initial_buffer));
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();

    processor
        .execute_mut_sync(&program, &mut host)
        .expect("deep stack use should grow the buffer on demand");
    assert!(
        processor.stack.len() > INITIAL_STACK_BUFFER_SIZE,
        "deep stack use should grow the buffer only when needed"
    );
}

#[test]
fn stack_growth_recenters_shallow_context_when_requested_len_exceeds_allocation_cap() {
    let options = ExecutionOptions::default()
        .with_max_stack_depth(DEFAULT_MAX_STACK_DEPTH)
        .unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    // This models a callee that has only the minimum live stack depth, but is still positioned at
    // the end of the current stack buffer after the caller filled the buffer and entered a new
    // context. The next push requests one slot past the allocation cap using the old position, but
    // growth can still succeed because it recenters the live stack before the push.
    processor.stack_top_idx = INITIAL_STACK_BUFFER_SIZE - 1;
    processor.stack_bot_idx = processor.stack_top_idx - MIN_STACK_DEPTH;

    processor
        .ensure_stack_capacity_for_push()
        .expect("recentered shallow context push should fit within the stack depth limit");

    assert_eq!(processor.stack_bot_idx, STACK_BUFFER_BASE_IDX);
    assert_eq!(processor.stack_top_idx, STACK_BUFFER_BASE_IDX + MIN_STACK_DEPTH);
    assert_eq!(processor.stack.len(), INITIAL_STACK_BUFFER_SIZE);
}

fn previous_growth_len(
    stack_len: usize,
    live_len: usize,
    requested_min_len: usize,
    max_len: usize,
) -> usize {
    let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);
    let required_len = requested_min_len.min(max_len).max(recentered_min_len);

    let mut new_len = stack_len;
    while new_len < required_len {
        let next_len = new_len.saturating_mul(2);
        if next_len <= new_len {
            return required_len;
        }
        new_len = next_len.min(max_len);
    }

    new_len
}

fn new_growth_len(live_len: usize, requested_min_len: usize, max_len: usize) -> usize {
    let target_len = STACK_BUFFER_BASE_IDX
        .saturating_add(live_len)
        .saturating_add(2)
        .saturating_mul(2);

    target_len.max(requested_min_len).min(max_len)
}

#[derive(Debug, PartialEq, Eq)]
struct GrowthSemantics {
    new_stack_bot_idx: usize,
    new_stack_top_idx: usize,
    covers_requested_len: bool,
    covers_recentered_len: bool,
    within_max_len: bool,
}

fn growth_semantics(
    new_len: usize,
    live_len: usize,
    requested_min_len: usize,
    max_len: usize,
) -> GrowthSemantics {
    let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);

    GrowthSemantics {
        new_stack_bot_idx: STACK_BUFFER_BASE_IDX,
        new_stack_top_idx: STACK_BUFFER_BASE_IDX + live_len,
        covers_requested_len: new_len >= requested_min_len,
        covers_recentered_len: new_len >= recentered_min_len,
        within_max_len: new_len <= max_len,
    }
}

#[test]
fn new_stack_growth_algorithm_is_vm_equivalent_to_previous_algorithm() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    for stack_len in [INITIAL_STACK_BUFFER_SIZE, INITIAL_STACK_BUFFER_SIZE * 2] {
        // Push growth is called when the next push would need one slot past the current buffer.
        let live_len = stack_len - STACK_BUFFER_BASE_IDX - 1;
        let requested_min_len = stack_len + 1;

        let previous_len = previous_growth_len(stack_len, live_len, requested_min_len, max_len);
        let new_len = new_growth_len(live_len, requested_min_len, max_len);

        assert_eq!(
            growth_semantics(previous_len, live_len, requested_min_len, max_len),
            growth_semantics(new_len, live_len, requested_min_len, max_len)
        );
    }

    for overflow_len in 0..=(max_depth - MIN_STACK_DEPTH) {
        // Restore growth is called from a callee with only the minimum live stack, but the
        // requested length must cover the caller overflow stack being restored.
        let requested_min_len =
            INITIAL_STACK_TOP_IDX.saturating_add(overflow_len).saturating_add(1);
        let previous_len = previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            MIN_STACK_DEPTH,
            requested_min_len,
            max_len,
        );
        let new_len = new_growth_len(MIN_STACK_DEPTH, requested_min_len, max_len);

        assert_eq!(
            growth_semantics(previous_len, MIN_STACK_DEPTH, requested_min_len, max_len),
            growth_semantics(new_len, MIN_STACK_DEPTH, requested_min_len, max_len)
        );
    }
}

#[test]
fn new_stack_growth_algorithm_allocation_differences_are_intentional() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    let push_live_len = INITIAL_STACK_BUFFER_SIZE - STACK_BUFFER_BASE_IDX - 1;
    let push_requested_min_len = INITIAL_STACK_BUFFER_SIZE + 1;
    assert_eq!(
        previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            push_live_len,
            push_requested_min_len,
            max_len,
        ),
        INITIAL_STACK_BUFFER_SIZE * 2
    );
    assert_eq!(
        new_growth_len(push_live_len, push_requested_min_len, max_len),
        INITIAL_STACK_BUFFER_SIZE * 2 + 2
    );

    let restore_requested_min_len = INITIAL_STACK_BUFFER_SIZE + 1;
    assert_eq!(
        previous_growth_len(
            INITIAL_STACK_BUFFER_SIZE,
            MIN_STACK_DEPTH,
            restore_requested_min_len,
            max_len,
        ),
        INITIAL_STACK_BUFFER_SIZE * 2
    );
    assert_eq!(
        new_growth_len(MIN_STACK_DEPTH, restore_requested_min_len, max_len),
        restore_requested_min_len
    );
}

#[test]
fn new_stack_growth_algorithm_preserves_required_bounds() {
    let max_depth = DEFAULT_MAX_STACK_DEPTH * 4;
    let max_len = STACK_BUFFER_BASE_IDX.saturating_add(max_depth).saturating_add(1);

    for live_len in MIN_STACK_DEPTH..max_depth {
        let recentered_min_len = STACK_BUFFER_BASE_IDX.saturating_add(live_len).saturating_add(2);
        let requested_min_len = recentered_min_len.max(INITIAL_STACK_BUFFER_SIZE + 1);
        let new_len = new_growth_len(live_len, requested_min_len, max_len);

        assert!(new_len >= requested_min_len);
        assert!(new_len >= recentered_min_len);
        assert!(new_len <= max_len);
    }

    for overflow_len in 0..=(max_depth - MIN_STACK_DEPTH) {
        let requested_min_len =
            INITIAL_STACK_TOP_IDX.saturating_add(overflow_len).saturating_add(1);
        let new_len = new_growth_len(MIN_STACK_DEPTH, requested_min_len, max_len);

        assert!(new_len >= requested_min_len);
        assert!(new_len <= max_len);
    }
}

#[test]
fn stack_depth_limit_exceeded() {
    let mut host = DefaultHost::default();
    let program = simple_program_with_ops(vec![Operation::Pad]);
    let options = ExecutionOptions::default().with_max_stack_depth(MIN_STACK_DEPTH).unwrap();

    let err =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits")
            .execute_sync(&program, &mut host)
            .expect_err("pushing past the configured stack depth should fail");

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded {
            depth,
            max: MIN_STACK_DEPTH,
        } if depth == MIN_STACK_DEPTH + 1
    );
}

/// Nested `call` context switches park the caller's operand-stack overflow (everything below the
/// top 16 elements) in `stack_overflow_save_stack` rather than freeing it. Before the fix, only the
/// active context was charged against `max_stack_depth`, so a program could keep every live frame
/// within the limit while accumulating `O(call_depth * (max_stack_depth - 16))` hidden overflow in
/// heap memory. This test drives such a nested-call chain and asserts that the aggregate operand
/// stack (active context plus all suspended overflow) is now bounded: execution fails with
/// `StackDepthLimitExceeded`, and the aggregate never exceeds the configured limit at any step.
#[test]
fn nested_calls_enforce_aggregate_stack_depth_limit() {
    let max_stack_depth = MIN_STACK_DEPTH + 2;

    // Each frame pushes 2 elements (filling the active context to `max_stack_depth`) and then calls
    // the next frame, which parks those 2 elements as hidden overflow. Without an aggregate bound
    // the saved overflow would grow without limit as the chain deepens.
    let source = "
        proc leaf
            push.0
            drop
        end

        proc mid_3
            push.0 push.0
            call.leaf
            drop drop
        end

        proc mid_2
            push.0 push.0
            call.mid_3
            drop drop
        end

        proc mid_1
            push.0 push.0
            call.mid_2
            drop drop
        end

        begin
            push.0 push.0
            call.mid_1
            drop drop
        end
        ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program("program", source)
        .expect("program should assemble")
        .unwrap_program();

    let options = ExecutionOptions::default().with_max_stack_depth(max_stack_depth).unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();
    let mut resume_ctx = processor
        .get_initial_resume_context(&program)
        .expect("initial resume context should be created");

    // Step until execution halts. At every step the aggregate operand-stack depth (active context
    // plus all suspended overflow) must stay within the configured limit, and execution must
    // eventually fail with `StackDepthLimitExceeded` rather than silently accumulating overflow.
    let err = loop {
        let saved_hidden_values: usize =
            processor.stack_overflow_save_stack.iter().map(Vec::len).sum();
        assert!(
            processor.stack_size() + saved_hidden_values <= max_stack_depth,
            "aggregate operand-stack depth must never exceed the configured limit"
        );

        match processor.step_sync(&mut host, resume_ctx) {
            Ok(Some(next_ctx)) => resume_ctx = next_ctx,
            Ok(None) => panic!("nested-call chain should not complete within the aggregate limit"),
            Err(err) => break err,
        }
    };

    assert_matches!(
        err,
        ExecutionError::StackDepthLimitExceeded { depth, max }
            if depth == max_stack_depth + 1 && max == max_stack_depth
    );
}

/// Companion to [`nested_calls_enforce_aggregate_stack_depth_limit`]: the aggregate operand-stack
/// budget must be *released* when a context returns. A nested-call chain whose peak aggregate
/// (active context plus all suspended overflow) stays within the limit executes to completion, and
/// the saved overflow is fully unwound by the end.
#[test]
fn nested_calls_within_aggregate_budget_succeed() {
    // Four frames each park 2 elements of hidden overflow. The peak aggregate occurs in the deepest
    // callee: 16 (active) + 4 * 2 (suspended) + 1 (its first push) = 25. Give exactly that budget.
    let max_stack_depth = MIN_STACK_DEPTH + 9;

    let source = "
        proc leaf
            push.0
            drop
        end

        proc mid_3
            push.0 push.0
            call.leaf
            drop drop
        end

        proc mid_2
            push.0 push.0
            call.mid_3
            drop drop
        end

        proc mid_1
            push.0 push.0
            call.mid_2
            drop drop
        end

        begin
            push.0 push.0
            call.mid_1
            drop drop
        end
        ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program("program", source)
        .expect("program should assemble")
        .unwrap_program();

    let options = ExecutionOptions::default().with_max_stack_depth(max_stack_depth).unwrap();
    let mut processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let mut host = DefaultHost::default();

    processor
        .execute_mut_sync(&program, &mut host)
        .expect("a nested-call chain within the aggregate budget should succeed");

    // Every context returned, so the suspended-overflow budget is fully released.
    assert!(processor.stack_overflow_save_stack.is_empty());
    assert_eq!(processor.saved_overflow_len, 0);
}

/// Tests that `ExecutionError::Internal` is correctly emitted when the continuation stack grows
/// past the maximum allowed size.
#[test]
fn test_continuation_stack_limit_exceeded() {
    let mut host = DefaultHost::default();

    // Build a program with deeply nested join nodes. Each join node pushes 2 continuations
    // (FinishJoin + StartNode) onto the continuation stack before executing its first child.
    // With `depth` levels of nesting, the continuation stack will grow to approximately
    // `2 * depth` entries.
    let program = {
        let mut forest = MastForest::new();

        // Create a simple leaf basic block (just a noop).
        let leaf_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();

        // Nest join nodes: join(join(join(..., leaf), leaf), leaf)
        // Each level adds ~2 continuations to the stack.
        let depth = 10;
        let mut current = leaf_id;
        for _ in 0..depth {
            current = JoinNodeBuilder::new([current, leaf_id]).add_to_forest(&mut forest).unwrap();
        }

        forest.make_root(current);
        Program::new(forest.into(), current)
    };

    // Set a very small continuation stack limit that will be exceeded by the nested joins.
    let options = ExecutionOptions::default().with_max_num_continuations(3);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");
    let err = processor.execute_sync(&program, &mut host).unwrap_err();

    assert_matches!(err, ExecutionError::Internal(msg) if msg.contains("continuation stack"));
}

/// Tests that a continuation stack size exactly equal to `max_num_continuations` succeeds.
#[test]
fn test_continuation_stack_limit_exactly_max_continuations_succeeds() {
    let mut host = DefaultHost::default();

    let program = {
        let mut forest = MastForest::new();

        let leaf_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();

        let root = JoinNodeBuilder::new([leaf_id, leaf_id]).add_to_forest(&mut forest).unwrap();
        forest.make_root(root);
        Program::new(forest.into(), root)
    };

    // A single join peaks at three continuations after the join start step:
    // FinishJoin(root), StartNode(second), StartNode(first).
    let options = ExecutionOptions::default().with_max_num_continuations(3);

    let processor =
        FastProcessor::new_with_options(StackInputs::default(), AdviceInputs::default(), options)
            .expect("processor advice inputs should fit advice map limits");

    processor.execute_sync(&program, &mut host).unwrap();
}

// TEST HELPERS
// -----------------------------------------------------------------------------------------------

fn simple_program_with_ops(ops: Vec<Operation>) -> Program {
    let program: Program = {
        let mut program = MastForest::new();
        let root_id = BasicBlockNodeBuilder::new(ops).add_to_forest(&mut program).unwrap();
        program.make_root(root_id);

        Program::new(program.into(), root_id)
    };

    program
}

fn pad_then_drop_ops(num_pads: usize) -> Vec<Operation> {
    let mut ops = vec![Operation::Pad; num_pads];
    ops.extend(vec![Operation::Drop; num_pads]);
    ops
}
