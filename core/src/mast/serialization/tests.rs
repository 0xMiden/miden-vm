use std::{
    string::{String, ToString},
    sync::{Mutex, Once},
};

use super::*;
use crate::{
    Felt, ONE, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DebugInfo, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForestContributor, MastForestError, MastForestView,
        MastNodeExt, MastNodeId, OP_BATCH_SIZE, OpBatch, SplitNodeBuilder, UntrustedMastForest,
    },
    operations::{DebugOptions, Decorator, Operation},
    serde::{ByteReader, Deserializable, DeserializationError, Serializable, SliceReader},
    utils::Idx,
};

struct TestLogger {
    messages: Mutex<Vec<String>>,
}

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Error
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            self.messages.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

static TEST_LOGGER: TestLogger = TestLogger { messages: Mutex::new(Vec::new()) };
static TEST_LOGGER_INIT: Once = Once::new();
static TEST_LOGGER_GUARD: Mutex<()> = Mutex::new(());

fn with_captured_error_logs<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    TEST_LOGGER_INIT.call_once(|| {
        log::set_logger(&TEST_LOGGER).expect("test logger should be installed once");
        log::set_max_level(log::LevelFilter::Error);
    });

    let _guard = TEST_LOGGER_GUARD.lock().unwrap();
    TEST_LOGGER.messages.lock().unwrap().clear();
    let result = f();
    let messages = TEST_LOGGER.messages.lock().unwrap().clone();
    (result, messages)
}

/// If this test fails to compile, it means that `Operation` or `Decorator` was changed. Make sure
/// that all tests in this file are updated accordingly. For example, if a new `Operation` variant
/// was added, make sure that you add it in the vector of operations in
/// [`serialize_deserialize_all_nodes`].
#[test]
fn confirm_operation_and_decorator_structure() {
    match Operation::Noop {
        Operation::Noop => (),
        Operation::Assert(_) => (),
        Operation::SDepth => (),
        Operation::Caller => (),
        Operation::Clk => (),
        Operation::Add => (),
        Operation::Neg => (),
        Operation::Mul => (),
        Operation::Inv => (),
        Operation::Incr => (),
        Operation::And => (),
        Operation::Or => (),
        Operation::Not => (),
        Operation::Eq => (),
        Operation::Eqz => (),
        Operation::Expacc => (),
        Operation::Ext2Mul => (),
        Operation::U32split => (),
        Operation::U32add => (),
        Operation::U32assert2(_) => (),
        Operation::U32add3 => (),
        Operation::U32sub => (),
        Operation::U32mul => (),
        Operation::U32madd => (),
        Operation::U32div => (),
        Operation::U32and => (),
        Operation::U32xor => (),
        Operation::Pad => (),
        Operation::Drop => (),
        Operation::Dup0 => (),
        Operation::Dup1 => (),
        Operation::Dup2 => (),
        Operation::Dup3 => (),
        Operation::Dup4 => (),
        Operation::Dup5 => (),
        Operation::Dup6 => (),
        Operation::Dup7 => (),
        Operation::Dup9 => (),
        Operation::Dup11 => (),
        Operation::Dup13 => (),
        Operation::Dup15 => (),
        Operation::Swap => (),
        Operation::SwapW => (),
        Operation::SwapW2 => (),
        Operation::SwapW3 => (),
        Operation::SwapDW => (),
        Operation::MovUp2 => (),
        Operation::MovUp3 => (),
        Operation::MovUp4 => (),
        Operation::MovUp5 => (),
        Operation::MovUp6 => (),
        Operation::MovUp7 => (),
        Operation::MovUp8 => (),
        Operation::MovDn2 => (),
        Operation::MovDn3 => (),
        Operation::MovDn4 => (),
        Operation::MovDn5 => (),
        Operation::MovDn6 => (),
        Operation::MovDn7 => (),
        Operation::MovDn8 => (),
        Operation::CSwap => (),
        Operation::CSwapW => (),
        Operation::Push(_) => (),
        Operation::AdvPop => (),
        Operation::AdvPopW => (),
        Operation::MLoadW => (),
        Operation::MStoreW => (),
        Operation::MLoad => (),
        Operation::MStore => (),
        Operation::MStream => (),
        Operation::Pipe => (),
        Operation::CryptoStream => (),
        Operation::HPerm => (),
        Operation::MpVerify(_) => (),
        Operation::MrUpdate => (),
        Operation::FriE2F4 => (),
        Operation::HornerBase => (),
        Operation::HornerExt => (),
        Operation::EvalCircuit => (),
        Operation::Emit => (),
        Operation::LogPrecompile => (),
    };

    // Decorator variants - exhaustiveness check to ensure serialization coverage.
    match Decorator::Trace(0) {
        Decorator::Debug(debug_options) => match debug_options {
            DebugOptions::StackAll => (),
            DebugOptions::StackTop(_) => (),
            DebugOptions::MemAll => (),
            DebugOptions::MemInterval(..) => (),
            DebugOptions::LocalInterval(..) => (),
            DebugOptions::AdvStackTop(_) => (),
        },
        Decorator::Trace(_) => (),
    };
}

/// Returns all currently supported basic-block [`Operation`] variants.
///
/// Control-flow instructions (e.g. `join`, `split`, `loop`, `call`) are represented as
/// [`MastNode`] variants, not as basic-block [`Operation`] values.
fn sample_basic_block_operations_all_variants() -> Vec<Operation> {
    vec![
        Operation::Noop,
        Operation::Assert(Felt::from_u32(42)),
        Operation::SDepth,
        Operation::Caller,
        Operation::Clk,
        Operation::Add,
        Operation::Neg,
        Operation::Mul,
        Operation::Inv,
        Operation::Incr,
        Operation::And,
        Operation::Or,
        Operation::Not,
        Operation::Eq,
        Operation::Eqz,
        Operation::Expacc,
        Operation::Ext2Mul,
        Operation::U32split,
        Operation::U32add,
        Operation::U32assert2(Felt::from_u32(222)),
        Operation::U32add3,
        Operation::U32sub,
        Operation::U32mul,
        Operation::U32madd,
        Operation::U32div,
        Operation::U32and,
        Operation::U32xor,
        Operation::Pad,
        Operation::Drop,
        Operation::Dup0,
        Operation::Dup1,
        Operation::Dup2,
        Operation::Dup3,
        Operation::Dup4,
        Operation::Dup5,
        Operation::Dup6,
        Operation::Dup7,
        Operation::Dup9,
        Operation::Dup11,
        Operation::Dup13,
        Operation::Dup15,
        Operation::Swap,
        Operation::SwapW,
        Operation::SwapW2,
        Operation::SwapW3,
        Operation::SwapDW,
        Operation::MovUp2,
        Operation::MovUp3,
        Operation::MovUp4,
        Operation::MovUp5,
        Operation::MovUp6,
        Operation::MovUp7,
        Operation::MovUp8,
        Operation::MovDn2,
        Operation::MovDn3,
        Operation::MovDn4,
        Operation::MovDn5,
        Operation::MovDn6,
        Operation::MovDn7,
        Operation::MovDn8,
        Operation::CSwap,
        Operation::CSwapW,
        Operation::Push(Felt::new_unchecked(45)),
        Operation::AdvPop,
        Operation::AdvPopW,
        Operation::MLoadW,
        Operation::MStoreW,
        Operation::MLoad,
        Operation::MStore,
        Operation::MStream,
        Operation::Pipe,
        Operation::CryptoStream,
        Operation::HPerm,
        Operation::MpVerify(Felt::from_u32(1022)),
        Operation::MrUpdate,
        Operation::FriE2F4,
        Operation::HornerBase,
        Operation::HornerExt,
        Operation::EvalCircuit,
        Operation::Emit,
        Operation::LogPrecompile,
    ]
}

fn assert_operation_encoded_size_matches_serialized_len(operation: Operation) {
    match operation {
        operation @ (Operation::Noop
        | Operation::Assert(_)
        | Operation::SDepth
        | Operation::Caller
        | Operation::Clk
        | Operation::Add
        | Operation::Neg
        | Operation::Mul
        | Operation::Inv
        | Operation::Incr
        | Operation::And
        | Operation::Or
        | Operation::Not
        | Operation::Eq
        | Operation::Eqz
        | Operation::Expacc
        | Operation::Ext2Mul
        | Operation::U32split
        | Operation::U32add
        | Operation::U32assert2(_)
        | Operation::U32add3
        | Operation::U32sub
        | Operation::U32mul
        | Operation::U32madd
        | Operation::U32div
        | Operation::U32and
        | Operation::U32xor
        | Operation::Pad
        | Operation::Drop
        | Operation::Dup0
        | Operation::Dup1
        | Operation::Dup2
        | Operation::Dup3
        | Operation::Dup4
        | Operation::Dup5
        | Operation::Dup6
        | Operation::Dup7
        | Operation::Dup9
        | Operation::Dup11
        | Operation::Dup13
        | Operation::Dup15
        | Operation::Swap
        | Operation::SwapW
        | Operation::SwapW2
        | Operation::SwapW3
        | Operation::SwapDW
        | Operation::MovUp2
        | Operation::MovUp3
        | Operation::MovUp4
        | Operation::MovUp5
        | Operation::MovUp6
        | Operation::MovUp7
        | Operation::MovUp8
        | Operation::MovDn2
        | Operation::MovDn3
        | Operation::MovDn4
        | Operation::MovDn5
        | Operation::MovDn6
        | Operation::MovDn7
        | Operation::MovDn8
        | Operation::CSwap
        | Operation::CSwapW
        | Operation::Push(_)
        | Operation::AdvPop
        | Operation::AdvPopW
        | Operation::MLoadW
        | Operation::MStoreW
        | Operation::MLoad
        | Operation::MStore
        | Operation::MStream
        | Operation::Pipe
        | Operation::CryptoStream
        | Operation::HPerm
        | Operation::MpVerify(_)
        | Operation::MrUpdate
        | Operation::FriE2F4
        | Operation::HornerBase
        | Operation::HornerExt
        | Operation::EvalCircuit
        | Operation::Emit
        | Operation::LogPrecompile) => {
            assert_eq!(operation.encoded_size(), operation.to_bytes().len());
        },
    }
}

#[test]
fn serialize_deserialize_all_nodes() {
    let mut mast_forest = MastForest::new();

    let basic_block_id = {
        let operations = sample_basic_block_operations_all_variants();

        let num_operations = operations.len();

        // Note: AssemblyOps are now stored separately in DebugInfo's asm_op storage,
        // not as decorators. See the asm_op module tests for AssemblyOp serialization.
        let decorators = vec![
            (0, Decorator::Debug(DebugOptions::StackAll)),
            (15, Decorator::Debug(DebugOptions::StackTop(255))),
            (15, Decorator::Debug(DebugOptions::MemAll)),
            (15, Decorator::Debug(DebugOptions::MemInterval(0, 16))),
            (17, Decorator::Debug(DebugOptions::LocalInterval(1, 2, 3))),
            (19, Decorator::Debug(DebugOptions::AdvStackTop(255))),
            (num_operations, Decorator::Trace(55)),
        ];

        // Convert raw decorators to decorator list by adding them to the forest first
        let decorator_list: Vec<(usize, crate::mast::DecoratorId)> = decorators
            .into_iter()
            .map(|(idx, decorator)| {
                mast_forest.add_decorator(decorator).map(|decorator_id| (idx, decorator_id))
            })
            .collect::<Result<Vec<_>, MastForestError>>()
            .unwrap();

        BasicBlockNodeBuilder::new(operations, decorator_list)
            .add_to_forest(&mut mast_forest)
            .unwrap()
    };

    // Decorators to add to following nodes
    let decorator_id1 = mast_forest.add_decorator(Decorator::Trace(1)).unwrap();
    let decorator_id2 = mast_forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Call node
    let call_node_id = CallNodeBuilder::new(basic_block_id)
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Syscall node
    let syscall_node_id = CallNodeBuilder::new_syscall(basic_block_id)
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Loop node
    let loop_node_id = LoopNodeBuilder::new(basic_block_id)
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Join node
    let join_node_id = JoinNodeBuilder::new([basic_block_id, call_node_id])
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Split node
    let split_node_id = SplitNodeBuilder::new([basic_block_id, call_node_id])
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Dyn node
    let dyn_node_id = DynNodeBuilder::new_dyn()
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // Dyncall node
    let dyncall_node_id = DynNodeBuilder::new_dyncall()
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    // External node
    let external_node_id = ExternalNodeBuilder::new(Word::default())
        .with_before_enter(vec![decorator_id1])
        .with_after_exit(vec![decorator_id2])
        .add_to_forest(&mut mast_forest)
        .unwrap();

    mast_forest.make_root(join_node_id);
    mast_forest.make_root(syscall_node_id);
    mast_forest.make_root(loop_node_id);
    mast_forest.make_root(split_node_id);
    mast_forest.make_root(dyn_node_id);
    mast_forest.make_root(dyncall_node_id);
    mast_forest.make_root(external_node_id);

    let serialized_mast_forest = mast_forest.to_bytes();
    let deserialized_mast_forest = MastForest::read_from_bytes(&serialized_mast_forest).unwrap();

    assert_eq!(mast_forest, deserialized_mast_forest);
}

#[test]
fn test_operation_encoded_size_matches_serialized_len() {
    for operation in sample_basic_block_operations_all_variants() {
        assert_operation_encoded_size_matches_serialized_len(operation);
    }
}

#[test]
fn test_operation_encoded_size_push_varint_boundaries() {
    for value in [
        127u64,
        128,
        16_383,
        16_384,
        2_097_151,
        2_097_152,
        268_435_455,
        268_435_456,
        72_057_594_037_927_935,
        72_057_594_037_927_936,
    ] {
        assert_operation_encoded_size_matches_serialized_len(Operation::Push(Felt::new(value)));
    }
}

fn assert_serialized_view_matches_forest(forest: &MastForest) {
    let mut bytes = Vec::new();
    forest.write_stripped(&mut bytes);

    let view = SerializedMastForest::new(&bytes).unwrap();
    assert_eq!(view.node_count(), forest.nodes().len());

    let mut bb_builder = super::basic_blocks::BasicBlockDataBuilder::new();
    for (idx, node) in forest.nodes().iter().enumerate() {
        let ops_offset = if let MastNode::Block(block) = node {
            bb_builder.encode_basic_block(block)
        } else {
            0
        };
        let expected = MastNodeInfo::new(node, ops_offset);
        let actual = view.node_info_at(idx).unwrap();
        assert_eq!(expected.to_bytes(), actual.to_bytes());
    }
}

#[test]
fn test_mast_forest_view_trait_matches_serialized_view() {
    let mut forest = MastForest::new();

    let block1 = BasicBlockNodeBuilder::new(
        vec![Operation::Push(Felt::new(7)), Operation::Add, Operation::Mul],
        Vec::new(),
    )
    .add_to_forest(&mut forest)
    .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);

    let mut bytes = Vec::new();
    forest.write_stripped(&mut bytes);
    let serialized = SerializedMastForest::new(&bytes).unwrap();

    let in_memory: &dyn MastForestView = &forest;
    let serialized_view: &dyn MastForestView = &serialized;

    assert!(!in_memory.is_empty());
    assert!(in_memory.has_node(0));
    assert!(!in_memory.has_node(in_memory.node_count()));

    assert_eq!(in_memory.node_count(), serialized_view.node_count());
    for index in 0..in_memory.node_count() {
        assert_eq!(
            in_memory.node_info_at(index).unwrap().to_bytes(),
            serialized_view.node_info_at(index).unwrap().to_bytes()
        );
        assert_eq!(
            in_memory.node_digest_at(index).unwrap(),
            serialized_view.node_digest_at(index).unwrap()
        );
    }

    assert_eq!(in_memory.procedure_root_count(), serialized_view.procedure_root_count());
    assert_eq!(in_memory.procedure_roots().unwrap(), serialized_view.procedure_roots().unwrap());

    let in_memory_infos = in_memory.all_node_infos().unwrap();
    let serialized_infos = serialized_view.all_node_infos().unwrap();
    assert_eq!(in_memory_infos.len(), serialized_infos.len());
    for (lhs, rhs) in in_memory_infos.iter().zip(serialized_infos.iter()) {
        assert_eq!(lhs.to_bytes(), rhs.to_bytes());
    }
}

#[test]
fn test_serialized_mast_forest_random_access_all_node_types() {
    let mut forest = MastForest::new();

    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let call_id = CallNodeBuilder::new(block_id).add_to_forest(&mut forest).unwrap();
    let syscall_id = CallNodeBuilder::new_syscall(block_id).add_to_forest(&mut forest).unwrap();
    let loop_id = LoopNodeBuilder::new(block_id).add_to_forest(&mut forest).unwrap();
    let join_id = JoinNodeBuilder::new([block_id, call_id]).add_to_forest(&mut forest).unwrap();
    let split_id = SplitNodeBuilder::new([block_id, call_id]).add_to_forest(&mut forest).unwrap();
    let dyn_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
    let dyncall_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
    let external_id = ExternalNodeBuilder::new(Word::default()).add_to_forest(&mut forest).unwrap();

    forest.make_root(join_id);
    forest.make_root(syscall_id);
    forest.make_root(loop_id);
    forest.make_root(split_id);
    forest.make_root(dyn_id);
    forest.make_root(dyncall_id);
    forest.make_root(external_id);

    assert_serialized_view_matches_forest(&forest);
}

#[test]
fn test_serialized_mast_forest_large_counts() {
    let mut forest = MastForest::new();
    let mut roots = Vec::new();

    for _ in 0..300 {
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        roots.push(block_id);
    }

    for root in roots.iter().take(200) {
        forest.make_root(*root);
    }

    assert_serialized_view_matches_forest(&forest);
}

fn debug_info_offset_after_advice_map(bytes: &[u8]) -> usize {
    let view = SerializedMastForest::new(bytes).unwrap();
    let mut offset = view.advice_map_offset().unwrap();
    let entry_count = read_usize_at(bytes, &mut offset).unwrap();
    for _ in 0..entry_count {
        for _ in 0..4 {
            let _ = read_array_at::<8>(bytes, &mut offset).unwrap();
        }
        let values_len = read_usize_at(bytes, &mut offset).unwrap();
        for _ in 0..values_len {
            let _ = read_array_at::<8>(bytes, &mut offset).unwrap();
        }
    }
    offset
}

fn node_hash_digest_offset(view: &SerializedMastForest<'_>, node_index: usize) -> usize {
    let digest_slot = view.digest_slot_at(node_index);
    view.node_hash_offset().unwrap() + digest_slot * Word::min_serialized_size()
}

fn rewrite_debug_info_procedure_name_digest(
    bytes: &[u8],
    from_digest: Word,
    to_digest: Word,
) -> Vec<u8> {
    let debug_info_offset = debug_info_offset_after_advice_map(bytes);
    let mut reader = SliceReader::new(&bytes[debug_info_offset..]);
    let mut debug_info = DebugInfo::read_from(&mut reader).unwrap();

    let procedure_names: Vec<_> = debug_info
        .procedure_names()
        .map(|(digest, name)| {
            let remapped_digest = if digest == from_digest { to_digest } else { digest };
            (remapped_digest, name.to_string().into())
        })
        .collect();

    debug_info.clear_procedure_names();
    debug_info.extend_procedure_names(procedure_names);

    let mut rewritten = bytes[..debug_info_offset].to_vec();
    debug_info.write_into(&mut rewritten);
    rewritten
}

#[test]
fn test_serialized_mast_forest_hashless_omits_hash_section_and_recomputes_digests() {
    let mut forest = MastForest::new();
    let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);
    let view = SerializedMastForest::new(&bytes).unwrap();
    assert!(view.node_hash_offset().is_none());
    for index in 0..view.node_count() {
        assert_eq!(forest.nodes()[index].digest(), view.node_info_at(index).unwrap().digest());
    }
}

#[test]
fn test_serialized_mast_forest_hashless_accepts_external_nodes_parse_only() {
    let mut forest = MastForest::new();
    let external_digest = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let external_id = ExternalNodeBuilder::new(external_digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(external_id);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);
    let view = SerializedMastForest::new(&bytes).unwrap();
    assert_eq!(view.node_count(), 1);
    assert!(view.node_info_at(0).is_ok());
    assert_eq!(view.node_digest_at(0).unwrap(), external_digest);
}

/// Test that a forest with a node whose child ids are larger than its own id serializes and
/// deserializes successfully.
#[test]
fn mast_forest_serialize_deserialize_with_child_ids_exceeding_parent_id() {
    let mut forest = MastForest::new();
    let deco0 = forest.add_decorator(Decorator::Trace(0)).unwrap();
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let zero = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32add], vec![(0, deco0)])
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32and], vec![(1, deco1)])
        .add_to_forest(&mut forest)
        .unwrap();
    JoinNodeBuilder::new([first, second]).add_to_forest(&mut forest).unwrap();

    // Move the Join node before its child nodes and remove the temporary zero node.
    forest.nodes.swap_remove(zero.to_usize());

    MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
}

/// Test that a forest with a node whose referenced index is >= the max number of nodes in
/// the forest returns an error during deserialization.
#[test]
fn mast_forest_serialize_deserialize_with_overflowing_ids_fails() {
    let mut overflow_forest = MastForest::new();
    let id0 = BasicBlockNodeBuilder::new(vec![Operation::Eqz], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::Eqz], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    let id2 = BasicBlockNodeBuilder::new(vec![Operation::Eqz], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    let id_join = JoinNodeBuilder::new([id0, id2]).add_to_forest(&mut overflow_forest).unwrap();

    let join_node = overflow_forest[id_join].clone();

    // Add the Join(0, 2) to this forest which does not have a node with index 2.
    let mut forest = MastForest::new();
    let deco0 = forest.add_decorator(Decorator::Trace(0)).unwrap();
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::U32add], vec![(0, deco0), (1, deco1)])
        .add_to_forest(&mut forest)
        .unwrap();
    // hack to force addition of a node which builder would return an error at runtime
    // don't use this in production
    forest.nodes.push(join_node).unwrap();

    assert_matches!(
        MastForest::read_from_bytes(&forest.to_bytes()),
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("number of nodes")
    );
}

#[test]
fn mast_forest_invalid_node_id() {
    // Hydrate a forest smaller than the second
    let mut forest = MastForest::new();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    // Hydrate a forest larger than the first to get an overflow MastNodeId
    let mut overflow_forest = MastForest::new();

    BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    let overflow = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut overflow_forest)
        .unwrap();

    // Attempt to join with invalid ids
    let join = JoinNodeBuilder::new([overflow, second]).add_to_forest(&mut forest);
    assert_eq!(join, Err(MastForestError::NodeIdOverflow(overflow, 2)));
    let join = JoinNodeBuilder::new([first, overflow]).add_to_forest(&mut forest);
    assert_eq!(join, Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Attempt to split with invalid ids
    let split = SplitNodeBuilder::new([overflow, second]).add_to_forest(&mut forest);
    assert_eq!(split, Err(MastForestError::NodeIdOverflow(overflow, 2)));
    let split = SplitNodeBuilder::new([first, overflow]).add_to_forest(&mut forest);
    assert_eq!(split, Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Attempt to loop with invalid ids
    assert_eq!(
        LoopNodeBuilder::new(overflow).add_to_forest(&mut forest),
        Err(MastForestError::NodeIdOverflow(overflow, 2))
    );

    // Attempt to call with invalid ids
    assert_eq!(
        CallNodeBuilder::new(overflow).add_to_forest(&mut forest),
        Err(MastForestError::NodeIdOverflow(overflow, 2))
    );
    assert_eq!(
        CallNodeBuilder::new_syscall(overflow).add_to_forest(&mut forest),
        Err(MastForestError::NodeIdOverflow(overflow, 2))
    );

    // Validate normal operations
    JoinNodeBuilder::new([first, second]).add_to_forest(&mut forest).unwrap();
}

/// Test `MastForest::advice_map` serialization and deserialization.
#[test]
fn mast_forest_serialize_deserialize_advice_map() {
    let mut forest = MastForest::new();
    let deco0 = forest.add_decorator(Decorator::Trace(0)).unwrap();
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32add], vec![(0, deco0)])
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32and], vec![(1, deco1)])
        .add_to_forest(&mut forest)
        .unwrap();
    JoinNodeBuilder::new([first, second]).add_to_forest(&mut forest).unwrap();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    forest.advice_map_mut().insert(key, value);

    let parsed = MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
    assert_eq!(forest.advice_map, parsed.advice_map);
}

/// Test that [`BasicBlockNode`] serialization doesn't duplicate `before_enter`/`after_exit`
/// decorators.
///
/// This test verifies that the serialization process correctly uses `indexed_decorator_iter()`
/// instead of `decorators()` to avoid duplicating before_enter and after_exit decorators, which
/// are serialized separately in the `before_enter_decorators` and `after_exit_decorators` lists.
#[test]
fn mast_forest_basic_block_serialization_no_decorator_duplication() {
    let mut forest = MastForest::new();

    // Create decorators
    let before_enter_deco = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let op_deco = forest.add_decorator(Decorator::Trace(2)).unwrap();
    let after_exit_deco = forest.add_decorator(Decorator::Trace(3)).unwrap();

    // Create a basic block with all types of decorators using builder pattern
    let operations = vec![Operation::Add, Operation::Mul];
    let block_id = BasicBlockNodeBuilder::new(operations, vec![(0, op_deco)])
        .with_before_enter(vec![before_enter_deco])
        .with_after_exit(vec![after_exit_deco])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    // Serialize and deserialize the forest
    let serialized = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&serialized).unwrap();

    // Get the deserialized block
    let deserialized_root_id = deserialized.procedure_roots()[0];
    let deserialized_block = if let MastNode::Block(block) = &deserialized[deserialized_root_id] {
        block
    } else {
        panic!("Expected a block node");
    };

    // Verify that each decorator appears exactly once in the deserialized structure
    assert_eq!(
        deserialized_block.before_enter(&deserialized),
        &[before_enter_deco],
        "before_enter decorator should appear exactly once"
    );
    assert_eq!(
        deserialized_block.after_exit(&deserialized),
        &[after_exit_deco],
        "after_exit decorator should appear exactly once"
    );

    // Verify that the op-indexed decorator is only in the indexed decorator list
    let indexed_decorators: Vec<_> =
        deserialized_block.indexed_decorator_iter(&deserialized).collect();
    assert_eq!(indexed_decorators.len(), 1, "Should have exactly one op-indexed decorator");
    assert_eq!(indexed_decorators[0].1, op_deco, "Op-indexed decorator should be preserved");

    // Verify that before_enter and after_exit decorators are NOT in the indexed decorator list
    assert!(
        !indexed_decorators.iter().any(|&(_, id)| id == before_enter_deco),
        "before_enter decorator should not be duplicated in indexed decorators"
    );
    assert!(
        !indexed_decorators.iter().any(|&(_, id)| id == after_exit_deco),
        "after_exit decorator should not be duplicated in indexed decorators"
    );

    // Note: The decorators() method test was removed as MastNodeErrorContext trait has been removed
    // The decorator functionality is now accessed through MastForest.get_assembly_op() directly
}

/// Tests that deserialization rejects ops_offset values beyond the basic_block_data buffer.
#[test]
fn mast_forest_deserialize_invalid_ops_offset_fails() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let serialized = forest.to_bytes();
    let mut reader = SliceReader::new(&serialized);

    let _: [u8; 8] = reader.read_array().unwrap(); // magic (4) + flags (1) + version (3)
    let _node_count: usize = reader.read().unwrap();
    let _decorator_count: usize = reader.read().unwrap();
    let _roots: Vec<u32> = Deserializable::read_from(&mut reader).unwrap();
    let _basic_block_data: Vec<u8> = Deserializable::read_from(&mut reader).unwrap();

    let view = SerializedMastForest::new(&serialized).unwrap();
    let node_entry_offset = view.node_entry_offset();

    // Corrupt the ops_offset field with an out-of-bounds value
    let block_discriminant: u64 = 3;
    let corrupted_value = (block_discriminant << 60) | u32::MAX as u64;

    let mut corrupted = serialized;
    corrupted_value.write_into(&mut &mut corrupted[node_entry_offset..node_entry_offset + 8]);

    let result = MastForest::read_from_bytes(&corrupted);
    assert_matches!(result, Err(DeserializationError::InvalidValue(_)));
}

#[test]
fn mast_forest_serialize_deserialize_procedure_names() {
    let mut forest = MastForest::new();

    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let digest = forest[block_id].digest();
    forest.insert_procedure_name(digest, "test_procedure".into());

    assert_eq!(forest.procedure_name(&digest), Some("test_procedure"));
    assert_eq!(forest.debug_info.num_procedure_names(), 1);

    let serialized = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized.procedure_name(&digest), Some("test_procedure"));
    assert_eq!(deserialized.debug_info.num_procedure_names(), 1);
    assert_eq!(forest, deserialized);
}

#[test]
fn mast_forest_serialize_deserialize_multiple_procedure_names() {
    let mut forest = MastForest::new();

    let block1_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let block2_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let block3_id = BasicBlockNodeBuilder::new(vec![Operation::U32sub], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    forest.make_root(block1_id);
    forest.make_root(block2_id);
    forest.make_root(block3_id);

    let digest1 = forest[block1_id].digest();
    let digest2 = forest[block2_id].digest();
    let digest3 = forest[block3_id].digest();

    forest.insert_procedure_name(digest1, "proc_add".into());
    forest.insert_procedure_name(digest2, "proc_mul".into());
    forest.insert_procedure_name(digest3, "proc_sub".into());

    assert_eq!(forest.debug_info.num_procedure_names(), 3);

    let serialized = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized.procedure_name(&digest1), Some("proc_add"));
    assert_eq!(deserialized.procedure_name(&digest2), Some("proc_mul"));
    assert_eq!(deserialized.procedure_name(&digest3), Some("proc_sub"));
    assert_eq!(deserialized.debug_info.num_procedure_names(), 3);

    assert_eq!(forest, deserialized);
}

// OPBATCH PRESERVATION TESTS
// ================================================================================================

/// Tests that OpBatch structure is preserved during round-trip serialization
#[test]
fn test_opbatch_roundtrip_preservation() {
    let mut forest = MastForest::new();

    let operations = vec![
        Operation::Add,
        Operation::Push(Felt::new_unchecked(100)),
        Operation::Push(Felt::new_unchecked(200)),
        Operation::Mul,
    ];

    let block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    let original = forest[block_id].unwrap_basic_block();
    let deserialized_forest = MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
    let deserialized = deserialized_forest[block_id].unwrap_basic_block();

    assert_eq!(original.op_batches(), deserialized.op_batches());
}

/// Tests OpBatch preservation with multiple batches (>72 operations)
#[test]
fn test_multi_batch_roundtrip() {
    let mut forest = MastForest::new();
    let operations: Vec<_> = (0..80).map(|i| Operation::Push(Felt::new_unchecked(i))).collect();

    let block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    let original = forest[block_id].unwrap_basic_block();
    assert!(original.op_batches().len() > 1, "Should have multiple batches");

    let deserialized_forest = MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
    let deserialized = deserialized_forest[block_id].unwrap_basic_block();

    assert_eq!(original.op_batches(), deserialized.op_batches());
}

/// Tests that decorator indices remain correct after round-trip with padded operations.
#[test]
fn test_decorator_indices_preserved_with_padding() {
    let mut forest = MastForest::new();

    let decorator_id = forest.add_decorator(Decorator::Trace(42)).unwrap();

    let operations = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(Felt::new_unchecked(100)), // Will cause padding
        Operation::Drop,
    ];

    // Add decorator at operation index 2 (the PUSH)
    let decorators = vec![(2, decorator_id)];

    let block_id = BasicBlockNodeBuilder::new(operations, decorators)
        .add_to_forest(&mut forest)
        .unwrap();

    // Serialize and deserialize
    let serialized = forest.to_bytes();
    let deserialized_forest = MastForest::read_from_bytes(&serialized).unwrap();

    // Verify decorator still points to correct operation
    let original_node = forest[block_id].unwrap_basic_block();
    let deserialized_node = deserialized_forest[block_id].unwrap_basic_block();

    let original_decorators: Vec<_> = original_node.indexed_decorator_iter(&forest).collect();
    let deserialized_decorators: Vec<_> =
        deserialized_node.indexed_decorator_iter(&deserialized_forest).collect();

    assert_eq!(
        original_decorators, deserialized_decorators,
        "Decorator indices should be preserved"
    );

    // Verify the decorator points to the PUSH operation
    assert_eq!(deserialized_decorators.len(), 1, "Should have one decorator");
    let (padded_idx, _) = deserialized_decorators[0];

    // Get the operation at the decorator's index
    let op_at_decorator = deserialized_node.operations().nth(padded_idx).unwrap();
    assert!(
        matches!(op_at_decorator, Operation::Push(_)),
        "Decorator should point to PUSH operation"
    );
}

// RAW VS BATCHED CONSTRUCTION EQUIVALENCE TESTS
// ================================================================================================

/// Tests that Raw and Batched construction paths produce semantically equivalent nodes.
///
/// This test verifies that a node constructed from raw operations and then deserialized
/// (which uses the Batched path) produces the same semantic result.
#[test]
fn test_raw_vs_batched_construction_equivalence() {
    let mut forest1 = MastForest::new();
    let mut forest2 = MastForest::new();

    let decorator_id1 = forest1.add_decorator(Decorator::Trace(1)).unwrap();
    let _ = forest2.add_decorator(Decorator::Trace(1)).unwrap();

    let operations = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(Felt::new_unchecked(100)),
        Operation::Drop,
    ];

    // Path 1: Raw construction
    let block_id1 = BasicBlockNodeBuilder::new(operations, vec![(2, decorator_id1)])
        .add_to_forest(&mut forest1)
        .unwrap();

    // Path 2: Serialize and deserialize (uses Batched construction)
    let serialized = forest1.to_bytes();
    let _deserialized_forest = MastForest::read_from_bytes(&serialized).unwrap();

    // Manually construct using Batched path to test directly
    let original_node = forest1[block_id1].unwrap_basic_block();
    let op_batches = original_node.op_batches().to_vec();
    let digest = original_node.digest();
    let decorators: Vec<_> = original_node.indexed_decorator_iter(&forest1).collect();

    let block_id2 = BasicBlockNodeBuilder::from_op_batches(op_batches, decorators, digest)
        .add_to_forest(&mut forest2)
        .unwrap();

    // Verify nodes are semantically equivalent
    let node1 = forest1[block_id1].unwrap_basic_block();
    let node2 = forest2[block_id2].unwrap_basic_block();

    // Check operations match
    let ops1: Vec<_> = node1.operations().collect();
    let ops2: Vec<_> = node2.operations().collect();
    assert_eq!(ops1, ops2, "Operations should match");

    // Check OpBatch structure matches
    assert_eq!(node1.op_batches(), node2.op_batches(), "OpBatch structures should match");

    // Check digest matches
    assert_eq!(node1.digest(), node2.digest(), "Digests should match");

    // Check decorators match
    let decorators1: Vec<_> = node1.indexed_decorator_iter(&forest1).collect();
    let decorators2: Vec<_> = node2.indexed_decorator_iter(&forest2).collect();
    assert_eq!(decorators1, decorators2, "Decorators should match");
}

/// Tests that Raw and Batched construction produce the same digest.
#[test]
fn test_raw_batched_digest_equivalence() {
    let operations = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(Felt::new_unchecked(42)),
        Operation::Drop,
        Operation::Dup0,
    ];

    // Construct via Raw path
    let mut forest1 = MastForest::new();
    let block_id1 = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut forest1)
        .unwrap();
    let digest1 = forest1[block_id1].unwrap_basic_block().digest();

    // Construct via Batched path (via serialization round-trip)
    let serialized = forest1.to_bytes();
    let deserialized = MastForest::read_from_bytes(&serialized).unwrap();
    let digest2 = deserialized[block_id1].unwrap_basic_block().digest();

    assert_eq!(digest1, digest2, "Digests from Raw and Batched paths should match");
}

/// Tests that Batched construction preserves the exact OpBatch structure.
///
/// This verifies that the Batched path doesn't inadvertently re-batch operations.
#[test]
fn test_batched_construction_preserves_structure() {
    let mut forest = MastForest::new();

    let operations = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(Felt::new_unchecked(100)),
        Operation::Push(Felt::new_unchecked(200)),
    ];

    let block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    // Get the OpBatches from the original node
    let original_node = forest[block_id].unwrap_basic_block();
    let original_batches = original_node.op_batches().to_vec();
    let original_digest = original_node.digest();

    // Construct a new node using the Batched path
    let mut forest2 = MastForest::new();
    let block_id2 = BasicBlockNodeBuilder::from_op_batches(
        original_batches.clone(),
        Vec::new(),
        original_digest,
    )
    .add_to_forest(&mut forest2)
    .unwrap();

    // Verify the OpBatch structure is exactly preserved
    let new_node = forest2[block_id2].unwrap_basic_block();
    assert_eq!(
        original_batches,
        new_node.op_batches(),
        "OpBatch structure should be exactly preserved"
    );
}

// PROPTEST-BASED ROUND-TRIP SERIALIZATION TESTS
// ================================================================================================

fn assert_header_flags(bytes: &[u8], expected_flags: u8) {
    assert_eq!(&bytes[0..4], b"MAST", "Magic should be MAST");
    assert_eq!(bytes[4], expected_flags, "unexpected serialization flags");
    assert_eq!(&bytes[5..8], &[0, 0, 4], "Version should be [0, 0, 4]");
}

#[test]
fn test_header_flags_for_all_serialization_modes() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    assert_header_flags(&forest.to_bytes(), 0x00);

    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);
    assert_header_flags(&stripped_bytes, 0x01);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);
    assert_header_flags(&hashless_bytes, 0x03);
}

/// Test that legacy version headers are rejected.
#[test]
fn test_legacy_version_is_rejected() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut bytes = forest.to_bytes();
    bytes[5..8].copy_from_slice(&[0, 0, 2]);

    let result = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("Unsupported version")
    );
}

/// Test that stripping and hashless serialization reduce wire size monotonically.
#[test]
fn test_serialization_sizes_shrink_from_full_to_stripped_to_hashless() {
    let mut forest = MastForest::new();

    let decorator_id = forest.add_decorator(Decorator::Trace(42)).unwrap();
    let operations = vec![Operation::Add, Operation::Mul, Operation::Drop];
    let block_id = BasicBlockNodeBuilder::new(operations, vec![(0, decorator_id)])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let digest = forest[block_id].digest();
    forest.insert_procedure_name(digest, "test_proc".into());

    let full_bytes = forest.to_bytes();

    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let full_view = SerializedMastForest::new(&full_bytes).unwrap();
    assert!(!full_view.is_stripped());
    assert!(!full_view.is_hashless());
    assert_eq!(full_view.node_count(), forest.num_nodes() as usize);
    assert_eq!(full_view.procedure_root_count(), 1);
    assert!(full_view.node_info_at(0).is_ok());

    assert!(
        stripped_bytes.len() < full_bytes.len(),
        "Stripped ({} bytes) should be smaller than full ({} bytes)",
        stripped_bytes.len(),
        full_bytes.len()
    );
    assert!(
        hashless_bytes.len() < stripped_bytes.len(),
        "Hashless ({} bytes) should be smaller than stripped ({} bytes)",
        hashless_bytes.len(),
        stripped_bytes.len()
    );

    let stripped_view = SerializedMastForest::new(&stripped_bytes).unwrap();
    let hashless_view = SerializedMastForest::new(&hashless_bytes).unwrap();
    assert!(stripped_view.node_hash_offset().is_some());
    assert!(hashless_view.node_hash_offset().is_none());
}

fn assert_stripped_size_hint_matches_serialized_len(forest: &MastForest) {
    let mut bytes = Vec::new();
    forest.write_stripped(&mut bytes);
    assert_eq!(forest.stripped_size_hint(), bytes.len());
}

/// Test that stripped size hints stay exact for both compact and large forests.
#[test]
fn test_stripped_size_hint_matches_serialized_len() {
    let mut small_forest = MastForest::new();

    let block1 =
        BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Push(Felt::new(3))], Vec::new())
            .add_to_forest(&mut small_forest)
            .unwrap();
    let block2 = BasicBlockNodeBuilder::new(
        vec![Operation::U32div, Operation::Assert(Felt::new(1))],
        Vec::new(),
    )
    .add_to_forest(&mut small_forest)
    .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut small_forest).unwrap();
    small_forest.make_root(join);
    small_forest.advice_map_mut().insert(Word::default(), vec![ONE, Felt::new(2)]);
    assert_stripped_size_hint_matches_serialized_len(&small_forest);

    let mut forest = MastForest::new();

    let mut operations = Vec::with_capacity(304);
    for _ in 0..300 {
        operations.push(Operation::Add);
    }
    operations.push(Operation::Push(Felt::new(7)));
    operations.push(Operation::Assert(Felt::new(9)));
    operations.push(Operation::U32assert2(Felt::new(11)));
    operations.push(Operation::MpVerify(Felt::new(13)));

    let block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let key_a = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let key_b = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);

    let values_a: Vec<Felt> = (0..200).map(|i| Felt::new(i as u64)).collect();
    let values_b: Vec<Felt> = (0..5).map(|i| Felt::new((i + 10) as u64)).collect();

    forest.advice_map_mut().insert(key_a, values_a);
    forest.advice_map_mut().insert(key_b, values_b);

    assert_stripped_size_hint_matches_serialized_len(&forest);
}

/// Test that node digests are preserved in stripped serialization.
#[test]
fn test_stripped_preserves_digests() {
    let mut forest = MastForest::new();

    let decorator_id = forest.add_decorator(Decorator::Trace(1)).unwrap();

    let block1_id = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![(0, decorator_id)])
        .add_to_forest(&mut forest)
        .unwrap();
    let block2_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let join_id = JoinNodeBuilder::new([block1_id, block2_id]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join_id);

    // Capture original digests
    let original_digests: Vec<_> = forest.nodes().iter().map(MastNodeExt::digest).collect();

    // Stripped roundtrip
    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);
    let restored = MastForest::read_from_bytes(&stripped_bytes).unwrap();

    // Verify digests match
    let restored_digests: Vec<_> = restored.nodes().iter().map(MastNodeExt::digest).collect();
    assert_eq!(original_digests, restored_digests, "Node digests should be preserved");
}

/// Test that deserialization rejects unknown flags.
#[test]
fn test_deserialize_rejects_unknown_flags() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut bytes = forest.to_bytes();

    // Set an unknown flag (bit 2)
    bytes[4] = 0x04;

    let result = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("reserved") || msg.contains("flags")
    );
}

/// Test that trusted deserialization rejects hashless inputs.
#[test]
fn test_trusted_rejects_hashless() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let result = MastForest::read_from_bytes(&hashless_bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS")
    );
}

#[test]
fn test_trusted_rejects_truncated_hashless_before_layout_scan() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);
    hashless_bytes.truncate(8);

    let result = MastForest::read_from_bytes(&hashless_bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS")
    );
}

/// Test that hashless without stripped is rejected.
#[test]
fn test_hashless_requires_stripped() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut bytes = forest.to_bytes();
    // Set HASHLESS without STRIPPED
    bytes[4] = 0x02;

    let result = UntrustedMastForest::read_from_bytes(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS") && msg.contains("STRIPPED")
    );
}

fn assert_untrusted_overspec_logging(
    bytes: &[u8],
    expected_flags: u8,
    expected_nodes: u32,
    expected_log_fragments: &[&str],
) {
    let (result, logs) =
        with_captured_error_logs(|| UntrustedMastForest::read_from_bytes_with_flags(bytes));

    let (untrusted, flags) = result.unwrap();
    assert_eq!(flags, expected_flags);
    assert_eq!(logs.len(), expected_log_fragments.len());
    for expected in expected_log_fragments {
        assert!(logs.iter().any(|msg| msg.contains(expected)));
    }
    assert_eq!(untrusted.validate().unwrap().num_nodes(), expected_nodes);

    let (budgeted, budgeted_flags) =
        UntrustedMastForest::read_from_bytes_with_budget_and_flags(bytes, bytes.len()).unwrap();
    assert_eq!(budgeted_flags, expected_flags);
    assert_eq!(budgeted.validate().unwrap().num_nodes(), expected_nodes);
}

#[test]
fn test_untrusted_overspecification_logging_matches_wire_mode() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);
    assert_untrusted_overspec_logging(&hashless_bytes, 0x03, forest.num_nodes(), &[]);

    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);
    assert_untrusted_overspec_logging(
        &stripped_bytes,
        0x01,
        forest.num_nodes(),
        &["wire node hashes"],
    );

    forest.insert_procedure_name(forest[block_id].digest(), "test".into());
    let bytes = forest.to_bytes();
    assert_untrusted_overspec_logging(
        &bytes,
        0x00,
        forest.num_nodes(),
        &["wire node hashes", "DebugInfo"],
    );
}

/// Test that untrusted validation in hashless mode recomputes non-external digests without any
/// general wire hash section.
#[test]
fn test_untrusted_hashless_validate_recomputes_without_wire_hash_section() {
    let mut forest = MastForest::new();
    let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);

    let expected_digests: Vec<_> = forest.nodes().iter().map(|node| node.digest()).collect();

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let (untrusted, flags) =
        UntrustedMastForest::read_from_bytes_with_flags(&hashless_bytes).unwrap();
    assert_eq!(flags, 0x03);

    let validated = untrusted.validate().unwrap();
    let validated_digests: Vec<_> = validated.nodes().iter().map(|node| node.digest()).collect();
    assert_eq!(validated_digests, expected_digests);
}

/// Test that untrusted hashless deserialization accepts external nodes at parse time.
#[test]
fn test_untrusted_hashless_external_parse_and_validate() {
    let mut forest = MastForest::new();
    let external = ExternalNodeBuilder::new(Word::new([
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
    ]))
    .add_to_forest(&mut forest)
    .unwrap();
    forest.make_root(external);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let (untrusted, flags) =
        UntrustedMastForest::read_from_bytes_with_flags(&hashless_bytes).unwrap();
    assert_eq!(flags, 0x03, "hashless untrusted path should preserve wire mode");
    assert_eq!(untrusted.validate().unwrap().num_nodes(), 1);
}

mod proptests {
    use proptest::{prelude::*, strategy::Just};

    use super::*;
    use crate::{
        mast::{BasicBlockNodeBuilder, MastForest, MastNode, arbitrary::MastForestParams},
        operations::Decorator,
    };

    proptest! {
        /// Property test: any MastForest should round-trip through serialization
        #[test]
        fn proptest_mast_forest_roundtrip(
            forest in any_with::<MastForest>(MastForestParams {
                decorators: 5,
                blocks: 1..=5,
                max_joins: 3,
                max_splits: 2,
                max_loops: 2,
                max_calls: 2,
                max_syscalls: 0, // Avoid syscalls in roundtrip tests
                max_externals: 1,
                max_dyns: 1,
            })
        ) {
            // Serialize
            let serialized = forest.to_bytes();

            // Deserialize
            let deserialized = MastForest::read_from_bytes(&serialized)
                .expect("Deserialization should succeed");

            // Verify node count
            prop_assert_eq!(
                forest.num_nodes(),
                deserialized.num_nodes(),
                "Node count should match"
            );

            // Verify all nodes match
            for (idx, original) in forest.nodes().iter().enumerate() {
                let node_id = MastNodeId::new_unchecked(idx as u32);
                let deserialized_node = &deserialized[node_id];

                // Check digests match
                prop_assert_eq!(
                    original.digest(),
                    deserialized_node.digest(),
                    "Node {:?} digest mismatch", node_id
                );

                // For basic blocks, verify OpBatch structure and decorators are preserved
                if let MastNode::Block(original_block) = original
                    && let MastNode::Block(deserialized_block) = deserialized_node
                {
                    prop_assert_eq!(
                        original_block.op_batches(),
                        deserialized_block.op_batches(),
                        "Node {:?}: OpBatch mismatch", node_id
                    );

                    let orig_decorators: Vec<_> =
                        original_block.indexed_decorator_iter(&forest).collect();
                    let deser_decorators: Vec<_> =
                        deserialized_block.indexed_decorator_iter(&deserialized).collect();

                    prop_assert_eq!(
                        orig_decorators.len(),
                        deser_decorators.len(),
                        "Node {:?}: Decorator count mismatch", node_id
                    );

                    for ((orig_idx, orig_dec_id), (deser_idx, deser_dec_id)) in
                        orig_decorators.iter().zip(&deser_decorators)
                    {
                        prop_assert_eq!(orig_idx, deser_idx, "Node {:?}: Decorator index mismatch", node_id);
                        prop_assert_eq!(
                            forest.decorator_by_id(*orig_dec_id),
                            deserialized.decorator_by_id(*deser_dec_id),
                            "Node {:?}: Decorator content mismatch", node_id
                        );
                    }
                }

            }
        }

        /// Property test: multi-batch basic blocks should preserve exact structure
        #[test]
        fn proptest_multi_batch_roundtrip(
            ops in prop::collection::vec(
                prop::sample::select(vec![
                    Operation::Add,
                    Operation::Mul,
                    Operation::Push(Felt::new_unchecked(42)),
                    Operation::Drop,
                    Operation::Dup0,
                    Operation::Swap,
                ]),
                73..=150  // Generate 73-150 operations for multi-batch testing
            )
        ) {
            // Create a forest and add the block
            let mut forest = MastForest::new();

            let block_id = BasicBlockNodeBuilder::new(ops, Vec::new())
                .add_to_forest(&mut forest)
                .unwrap();

            let original_block = forest[block_id].unwrap_basic_block();
            let original_batches = original_block.op_batches();

            // Verify we have multiple batches
            prop_assume!(original_batches.len() > 1, "Need multiple batches for this test");

            // Serialize and deserialize
            let serialized = forest.to_bytes();
            let deserialized_forest = MastForest::read_from_bytes(&serialized)
                .expect("Deserialization should succeed");

            let deserialized_block = deserialized_forest[block_id].unwrap_basic_block();
            let deserialized_batches = deserialized_block.op_batches();

            // Verify batch count
            prop_assert_eq!(
                original_batches.len(),
                deserialized_batches.len(),
                "Batch count should match"
            );

            // Verify every batch field matches exactly
            for (i, (orig_batch, deser_batch)) in
                original_batches.iter().zip(deserialized_batches).enumerate()
            {
                prop_assert_eq!(
                    orig_batch.ops(),
                    deser_batch.ops(),
                    "Batch {}: Operations should match exactly", i
                );
                prop_assert_eq!(
                    orig_batch.indptr(),
                    deser_batch.indptr(),
                    "Batch {}: Indptr arrays should match exactly", i
                );
                prop_assert_eq!(
                    orig_batch.padding(),
                    deser_batch.padding(),
                    "Batch {}: Padding metadata should match exactly", i
                );
                prop_assert_eq!(
                    orig_batch.groups(),
                    deser_batch.groups(),
                    "Batch {}: Groups arrays should match exactly", i
                );
                prop_assert_eq!(
                    orig_batch.num_groups(),
                    deser_batch.num_groups(),
                    "Batch {}: num_groups should match exactly", i
                );
            }
        }

        /// Property test: basic blocks with decorators should preserve decorator indices
        #[test]
        fn proptest_decorator_indices_roundtrip(
            (ops, decorator_indices) in (
                prop::collection::vec(
                    prop::sample::select(vec![
                        Operation::Add,
                        Operation::Mul,
                        Operation::Push(Felt::new_unchecked(99)),
                        Operation::Drop,
                        Operation::Dup0,
                    ]),
                    10..=50
                )
            ).prop_flat_map(|ops| {
                let ops_len = ops.len();
                (
                    Just(ops),
                    prop::collection::vec((0..ops_len, 0..5_u32), 1..=10)
                )
            })
        ) {
            // Create a forest and add decorators
            let mut forest = MastForest::new();
            let decorator_id1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
            let decorator_id2 = forest.add_decorator(Decorator::Trace(2)).unwrap();
            let decorator_id3 = forest.add_decorator(Decorator::Trace(3)).unwrap();
            let decorator_id4 = forest.add_decorator(Decorator::Trace(4)).unwrap();
            let decorator_id5 = forest.add_decorator(Decorator::Trace(5)).unwrap();
            let decorator_ids = [decorator_id1, decorator_id2, decorator_id3, decorator_id4, decorator_id5];

            // Map indices to actual decorator IDs and sort by index
            let mut decorators: Vec<(usize, _)> = decorator_indices
                .into_iter()
                .map(|(idx, dec_id_idx)| (idx, decorator_ids[dec_id_idx as usize]))
                .collect();
            decorators.sort_by_key(|(idx, _)| *idx);
            decorators.dedup_by_key(|(idx, _)| *idx);  // Remove duplicates

            let block_id = BasicBlockNodeBuilder::new(ops, decorators)
                .add_to_forest(&mut forest)
                .unwrap();

            let original_block = forest[block_id].unwrap_basic_block();

            // Serialize and deserialize
            let serialized = forest.to_bytes();
            let deserialized_forest = MastForest::read_from_bytes(&serialized)
                .expect("Deserialization should succeed");

            let deserialized_block = deserialized_forest[block_id].unwrap_basic_block();

            // Verify decorator indices and content match
            let orig_decorators: Vec<_> =
                original_block.indexed_decorator_iter(&forest).collect();
            let deser_decorators: Vec<_> =
                deserialized_block.indexed_decorator_iter(&deserialized_forest).collect();

            prop_assert_eq!(
                orig_decorators.len(),
                deser_decorators.len(),
                "Decorator count should match"
            );

            for ((orig_idx, orig_dec_id), (deser_idx, deser_dec_id)) in
                orig_decorators.iter().zip(&deser_decorators)
            {
                prop_assert_eq!(
                    orig_idx,
                    deser_idx,
                    "Decorator indices should match (padded form)"
                );

                prop_assert_eq!(
                    forest.decorator_by_id(*orig_dec_id),
                    deserialized_forest.decorator_by_id(*deser_dec_id),
                    "Decorator content should match"
                );
            }
        }

        /// Property test: stripped serialization should preserve node structure
        #[test]
        fn proptest_stripped_roundtrip(
            forest in any_with::<MastForest>(MastForestParams {
                decorators: 10,
                blocks: 1..=5,
                max_joins: 3,
                max_splits: 2,
                max_loops: 2,
                max_calls: 2,
                max_syscalls: 0,
                max_externals: 1,
                max_dyns: 1,
            })
        ) {
            // Stripped serialization
            let mut stripped_bytes = Vec::new();
            forest.write_stripped(&mut stripped_bytes);

            // Deserialize
            let restored = MastForest::read_from_bytes(&stripped_bytes)
                .expect("Stripped deserialization should succeed");

            // Verify node count matches
            prop_assert_eq!(
                forest.num_nodes(),
                restored.num_nodes(),
                "Node count should match"
            );

            // Verify all node digests match
            for (idx, original) in forest.nodes().iter().enumerate() {
                let node_id = MastNodeId::new_unchecked(idx as u32);
                let restored_node = &restored[node_id];

                prop_assert_eq!(
                    original.digest(),
                    restored_node.digest(),
                    "Node {:?} digest mismatch", node_id
                );
            }

            // Verify debug info is empty
            prop_assert!(
                restored.debug_info.is_empty(),
                "DebugInfo should be empty after stripped roundtrip"
            );
        }
    }
}

// COMPREHENSIVE DEBUGINFO ROUND-TRIP TESTS
// ================================================================================================

/// Test DebugInfo serialization with empty decorators (no decorators at all)
#[test]
fn test_debuginfo_serialization_empty() {
    // Create forest with no decorators
    let mut forest = MastForest::new();

    // Add a simple basic block with no decorators
    let ops = vec![Operation::Noop; 4];
    let block_id = BasicBlockNodeBuilder::new(ops, Vec::new()).add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);

    // Serialize and deserialize
    let bytes = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&bytes).unwrap();

    // Verify
    assert_eq!(forest.num_nodes(), deserialized.num_nodes());
    assert_eq!(forest.decorators().len(), 0);
    assert_eq!(deserialized.decorators().len(), 0);
}

/// Test DebugInfo serialization with sparse decorators (20% of nodes have decorators)
#[test]
fn test_debuginfo_serialization_sparse() {
    let mut forest = MastForest::new();

    // Create 10 blocks, only 2 with decorators (20% sparse)
    for i in 0..10 {
        let ops = vec![Operation::Noop; 4];

        if i % 5 == 0 {
            // Add decorator at position 0 for nodes 0 and 5
            let decorator_id = forest.add_decorator(Decorator::Trace(i)).unwrap();
            BasicBlockNodeBuilder::new(ops, vec![(0, decorator_id)])
                .add_to_forest(&mut forest)
                .unwrap();
        } else {
            BasicBlockNodeBuilder::new(ops, Vec::new()).add_to_forest(&mut forest).unwrap();
        }
    }

    // Serialize and deserialize
    let bytes = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&bytes).unwrap();

    // Verify decorator count
    assert_eq!(forest.decorators().len(), 2);
    assert_eq!(deserialized.decorators().len(), 2);

    // Verify decorators are at correct nodes
    for i in 0..10 {
        let node_id = MastNodeId::new_unchecked(i);
        let orig_decorators = forest.decorator_indices_for_op(node_id, 0);
        let deser_decorators = deserialized.decorator_indices_for_op(node_id, 0);

        assert_eq!(orig_decorators, deser_decorators, "Decorators at node {i} should match");
    }
}

/// Test DebugInfo serialization with dense decorators (80% of nodes have decorators)
#[test]
fn test_debuginfo_serialization_dense() {
    let mut forest = MastForest::new();

    // Create 10 blocks, 8 with decorators (80% dense)
    for i in 0..10 {
        let ops = vec![Operation::Noop; 4];

        if i < 8 {
            // Add decorator at position 0 for first 8 nodes
            let decorator_id = forest.add_decorator(Decorator::Trace(i)).unwrap();
            BasicBlockNodeBuilder::new(ops, vec![(0, decorator_id)])
                .add_to_forest(&mut forest)
                .unwrap();
        } else {
            BasicBlockNodeBuilder::new(ops, Vec::new()).add_to_forest(&mut forest).unwrap();
        }
    }

    // Serialize and deserialize
    let bytes = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&bytes).unwrap();

    // Verify decorator count
    assert_eq!(forest.decorators().len(), 8);
    assert_eq!(deserialized.decorators().len(), 8);

    // Verify decorators are at correct nodes
    for i in 0..10 {
        let node_id = MastNodeId::new_unchecked(i);
        let orig_decorators = forest.decorator_indices_for_op(node_id, 0);
        let deser_decorators = deserialized.decorator_indices_for_op(node_id, 0);

        assert_eq!(orig_decorators, deser_decorators, "Decorators at node {i} should match");

        // Verify expected decorator presence
        if i < 8 {
            assert_eq!(orig_decorators.len(), 1, "Node {i} should have 1 decorator");
            assert_eq!(
                deser_decorators.len(),
                1,
                "Node {i} should have 1 decorator after deserialization"
            );
        } else {
            assert_eq!(orig_decorators.len(), 0, "Node {i} should have no decorators");
            assert_eq!(
                deser_decorators.len(),
                0,
                "Node {i} should have no decorators after deserialization"
            );
        }
    }
}

// UNTRUSTED MAST FOREST VALIDATION TESTS
// ================================================================================================

/// Test that UntrustedMastForest::validate detects forward references.
#[test]
fn test_untrusted_forest_detects_forward_reference() {
    // Create a forest with forward references by swapping node order
    let mut forest = MastForest::new();
    let zero = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32and], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    JoinNodeBuilder::new([first, second]).add_to_forest(&mut forest).unwrap();

    // Swap the Join node (index 3) with the first basic block (index 0)
    // This creates a forest where Join(1, 2) is at index 0, referencing nodes 1 and 2
    // which are forward references
    forest.nodes.swap_remove(zero.to_usize());

    // Serialize the corrupted forest
    let bytes = forest.to_bytes();

    // Deserialize as untrusted and try to validate
    let untrusted = UntrustedMastForest::read_from_bytes(&bytes).unwrap();
    let result = untrusted.validate();

    assert_matches!(result, Err(MastForestError::ForwardReference(_, _)));
}

#[test]
fn test_untrusted_forest_remaps_procedure_names_after_hash_recompute() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);
    let expected_digest = forest[block_id].digest();
    forest.insert_procedure_name(expected_digest, "proc".into());

    let bytes = forest.to_bytes();
    let view = SerializedMastForest::new(&bytes).unwrap();
    let digest_offset = node_hash_digest_offset(&view, block_id.to_usize());
    let bogus_digest: Word = [Felt::new(9), Felt::new(8), Felt::new(7), Felt::new(6)].into();

    let mut corrupted =
        rewrite_debug_info_procedure_name_digest(&bytes, expected_digest, bogus_digest);
    bogus_digest.write_into(
        &mut &mut corrupted[digest_offset..digest_offset + Word::min_serialized_size()],
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&corrupted).unwrap();
    let validated = untrusted.validate().unwrap();

    assert_eq!(validated[block_id].digest(), expected_digest);
    assert_eq!(validated.procedure_name(&expected_digest), Some("proc"));
    assert_eq!(validated.debug_info().num_procedure_names(), 1);
}

#[test]
fn test_untrusted_forest_keeps_procedure_names_when_only_wire_root_hash_is_corrupted() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);
    let expected_digest = forest[block_id].digest();
    forest.insert_procedure_name(expected_digest, "proc".into());

    let bytes = forest.to_bytes();
    let view = SerializedMastForest::new(&bytes).unwrap();
    let digest_offset = node_hash_digest_offset(&view, block_id.to_usize());
    let bogus_digest: Word = [Felt::new(9), Felt::new(8), Felt::new(7), Felt::new(6)].into();

    let mut corrupted = bytes.clone();
    bogus_digest.write_into(
        &mut &mut corrupted[digest_offset..digest_offset + Word::min_serialized_size()],
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&corrupted).unwrap();
    let validated = untrusted.validate().unwrap();

    assert_eq!(validated[block_id].digest(), expected_digest);
    assert_eq!(validated.procedure_name(&expected_digest), Some("proc"));
    assert_eq!(validated.debug_info().num_procedure_names(), 1);
}

#[test]
fn test_untrusted_forest_preserves_incoming_root_resolution_on_digest_collision() {
    let mut forest = MastForest::new();
    let left_root = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let right_root = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(left_root);
    forest.make_root(right_root);

    let left_digest = forest[left_root].digest();
    let right_digest = forest[right_root].digest();
    forest.insert_procedure_name(right_digest, "right".into());

    let bytes = forest.to_bytes();
    let view = SerializedMastForest::new(&bytes).unwrap();
    let left_digest_offset = node_hash_digest_offset(&view, left_root.to_usize());

    let mut corrupted = bytes.clone();
    right_digest.write_into(
        &mut &mut corrupted[left_digest_offset..left_digest_offset + Word::min_serialized_size()],
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&corrupted).unwrap();
    let validated = untrusted.validate().unwrap();

    assert_eq!(validated[left_root].digest(), left_digest);
    assert_eq!(validated[right_root].digest(), right_digest);
    assert_eq!(validated.procedure_name(&left_digest), Some("right"));
    assert_eq!(validated.procedure_name(&right_digest), None);
}

// UNTRUSTED VALIDATION TEST HELPERS
// --------------------------------------------------------------------------------------------

/// Build a packed operation group from op codes.
fn build_group(ops: &[Operation]) -> Felt {
    let mut group = 0u64;
    for (i, op) in ops.iter().enumerate() {
        group |= (op.op_code() as u64) << (Operation::OP_BITS * i);
    }
    Felt::new_unchecked(group)
}

fn make_batch(num_groups: usize, op: Operation) -> OpBatch {
    let ops: Vec<Operation> = (0..num_groups).map(|_| op).collect();
    let mut indptr = [0usize; OP_BATCH_SIZE + 1];

    for i in 0..num_groups {
        indptr[i + 1] = i + 1;
    }
    for i in (num_groups + 1)..=OP_BATCH_SIZE {
        indptr[i] = indptr[i - 1];
    }

    // Only the prefix [0..num_groups] is semantically valid; mark unused entries padded.
    let mut padding = [false; OP_BATCH_SIZE];
    for pad in padding.iter_mut().skip(num_groups) {
        *pad = true;
    }
    let mut groups = [Felt::new_unchecked(0); OP_BATCH_SIZE];
    for group in groups.iter_mut().take(num_groups) {
        *group = build_group(&[op]);
    }

    OpBatch::new_from_parts(ops, indptr, padding, groups, num_groups)
}

fn build_malicious_single_block_forest_bytes(push_imm: Felt) -> Vec<u8> {
    // Build a minimal forest containing a single basic-block procedure root.
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(
        vec![Operation::Push(push_imm), Operation::Noop, Operation::Add],
        Vec::new(),
    )
    .add_to_forest(&mut forest)
    .unwrap();
    forest.make_root(block_id);

    // Serialize using the standard format.
    let mut bytes = forest.to_bytes();

    // Patch the batch indptr metadata inside basic_block_data to a malformed layout which causes
    // the decoder to overwrite the `Push` immediate slot with a later opcode group.
    //
    // Desired indptr after unpacking: [0, 2, 3, 3, 3, 3, 3, 3, 3]
    // Deltas: [2, 1, 0, 0, 0, 0, 0, 0] -> packed nibbles: 0x12, 0x00, 0x00, 0x00.
    let malicious_packed_indptr = [0x12, 0x00, 0x00, 0x00];

    let (indptr_offset, digest_offset) = locate_single_block_indptr_and_digest_offsets(&bytes);

    // Sanity-check that the original indptr matches the honest encoding for this block.
    // Honest indptr is [0, 3, 3, 3, 3, 3, 3, 3, 3] -> deltas [3, 0, 0, 0, 0, 0, 0, 0] -> 0x03.
    assert_eq!(
        &bytes[indptr_offset..indptr_offset + 4],
        &[0x03, 0x00, 0x00, 0x00],
        "unexpected original packed indptr (offset computation likely wrong)"
    );

    bytes[indptr_offset..indptr_offset + 4].copy_from_slice(&malicious_packed_indptr);

    // Recompute the correct digest for the now-malformed decoding and patch it into the node-hash
    // section, so that `UntrustedMastForest::validate()` will accept it if the issue exists.
    if let Some(digest) = compute_single_block_digest_from_decoded_groups(&bytes) {
        bytes[digest_offset..digest_offset + 32].copy_from_slice(&digest.to_bytes());
    }

    bytes
}

struct OffsetReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> OffsetReader<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self { source, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }
}

impl ByteReader for OffsetReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let result = self.source[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let result = &self.source[self.pos..self.pos + len];
        self.pos += len;
        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(result)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        if self.pos + num_bytes > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        Ok(())
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}

fn locate_single_block_indptr_and_digest_offsets(bytes: &[u8]) -> (usize, usize) {
    // Parse the MastForest wire format, but track offsets so we can patch in-place.
    // We assume the forest contains exactly 1 node which is a Block node.
    let mut cursor = OffsetReader::new(bytes);

    // header: MAGIC (4) + FLAGS (1) + VERSION (3)
    let _header: [u8; 8] = cursor.read_array().unwrap();

    let node_count: usize = cursor.read().unwrap();
    assert_eq!(node_count, 1);

    let _decorator_count: usize = cursor.read().unwrap();
    let _roots: Vec<u32> = Deserializable::read_from(&mut cursor).unwrap();

    // basic block data section: Vec<u8>
    let bb_data_len: usize = cursor.read().unwrap();
    let bb_payload_start = cursor.position();
    let bb_payload_end = bb_payload_start + bb_data_len;
    let view = SerializedMastForest::new(bytes).unwrap();
    let node_entries_start = view.node_entry_offset();

    // node entry: MastNodeType (8 bytes)
    let node_type_u64 = u64::from_le_bytes(
        bytes[node_entries_start..node_entries_start + 8]
            .try_into()
            .expect("node type bytes"),
    );
    let discriminant = (node_type_u64 >> 60) as u8;
    assert_eq!(discriminant, 3, "expected a Block node");

    let payload = node_type_u64 & 0x0f_ff_ff_ff_ff_ff_ff_ff;
    assert!(payload <= u32::MAX as u64, "Block ops_offset payload must fit in u32");
    let ops_offset = payload as usize;

    let digest_offset = view.node_hash_offset().unwrap();

    // Locate the start of the packed indptr for the first (and only) batch.
    let block_start = bb_payload_start + ops_offset;
    assert!(block_start < bb_payload_end);

    let mut block_cursor = OffsetReader::new(&bytes[block_start..bb_payload_end]);
    let _ops: Vec<Operation> = Deserializable::read_from(&mut block_cursor).unwrap();
    let num_batches: u32 = block_cursor.read().unwrap();
    assert_eq!(num_batches, 1);

    let indptr_offset = block_start + block_cursor.position();

    (indptr_offset, digest_offset)
}

fn compute_single_block_digest_from_decoded_groups(bytes: &[u8]) -> Option<Word> {
    use crate::chiplets::hasher;

    let forest = MastForest::read_from_bytes(bytes).ok()?;
    let block = forest[MastNodeId::new_unchecked(0)].unwrap_basic_block().clone();

    let op_groups: Vec<Felt> =
        block.op_batches().iter().flat_map(|batch| *batch.groups()).collect();

    Some(hasher::hash_elements(&op_groups))
}

/// Test that UntrustedMastForest::validate rejects a non-full batch before the last batch.
#[test]
fn test_untrusted_forest_rejects_non_full_prefix_batch() {
    let op_batches = vec![make_batch(4, Operation::Add), make_batch(2, Operation::Mul)];

    let op_groups: Vec<Felt> = op_batches.iter().flat_map(OpBatch::groups).copied().collect();
    let digest = hasher::hash_elements(&op_groups);

    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::from_op_batches(op_batches, Vec::new(), digest)
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let bytes = forest.to_bytes();
    let untrusted = UntrustedMastForest::read_from_bytes(&bytes).unwrap();
    let result = untrusted.validate();

    assert_matches!(result, Err(MastForestError::InvalidBatchPadding(_, _)));
}

/// Test that UntrustedMastForest::validate accepts full prefix batches and a power-of-two last.
#[test]
fn test_untrusted_forest_accepts_full_prefix_batch() {
    let op_batches = vec![make_batch(OP_BATCH_SIZE, Operation::Add), make_batch(4, Operation::Mul)];

    let op_groups: Vec<Felt> = op_batches.iter().flat_map(OpBatch::groups).copied().collect();
    let digest = hasher::hash_elements(&op_groups);

    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::from_op_batches(op_batches, Vec::new(), digest)
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let bytes = forest.to_bytes();
    let untrusted = UntrustedMastForest::read_from_bytes(&bytes).unwrap();
    let result = untrusted.validate();

    assert!(result.is_ok(), "full prefix batches should validate");
}

#[test]
fn test_untrusted_forest_rejects_basic_block_indptr_that_breaks_push_immediate_commitment() {
    // Two distinct immediates. Using large values reduces the chance of accidental equality with a
    // packed opcode group value.
    let imm_a = Felt::new_unchecked(0xdead_beef_dead_beef);
    let imm_b = Felt::new_unchecked(0xfeed_face_feed_face);

    let bytes_a = build_malicious_single_block_forest_bytes(imm_a);
    let bytes_b = build_malicious_single_block_forest_bytes(imm_b);

    let validated_a = match UntrustedMastForest::read_from_bytes(&bytes_a) {
        Ok(untrusted) => untrusted.validate(),
        Err(DeserializationError::InvalidValue(msg)) => {
            assert!(msg.contains("push immediate"));
            return;
        },
        Err(err) => panic!("unexpected deserialization error: {err:?}"),
    };
    let validated_b = match UntrustedMastForest::read_from_bytes(&bytes_b) {
        Ok(untrusted) => untrusted.validate(),
        Err(DeserializationError::InvalidValue(msg)) => {
            assert!(msg.contains("push immediate"));
            return;
        },
        Err(err) => panic!("unexpected deserialization error: {err:?}"),
    };

    // A fix may choose to reject this encoding at validation time. Either (or both) being `Err`
    // is an acceptable outcome: it prevents the commitment gap.
    let assert_expected_rejection = |result: Result<MastForest, MastForestError>| match result {
        Err(MastForestError::InvalidBatchPadding(_, msg)) => {
            assert!(msg.contains("push immediate"));
        },
        Err(MastForestError::Deserialization(DeserializationError::InvalidValue(msg))) => {
            assert!(msg.contains("push immediate"));
        },
        Err(err) => panic!("unexpected validation error: {err:?}"),
        Ok(_) => {},
    };

    let (forest_a, forest_b) = match (validated_a, validated_b) {
        (Ok(forest_a), Ok(forest_b)) => (forest_a, forest_b),
        (validated_a, validated_b) => {
            assert_expected_rejection(validated_a);
            assert_expected_rejection(validated_b);
            return;
        },
    };

    // If both validate successfully, then their digests must bind to their executed semantics.
    // Concretely: changing the `Push` immediate must change the committed digest.
    let block_a = forest_a[MastNodeId::new_unchecked(0)].unwrap_basic_block().clone();
    let block_b = forest_b[MastNodeId::new_unchecked(0)].unwrap_basic_block().clone();

    let ops_a: Vec<Operation> = block_a.operations().copied().collect();
    let ops_b: Vec<Operation> = block_b.operations().copied().collect();

    assert!(
        matches!(ops_a.as_slice(), [Operation::Push(v), ..] if *v == imm_a),
        "unexpected ops in forest_a: {ops_a:?}"
    );
    assert!(
        matches!(ops_b.as_slice(), [Operation::Push(v), ..] if *v == imm_b),
        "unexpected ops in forest_b: {ops_b:?}"
    );

    // If this assert fails, it demonstrates the issue: a `Push` immediate can be changed
    // without changing the basic-block digest and without failing untrusted validation.
    assert_ne!(
        block_a.digest(),
        block_b.digest(),
        "BUG: UntrustedMastForest::validate() accepted two basic blocks with different Push immediates \
         but identical digests.\n\
         digest={:?}\n\
         ops_a={ops_a:?}\n\
         ops_b={ops_b:?}\n\
         groups_a={:?}\n\
         groups_b={:?}\n",
        block_a.digest(),
        block_a.op_batches()[0].groups(),
        block_b.op_batches()[0].groups(),
    );
}

/// Test that UntrustedMastForest::validate succeeds for forests with all node types.
#[test]
fn test_untrusted_forest_validates_all_node_types() {
    let mut forest = MastForest::new();

    // Create basic blocks
    let block1_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    let block2_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();

    // Join node
    let join_id = JoinNodeBuilder::new([block1_id, block2_id]).add_to_forest(&mut forest).unwrap();

    // Split node
    let split_id = SplitNodeBuilder::new([block1_id, block2_id])
        .add_to_forest(&mut forest)
        .unwrap();

    // Loop node
    let loop_id = LoopNodeBuilder::new(block1_id).add_to_forest(&mut forest).unwrap();

    // Call node
    let call_id = CallNodeBuilder::new(block1_id).add_to_forest(&mut forest).unwrap();

    // Syscall node
    let syscall_id = CallNodeBuilder::new_syscall(block1_id).add_to_forest(&mut forest).unwrap();

    // Dyn node
    let dyn_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();

    // Dyncall node
    let dyncall_id = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();

    // External node (will be skipped in hash validation)
    let external_id = ExternalNodeBuilder::new(Word::default()).add_to_forest(&mut forest).unwrap();

    forest.make_root(join_id);
    forest.make_root(split_id);
    forest.make_root(loop_id);
    forest.make_root(call_id);
    forest.make_root(syscall_id);
    forest.make_root(dyn_id);
    forest.make_root(dyncall_id);
    forest.make_root(external_id);

    // Serialize
    let bytes = forest.to_bytes();

    // Deserialize as untrusted and validate
    let untrusted = UntrustedMastForest::read_from_bytes(&bytes).unwrap();
    let validated = untrusted.validate().unwrap();

    assert_eq!(forest, validated);
}

/// Test that UntrustedMastForest::validate works with stripped serialization.
#[test]
fn test_untrusted_forest_validates_stripped() {
    let mut forest = MastForest::new();

    let decorator_id = forest.add_decorator(Decorator::Trace(42)).unwrap();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], vec![(0, decorator_id)])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    // Serialize stripped (no debug info)
    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);

    // Deserialize as untrusted and validate
    let untrusted = UntrustedMastForest::read_from_bytes(&stripped_bytes).unwrap();
    let validated = untrusted.validate().unwrap();

    // Structure should be preserved, but debug info should be empty
    assert_eq!(forest.num_nodes(), validated.num_nodes());
    assert!(validated.debug_info.is_empty());
}

/// Test that deserialization rejects node counts exceeding MAX_NODES.
#[test]
fn test_deserialization_rejects_excessive_node_count() {
    // Craft a malicious payload with node_count exceeding MAX_NODES
    let mut bytes = Vec::new();

    // Write valid header
    MAGIC.write_into(&mut bytes);
    bytes.write_u8(0); // flags
    VERSION.write_into(&mut bytes);

    // Write excessive node count (MAX_NODES + 1)
    let excessive_count: usize = MastForest::MAX_NODES + 1;
    excessive_count.write_into(&mut bytes);

    // Write decorator count
    0usize.write_into(&mut bytes);

    // Attempt to deserialize - should fail before any large allocation
    let result = MastForest::read_from_bytes(&bytes);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("exceeds maximum"),
        "Expected error about exceeding maximum, got: {err}"
    );
}
