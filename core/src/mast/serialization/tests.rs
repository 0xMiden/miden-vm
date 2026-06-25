use core::assert_matches;
use std::{
    string::{String, ToString},
    sync::{Arc, Mutex, Once},
};

use super::*;
use crate::{
    Felt, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExecutableMastForest,
        ExternalNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForestContributor,
        MastForestError, MastForestView, MastNodeExt, MastNodeId, OP_BATCH_SIZE, OpBatch,
        SparseMastForest, SparseMastForestBuilder, SparseMastForestReadOptions, SplitNodeBuilder,
        UntrustedMastForest, UntrustedMastForestReadOptions, VisitKind,
    },
    operations::Operation,
    serde::{ByteReader, Deserializable, DeserializationError, Serializable, SliceReader},
    utils::Idx,
};

struct TestLogger {
    messages: Mutex<Vec<String>>,
}

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
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
    with_captured_logs(log::LevelFilter::Error, f)
}

fn with_captured_logs<T>(level: log::LevelFilter, f: impl FnOnce() -> T) -> (T, Vec<String>) {
    TEST_LOGGER_INIT.call_once(|| {
        log::set_logger(&TEST_LOGGER).expect("test logger should be installed once");
    });

    let _guard = TEST_LOGGER_GUARD.lock().unwrap();
    log::set_max_level(level);
    TEST_LOGGER.messages.lock().unwrap().clear();
    let result = f();
    let messages = TEST_LOGGER.messages.lock().unwrap().clone();
    (result, messages)
}

/// If this test fails to compile, it means that `Operation` was changed. Make sure
/// that all tests in this file are updated accordingly. For example, if a new `Operation` variant
/// was added, make sure that you add it in the vector of operations in
/// [`serialize_deserialize_all_nodes`].
#[test]
fn confirm_operation_structure() {
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
        assert_operation_encoded_size_matches_serialized_len(Operation::Push(Felt::new_unchecked(
            value,
        )));
    }
}

fn assert_serialized_view_matches_forest(forest: &MastForest) {
    let mut bytes = Vec::new();
    forest.write_into(&mut bytes);

    let view = MastForestWireView::new(&bytes).unwrap();
    assert_eq!(view.node_count(), forest.nodes().len());

    let mut bb_builder = BasicBlockDataBuilder::new();
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

    let block1 = BasicBlockNodeBuilder::new(vec![
        Operation::Push(Felt::new_unchecked(7)),
        Operation::Add,
        Operation::Mul,
    ])
    .add_to_forest(&mut forest)
    .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);
    let advice_key = Word::new([
        Felt::new_unchecked(11),
        Felt::new_unchecked(12),
        Felt::new_unchecked(13),
        Felt::new_unchecked(14),
    ]);
    let advice_values = vec![Felt::new_unchecked(15), Felt::new_unchecked(16)];
    forest.advice_map_mut().insert(advice_key, advice_values.clone());

    let mut bytes = Vec::new();
    forest.write_into(&mut bytes);
    let serialized = MastForestWireView::new(&bytes).unwrap();

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

    let in_memory_advice = in_memory.advice_map();
    let serialized_advice = serialized_view.advice_map();
    assert_eq!(in_memory_advice.len(), 1);
    assert_eq!(serialized_advice.len(), 1);
    assert!(in_memory_advice.contains_key(&advice_key));
    assert!(serialized_advice.contains_key(&advice_key));
    assert_eq!(
        in_memory_advice.get(&advice_key).unwrap().unwrap().as_ref(),
        advice_values.as_slice()
    );
    assert_eq!(
        serialized_advice.get(&advice_key).unwrap().unwrap().as_ref(),
        advice_values.as_slice()
    );

    let in_memory_infos = in_memory.all_node_infos().unwrap();
    let serialized_infos = serialized_view.all_node_infos().unwrap();
    assert_eq!(in_memory_infos.len(), serialized_infos.len());
    for (lhs, rhs) in in_memory_infos.iter().zip(serialized_infos.iter()) {
        assert_eq!(lhs.to_bytes(), rhs.to_bytes());
    }
}

#[test]
fn test_mast_forest_read_view_modes_match() {
    let mut forest = MastForest::new();
    let block = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::new_unchecked(3))])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block);

    let advice_key = Word::new([
        Felt::new_unchecked(21),
        Felt::new_unchecked(22),
        Felt::new_unchecked(23),
        Felt::new_unchecked(24),
    ]);
    let advice_values = vec![Felt::new_unchecked(25), Felt::new_unchecked(26)];
    forest.advice_map_mut().insert(advice_key, advice_values.clone());

    let mut bytes = Vec::new();
    forest.write_into(&mut bytes);

    let materialized =
        MastForest::read_view_from_bytes(&bytes, MastForestReadMode::Materialized).unwrap();
    let wire_backed =
        MastForest::read_view_from_bytes(&bytes, MastForestReadMode::WireBacked).unwrap();

    assert!(matches!(materialized, MastForestReadView::Materialized(_)));
    assert!(matches!(wire_backed, MastForestReadView::WireBacked(_)));
    assert_eq!(materialized.node_count(), wire_backed.node_count());
    assert_eq!(
        materialized.node_info_at(0).unwrap().to_bytes(),
        wire_backed.node_info_at(0).unwrap().to_bytes()
    );
    assert_eq!(materialized.procedure_roots().unwrap(), wire_backed.procedure_roots().unwrap());
    assert_eq!(
        materialized.advice_map().get(&advice_key).unwrap().unwrap().as_ref(),
        advice_values.as_slice()
    );
    assert_eq!(
        wire_backed.advice_map().get(&advice_key).unwrap().unwrap().as_ref(),
        advice_values.as_slice()
    );
}

#[test]
fn test_mast_forest_wire_view_random_access_all_node_types() {
    let mut forest = MastForest::new();

    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
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
fn test_mast_forest_wire_view_large_counts() {
    let mut forest = MastForest::new();
    let mut roots = Vec::new();

    for _ in 0..300 {
        let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        roots.push(block_id);
    }

    for root in roots.iter().take(200) {
        forest.make_root(*root);
    }

    assert_serialized_view_matches_forest(&forest);
}

fn node_hash_digest_offset(view: &MastForestWireView<'_>, node_index: usize) -> usize {
    let digest_slot = view.digest_slot_at(node_index);
    view.node_hash_offset().unwrap() + digest_slot * Word::min_serialized_size()
}

fn external_digest_offset(view: &MastForestWireView<'_>, node_index: usize) -> usize {
    let digest_slot = view.digest_slot_at(node_index);
    view.external_digest_offset() + digest_slot * Word::min_serialized_size()
}

fn read_word_at(bytes: &[u8], offset: usize) -> Word {
    let mut reader = SliceReader::new(&bytes[offset..offset + Word::min_serialized_size()]);
    Word::read_from(&mut reader).unwrap()
}

#[test]
fn test_mast_forest_wire_view_rejects_hashless() {
    let mut forest = MastForest::new();
    let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);
    let result = MastForestWireView::new(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS flag is set")
    );
}

#[test]
fn test_mast_forest_wire_view_rejects_hashless_external_nodes() {
    let mut forest = MastForest::new();
    let external_digest = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let external_id = ExternalNodeBuilder::new(external_digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(external_id);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);
    let result = MastForestWireView::new(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS flag is set")
    );
}

#[test]
fn test_mast_forest_wire_view_external_digests_are_ordered_by_node_index() {
    let mut forest = MastForest::new();
    let first = Word::new([
        Felt::new_unchecked(30),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]);
    let second = Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]);
    let third = Word::new([
        Felt::new_unchecked(20),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]);

    let first_id = ExternalNodeBuilder::new(first).add_to_forest(&mut forest).unwrap();
    let second_id = ExternalNodeBuilder::new(second).add_to_forest(&mut forest).unwrap();
    let third_id = ExternalNodeBuilder::new(third).add_to_forest(&mut forest).unwrap();
    forest.make_root(first_id);
    forest.make_root(second_id);
    forest.make_root(third_id);

    let bytes = forest.to_bytes();
    let view = MastForestWireView::new(&bytes).unwrap();

    assert_eq!(read_word_at(&bytes, view.external_digest_offset()), first);
    assert_eq!(
        read_word_at(&bytes, view.external_digest_offset() + Word::min_serialized_size()),
        second
    );
    assert_eq!(
        read_word_at(&bytes, view.external_digest_offset() + 2 * Word::min_serialized_size()),
        third
    );
    assert_eq!(view.node_digest_at(first_id.to_usize()).unwrap(), first);
    assert_eq!(view.node_digest_at(second_id.to_usize()).unwrap(), second);
    assert_eq!(view.node_digest_at(third_id.to_usize()).unwrap(), third);
    assert_eq!(read_word_at(&bytes, external_digest_offset(&view, first_id.to_usize())), first);
    assert_eq!(
        read_word_at(&bytes, external_digest_offset(&view, second_id.to_usize())),
        second
    );
    assert_eq!(read_word_at(&bytes, external_digest_offset(&view, third_id.to_usize())), third);
}

#[test]
fn test_untrusted_hashless_keeps_external_digests_by_node_index() {
    let mut forest = MastForest::new();
    let external_high = Word::new([
        Felt::new_unchecked(9),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]);
    let external_low = Word::new([
        Felt::new_unchecked(3),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]);

    let _block = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let high_id = ExternalNodeBuilder::new(external_high).add_to_forest(&mut forest).unwrap();
    let low_id = ExternalNodeBuilder::new(external_low).add_to_forest(&mut forest).unwrap();
    forest.make_root(high_id);
    forest.make_root(low_id);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);
    let untrusted = UntrustedMastForest::read_from_bytes(&bytes).unwrap();
    let restored = untrusted.validate().unwrap();

    assert_eq!(restored[high_id].digest(), external_high);
    assert_eq!(restored[low_id].digest(), external_low);
}

fn sparse_split_fixture() -> (Arc<MastForest>, SparseMastForest, MastNodeId, MastNodeId, MastNodeId)
{
    let mut forest = MastForest::new();
    let true_branch = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let false_branch = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let root = SplitNodeBuilder::new([true_branch, false_branch])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);

    let forest = Arc::new(forest);
    let mut builder = SparseMastForestBuilder::new(Arc::clone(&forest));
    builder.record_visit(true_branch, VisitKind::FullVisit);
    builder.record_visit(false_branch, VisitKind::DigestOnly);
    builder.record_visit(root, VisitKind::FullVisit);
    let sparse = builder.finalize();

    (forest, sparse, true_branch, false_branch, root)
}

#[test]
fn sparse_mast_round_trip_preserves_sparse_replay_ids() {
    let (source, sparse, true_branch, false_branch, root) = sparse_split_fixture();

    let bytes = sparse.to_bytes();
    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();

    assert_eq!(restored.num_nodes(), source.num_nodes() as usize);
    assert_eq!(restored.procedure_roots(), &[root]);
    assert_eq!(restored.commitment(), source.commitment());
    assert_eq!(
        restored.get_node_by_id(true_branch).unwrap().digest(),
        source[true_branch].digest()
    );
    assert_eq!(restored.get_node_by_id(root).unwrap().digest(), source[root].digest());
    assert!(restored.get_node_by_id(false_branch).is_none());
    assert_eq!(restored.get_digest_by_id(true_branch), Some(source[true_branch].digest()));
    assert_eq!(restored.get_digest_by_id(false_branch), Some(source[false_branch].digest()));
    assert_eq!(restored.get_digest_by_id(root), Some(source[root].digest()));
}

#[test]
fn sparse_mast_round_trip_preserves_external_full_node() {
    let mut forest = MastForest::new();
    let unvisited = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let external_digest = Word::new([
        Felt::new_unchecked(17),
        Felt::new_unchecked(18),
        Felt::new_unchecked(19),
        Felt::new_unchecked(20),
    ]);
    let external = ExternalNodeBuilder::new(external_digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(external);

    let forest = Arc::new(forest);
    let mut builder = SparseMastForestBuilder::new(Arc::clone(&forest));
    builder.record_visit(external, VisitKind::FullVisit);
    let sparse = builder.finalize();

    let restored = SparseMastForest::read_from_bytes(&sparse.to_bytes()).unwrap();

    assert_eq!(restored.num_nodes(), forest.num_nodes() as usize);
    assert_eq!(restored.procedure_roots(), &[external]);
    assert_eq!(restored.commitment(), forest.commitment());
    assert_eq!(restored.get_node_by_id(external).unwrap().digest(), external_digest);
    assert_eq!(restored.get_digest_by_id(external), Some(external_digest));
    assert!(restored.get_node_by_id(unvisited).is_none());
    assert_eq!(restored.get_digest_by_id(unvisited), None);
}

fn write_sparse_test_payload(
    source_node_count: usize,
    roots: &[MastNodeId],
    full_ids: &[MastNodeId],
    entries: &[MastNodeEntry],
    full_digests: &[Word],
    basic_block_data: &[u8],
    commitment: Word,
) -> Vec<u8> {
    assert_eq!(full_ids.len(), entries.len());
    assert_eq!(full_ids.len(), full_digests.len());

    let mut bytes = Vec::new();
    bytes.write_bytes(MAGIC);
    bytes.write_u8(FLAG_HASHLESS | FLAG_SPARSE);
    bytes.write_bytes(&VERSION);

    bytes.write_usize(roots.len());
    bytes.write_usize(source_node_count);
    bytes.write_usize(full_ids.len());
    bytes.write_usize(0);
    bytes.write_usize(
        entries.iter().filter(|entry| matches!(entry, MastNodeEntry::External)).count(),
    );
    bytes.write_usize(full_ids.len());
    bytes.write_usize(basic_block_data.len());

    for root in roots {
        root.0.write_into(&mut bytes);
    }
    commitment.write_into(&mut bytes);
    bytes.write_bytes(basic_block_data);
    for id in full_ids {
        id.0.write_into(&mut bytes);
    }
    for entry in entries {
        entry.write_into(&mut bytes);
    }
    for digest in full_digests {
        digest.write_into(&mut bytes);
    }
    AdviceMap::default().write_into(&mut bytes);
    bytes
}

#[test]
fn sparse_reader_allows_large_source_node_count_with_small_payload() {
    let block = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
    let mut basic_block_data = BasicBlockDataBuilder::new();
    let block_offset = basic_block_data.encode_basic_block(&block);
    let basic_block_data = basic_block_data.finalize();

    let root = MastNodeId::from(0);
    let bytes = write_sparse_test_payload(
        MastForest::MAX_NODES,
        &[root],
        &[root],
        &[MastNodeEntry::Block { ops_offset: block_offset }],
        &[block.digest()],
        &basic_block_data,
        block.digest(),
    );

    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored.num_nodes(), MastForest::MAX_NODES);
    assert_eq!(restored.get_digest_by_id(root), Some(block.digest()));
}

#[test]
fn sparse_reader_reconstructs_forward_full_child_digests() {
    let left_block = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
    let right_block = BasicBlockNodeBuilder::new(vec![Operation::Mul]).build().unwrap();

    let mut basic_block_data = BasicBlockDataBuilder::new();
    let left_offset = basic_block_data.encode_basic_block(&left_block);
    let right_offset = basic_block_data.encode_basic_block(&right_block);
    let basic_block_data = basic_block_data.finalize();

    let root = MastNodeId::from(0);
    let left = MastNodeId::from(1);
    let right = MastNodeId::from(2);
    let expected_root_digest = hasher::merge_in_domain(
        &[left_block.digest(), right_block.digest()],
        crate::mast::JoinNode::DOMAIN,
    );
    let bytes = write_sparse_test_payload(
        3,
        &[root],
        &[root, left, right],
        &[
            MastNodeEntry::Join {
                left_child_id: left.0,
                right_child_id: right.0,
            },
            MastNodeEntry::Block { ops_offset: left_offset },
            MastNodeEntry::Block { ops_offset: right_offset },
        ],
        &[expected_root_digest, left_block.digest(), right_block.digest()],
        &basic_block_data,
        expected_root_digest,
    );

    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored.get_digest_by_id(root), Some(expected_root_digest));
    assert_eq!(restored.get_digest_by_id(left), Some(left_block.digest()));
    assert_eq!(restored.get_digest_by_id(right), Some(right_block.digest()));
}

#[test]
fn sparse_reader_preserves_forced_full_node_digest() {
    let child_block = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
    let mut basic_block_data = BasicBlockDataBuilder::new();
    let child_offset = basic_block_data.encode_basic_block(&child_block);
    let basic_block_data = basic_block_data.finalize();

    let root = MastNodeId::from(0);
    let child = MastNodeId::from(1);
    let canonical_root_digest = hasher::merge_in_domain(
        &[child_block.digest(), Word::default()],
        crate::mast::CallNode::CALL_DOMAIN,
    );
    let forced_root_digest = Word::new([
        Felt::from(101_u32),
        Felt::from(102_u32),
        Felt::from(103_u32),
        Felt::from(104_u32),
    ]);
    assert_ne!(forced_root_digest, canonical_root_digest);

    let bytes = write_sparse_test_payload(
        2,
        &[root],
        &[root, child],
        &[
            MastNodeEntry::Call { callee_id: child.0 },
            MastNodeEntry::Block { ops_offset: child_offset },
        ],
        &[forced_root_digest, child_block.digest()],
        &basic_block_data,
        forced_root_digest,
    );

    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored.get_digest_by_id(root), Some(forced_root_digest));
    assert_eq!(restored.commitment(), forced_root_digest);
}

#[test]
fn sparse_reader_reconstructs_deep_forward_full_child_chain() {
    const CHAIN_LEN: usize = 4096;

    let block = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
    let mut basic_block_data = BasicBlockDataBuilder::new();
    let block_offset = basic_block_data.encode_basic_block(&block);
    let basic_block_data = basic_block_data.finalize();

    let full_ids: Vec<_> = (0..CHAIN_LEN).map(|id| MastNodeId::from(id as u32)).collect();
    let mut entries = Vec::with_capacity(CHAIN_LEN);
    for id in 0..CHAIN_LEN - 1 {
        entries.push(MastNodeEntry::Call { callee_id: (id + 1) as u32 });
    }
    entries.push(MastNodeEntry::Block { ops_offset: block_offset });

    let mut full_digests = vec![Word::default(); CHAIN_LEN];
    full_digests[CHAIN_LEN - 1] = block.digest();
    for id in (0..CHAIN_LEN - 1).rev() {
        full_digests[id] = hasher::merge_in_domain(
            &[full_digests[id + 1], Word::default()],
            crate::mast::CallNode::CALL_DOMAIN,
        );
    }
    let expected_root_digest = full_digests[0];

    let root = MastNodeId::from(0);
    let bytes = write_sparse_test_payload(
        CHAIN_LEN,
        &[root],
        &full_ids,
        &entries,
        &full_digests,
        &basic_block_data,
        expected_root_digest,
    );

    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored.get_digest_by_id(root), Some(expected_root_digest));
}

#[test]
fn sparse_reader_rejects_trailing_bytes_with_exact_prefix_budget() {
    let block = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap();
    let mut basic_block_data = BasicBlockDataBuilder::new();
    let block_offset = basic_block_data.encode_basic_block(&block);
    let basic_block_data = basic_block_data.finalize();

    let root = MastNodeId::from(0);
    let bytes = write_sparse_test_payload(
        1,
        &[root],
        &[root],
        &[MastNodeEntry::Block { ops_offset: block_offset }],
        &[block.digest()],
        &basic_block_data,
        block.digest(),
    );

    let mut bytes_with_trailing = bytes.clone();
    bytes_with_trailing.push(0);
    let err = SparseMastForest::read_from_bytes_with_options(
        &bytes_with_trailing,
        SparseMastForestReadOptions::new().with_wire_byte_budget(bytes_with_trailing.len()),
    )
    .unwrap_err();
    assert!(err.to_string().contains("extra bytes after SparseMastForest payload"));
}

#[test]
fn dense_mast_readers_reject_sparse_payloads() {
    let (_source, sparse, _true_branch, _false_branch, _root) = sparse_split_fixture();
    let bytes = sparse.to_bytes();

    let materialized = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        materialized,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("SPARSE flag is set")
    );

    let wire_view = MastForestWireView::new(&bytes);
    assert_matches!(
        wire_view,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("SPARSE flag is set")
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&bytes);
    assert_matches!(
        untrusted,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("SPARSE flag is set")
    );
}

#[test]
fn sparse_reader_rejects_dense_payloads() {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);

    let result = SparseMastForest::read_from_bytes(&forest.to_bytes());
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("SPARSE flag is not set")
    );
}

#[test]
fn sparse_serialized_parts_reject_missing_child_digest() {
    let (_source, sparse, _true_branch, false_branch, _root) = sparse_split_fixture();
    let nodes = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let digests = sparse
        .digest_entries()
        .iter()
        .filter_map(|(&id, &digest)| (id != false_branch).then_some((id, digest)))
        .collect();

    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests,
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );

    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("without a full node or digest-only entry")
    );
}

#[test]
fn sparse_serialized_parts_reject_duplicate_full_ids() {
    let (_source, sparse, true_branch, _false_branch, _root) = sparse_split_fixture();
    let mut nodes: Vec<_> = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let duplicate_node = sparse.get_node_by_id(true_branch).unwrap().clone();
    nodes.push((true_branch, duplicate_node));
    let digests = sparse.digest_entries().iter().map(|(&id, &digest)| (id, digest)).collect();

    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests,
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );

    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("duplicate sparse full-node id")
    );
}

#[test]
fn sparse_serialized_parts_reject_duplicate_digest_only_ids() {
    let (_source, sparse, _true_branch, false_branch, _root) = sparse_split_fixture();
    let nodes = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let mut digests: Vec<_> =
        sparse.digest_entries().iter().map(|(&id, &digest)| (id, digest)).collect();
    let digest = sparse.get_digest_by_id(false_branch).unwrap();
    digests.push((false_branch, digest));

    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests,
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );

    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("duplicate sparse digest-only id")
    );
}

#[test]
fn sparse_serialized_parts_reject_full_digest_overlap() {
    let (_source, sparse, true_branch, _false_branch, _root) = sparse_split_fixture();
    let nodes = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let mut digests: Vec<_> =
        sparse.digest_entries().iter().map(|(&id, &digest)| (id, digest)).collect();
    digests.push((true_branch, sparse.get_digest_by_id(true_branch).unwrap()));

    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests,
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );

    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("overlaps a digest-only entry")
    );
}

#[test]
fn sparse_serialized_parts_reject_out_of_range_full_digest_and_root_ids() {
    let (_source, sparse, true_branch, false_branch, _root) = sparse_split_fixture();
    let out_of_range = MastNodeId::from(sparse.num_nodes() as u32);

    let mut nodes: Vec<_> = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    nodes.push((out_of_range, sparse.get_node_by_id(true_branch).unwrap().clone()));
    let digests: Vec<_> =
        sparse.digest_entries().iter().map(|(&id, &digest)| (id, digest)).collect();
    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests.clone(),
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("full node id")
            && msg.contains("out of range")
    );

    let nodes = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let mut out_of_range_digests = digests;
    out_of_range_digests.push((out_of_range, sparse.get_digest_by_id(false_branch).unwrap()));
    let result = SparseMastForest::from_serialized_parts(
        nodes,
        out_of_range_digests,
        sparse.num_nodes(),
        sparse.procedure_roots().to_vec(),
        sparse.advice_map().clone(),
        sparse.commitment(),
    );
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("digest-only node id")
            && msg.contains("out of range")
    );

    let nodes = sparse.nodes().iter().map(|(&id, node)| (id, node.clone())).collect();
    let digests = sparse.digest_entries().iter().map(|(&id, &digest)| (id, digest)).collect();
    let result = SparseMastForest::from_serialized_parts(
        nodes,
        digests,
        sparse.num_nodes(),
        vec![out_of_range],
        sparse.advice_map().clone(),
        sparse.commitment(),
    );
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("procedure root id")
            && msg.contains("out of range")
    );
}

/// Test that a forest with a node whose child ids are larger than its own id serializes and
/// deserializes successfully.
#[test]
fn mast_forest_invalid_node_id() {
    // Hydrate a forest smaller than the second
    let mut forest = MastForest::new();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();

    // Hydrate a forest larger than the first to get an overflow MastNodeId
    let mut overflow_forest = MastForest::new();

    BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut overflow_forest)
        .unwrap();
    let overflow = BasicBlockNodeBuilder::new(vec![Operation::U32div])
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
fn mast_forest_deserialize_invalid_ops_offset_fails() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let serialized = forest.to_bytes();
    let mut reader = SliceReader::new(&serialized);

    let _: [u8; 8] = reader.read_array().unwrap(); // magic (4) + flags (1) + version (3)
    let _internal_node_count: usize = reader.read().unwrap();
    let _external_node_count: usize = reader.read().unwrap();
    let _roots: Vec<u32> = Deserializable::read_from(&mut reader).unwrap();
    let _basic_block_data: Vec<u8> = Deserializable::read_from(&mut reader).unwrap();

    let view = MastForestWireView::new(&serialized).unwrap();
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
fn mast_forest_read_from_bytes_rejects_fuzzed_overflow_payload() {
    // This fuzz payload contains length fields that make deserialization read far past the input
    // size. If this starts succeeding, the byte-slice path may no longer be enforcing its budget.
    let payload = [
        0x4d, 0x41, 0x53, 0x54, 0x00, 0x00, 0x00, 0x03, 0x07, 0x03, 0x0b, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x30, 0x01,
        0x3b, 0x0b, 0x00, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad,
        0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0x53, 0x4a,
        0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad,
        0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0x21, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xad, 0xad, 0xad, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x84, 0x81, 0xc3, 0xbc, 0x72, 0x7f,
        0x15, 0x30,
    ];

    let result = MastForest::read_from_bytes(&payload);
    assert!(result.is_err());

    // Wrapped fuzz inputs must use the generic budgeted entry point; otherwise the outer
    // collection length can drive unbounded work before the inner forest fails.
    let mut vec_payload = vec![0];
    vec_payload.extend_from_slice(&1000u64.to_le_bytes());
    let budget = vec_payload.len().saturating_mul(TRUSTED_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Vec::<MastForest>::read_from_bytes_with_budget(&vec_payload, budget);
    assert!(result.is_err());

    let mut option_payload = vec![1];
    option_payload.extend_from_slice(&payload);
    let budget = option_payload.len().saturating_mul(TRUSTED_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Option::<MastForest>::read_from_bytes_with_budget(&option_payload, budget);
    assert!(result.is_err());
}

#[test]
fn mast_forest_serialize_deserialize_omits_legacy_debug_info() {
    let mut forest = MastForest::new();

    let block1_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let block2_id = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let block3_id = BasicBlockNodeBuilder::new(vec![Operation::U32sub])
        .add_to_forest(&mut forest)
        .unwrap();

    forest.make_root(block1_id);
    forest.make_root(block2_id);
    forest.make_root(block3_id);

    let serialized = forest.to_bytes();
    let mut explicit = Vec::new();
    forest.write_into(&mut explicit);
    assert_eq!(serialized, explicit);

    let view = MastForestWireView::new(&serialized).unwrap();
    assert_eq!(view.debug_info_offset(), serialized.len());

    let deserialized = MastForest::read_from_bytes(&serialized).unwrap();

    assert_eq!(forest, deserialized);
}

fn serialized_single_block_forest() -> Vec<u8> {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);
    forest.to_bytes()
}

#[test]
fn mast_forest_deserializers_reject_reserved_bit_zero() {
    let mut bytes = serialized_single_block_forest();
    bytes[MAGIC.len()] = 0x01;

    let trusted = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        trusted,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("Unknown flags") && msg.contains("0x01")
    );

    let materialized_view =
        MastForest::read_view_from_bytes(&bytes, MastForestReadMode::Materialized);
    assert_matches!(
        materialized_view,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("Unknown flags") && msg.contains("0x01")
    );

    let wire_backed_view = MastForest::read_view_from_bytes(&bytes, MastForestReadMode::WireBacked);
    assert_matches!(
        wire_backed_view,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("Unknown flags") && msg.contains("0x01")
    );

    let wire_view = MastForestWireView::new(&bytes);
    assert_matches!(
        wire_view,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("Unknown flags") && msg.contains("0x01")
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&bytes);
    assert_matches!(
        untrusted,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("Unknown flags") && msg.contains("0x01")
    );
}

#[test]
fn mast_forest_wire_view_rejects_trailing_bytes_after_payload() {
    let mut bytes = serialized_single_block_forest();
    bytes.extend_from_slice(&[1, 2, 3]);

    let result = MastForestWireView::new(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("extra bytes after MastForest payload")
    );
}

#[test]
fn mast_forest_byte_readers_reject_trailing_bytes_after_payload() {
    let mut bytes = serialized_single_block_forest();
    bytes.extend_from_slice(&[1, 2, 3]);

    let trusted = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        trusted,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("extra bytes after MastForest payload")
    );

    let materialized_view =
        MastForest::read_view_from_bytes(&bytes, MastForestReadMode::Materialized);
    assert_matches!(
        materialized_view,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("extra bytes after MastForest payload")
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&bytes);
    assert_matches!(
        untrusted,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("extra bytes after MastForest payload")
    );
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

    let block_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

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

    let block_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

    let original = forest[block_id].unwrap_basic_block();
    assert!(original.op_batches().len() > 1, "Should have multiple batches");

    let deserialized_forest = MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
    let deserialized = deserialized_forest[block_id].unwrap_basic_block();

    assert_eq!(original.op_batches(), deserialized.op_batches());
}

/// Tests that operation batches preserve their digest across serialization.
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
    let block_id1 = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest1).unwrap();
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

    let block_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();

    // Get the OpBatches from the original node
    let original_node = forest[block_id].unwrap_basic_block();
    let original_batches = original_node.op_batches().to_vec();
    let original_digest = original_node.digest();

    // Construct a new node using the Batched path
    let mut forest2 = MastForest::new();
    let block_id2 =
        BasicBlockNodeBuilder::from_op_batches(original_batches.clone(), original_digest)
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
    assert_eq!(&bytes[5..8], &[0, 0, 5], "Version should be [0, 0, 5]");
}

fn read_header_counts(bytes: &[u8]) -> (usize, usize) {
    let mut offset = 8;
    let internal_node_count = read_usize_at(bytes, &mut offset).unwrap();
    let external_node_count = read_usize_at(bytes, &mut offset).unwrap();
    (internal_node_count, external_node_count)
}

#[test]
fn test_header_flags_for_serialization_modes() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    assert_header_flags(&forest.to_bytes(), 0x00);

    let mut normal_bytes = Vec::new();
    forest.write_into(&mut normal_bytes);
    assert_header_flags(&normal_bytes, 0x00);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);
    assert_header_flags(&hashless_bytes, 0x02);
}

#[test]
fn test_header_counts_match_node_kinds() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let external_id = ExternalNodeBuilder::new(Word::default()).add_to_forest(&mut forest).unwrap();
    let join_id = JoinNodeBuilder::new([block_id, external_id])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(join_id);

    let (internal_node_count, external_node_count) = read_header_counts(&forest.to_bytes());
    assert_eq!(internal_node_count, 2);
    assert_eq!(external_node_count, 1);
}

/// Test that legacy version headers are rejected.
#[test]
fn test_legacy_version_is_rejected() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut bytes = forest.to_bytes();
    bytes[5..8].copy_from_slice(&[0, 0, 3]);

    let result = MastForest::read_from_bytes(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("Unsupported version")
    );
}

#[test]
fn test_deserialization_rejects_mismatched_header_counts() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut bytes = forest.to_bytes();
    let mut offset = 8;
    let internal_count_offset = offset;
    let _internal_node_count = read_usize_at(&bytes, &mut offset).unwrap();
    let external_count_offset = offset;
    let _external_node_count = read_usize_at(&bytes, &mut offset).unwrap();

    let mut encoded_internal = Vec::new();
    0usize.write_into(&mut encoded_internal);
    let mut encoded_external = Vec::new();
    1usize.write_into(&mut encoded_external);
    assert_eq!(encoded_internal.len(), 1);
    assert_eq!(encoded_external.len(), 1);
    bytes[internal_count_offset..internal_count_offset + encoded_internal.len()]
        .copy_from_slice(&encoded_internal);
    bytes[external_count_offset..external_count_offset + encoded_external.len()]
        .copy_from_slice(&encoded_external);

    let result = MastForestWireView::new(&bytes);
    assert_matches!(
        result,
        Err(DeserializationError::InvalidValue(msg))
            if msg.contains("header external node count 1 does not match 0 external node entries")
    );
}

/// Test that normal serialization includes hashes, and hashless is smaller.
#[test]
fn test_serialization_sizes_shrink_from_digestful_to_hashless() {
    let mut forest = MastForest::new();

    let operations = vec![Operation::Add, Operation::Mul, Operation::Drop];
    let block_id = BasicBlockNodeBuilder::new(operations).add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);

    let full_bytes = forest.to_bytes();

    let mut normal_bytes = Vec::new();
    forest.write_into(&mut normal_bytes);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let full_view = MastForestWireView::new(&full_bytes).unwrap();
    assert_eq!(full_view.node_count(), forest.num_nodes() as usize);
    assert_eq!(full_view.procedure_root_count(), 1);
    assert!(full_view.node_info_at(0).is_ok());

    assert_eq!(normal_bytes, full_bytes);
    assert!(hashless_bytes.len() < normal_bytes.len());

    let normal_view = MastForestWireView::new(&normal_bytes).unwrap();
    let hashless_view = MastForestWireView::new(&hashless_bytes);
    assert!(normal_view.node_hash_offset().is_some());
    assert_matches!(hashless_view, Err(DeserializationError::InvalidValue(msg)) if msg.contains("HASHLESS flag is set"));
}

/// Test that unknown header flags are rejected.
#[test]
fn test_deserialize_rejects_unknown_flags() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let bytes = forest.to_bytes();

    for flag in [0x01, 0x08] {
        let mut bytes = bytes.clone();
        bytes[4] = flag;

        let result = MastForest::read_from_bytes(&bytes);
        assert_matches!(
            result,
            Err(DeserializationError::InvalidValue(msg))
                if msg.contains("Unknown flags") && msg.contains("Reserved bits")
        );
    }
}

/// Test that trusted deserialization rejects hashless inputs.
#[test]
fn test_trusted_rejects_hashless() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
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
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
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

#[test]
fn test_materialized_deserialization_preserves_duplicate_roots() {
    let mut forest = MastForest::new();
    let root_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.roots = vec![root_id, root_id];
    forest.commitment = forest.compute_nodes_commitment(&forest.roots);

    let bytes = forest.to_bytes();
    let restored = MastForest::read_from_bytes(&bytes).unwrap();

    assert_eq!(restored.procedure_roots(), &[root_id, root_id]);
    assert_eq!(restored.commitment(), forest.commitment());
}

fn assert_untrusted_overspec_logging(
    bytes: &[u8],
    expected_nodes: u32,
    expected_log_fragments: &[&str],
) {
    let (result, logs) = with_captured_error_logs(|| UntrustedMastForest::read_from_bytes(bytes));

    let untrusted = result.unwrap();
    assert_eq!(logs.len(), expected_log_fragments.len());
    for expected in expected_log_fragments {
        assert!(logs.iter().any(|msg| msg.contains(expected)));
    }
    assert_eq!(untrusted.validate().unwrap().num_nodes(), expected_nodes);

    let budgeted = UntrustedMastForest::read_from_bytes_with_options(
        bytes,
        UntrustedMastForestReadOptions::new().with_wire_byte_budget(bytes.len()),
    )
    .unwrap();
    assert_eq!(budgeted.validate().unwrap().num_nodes(), expected_nodes);
}

#[test]
fn test_untrusted_overspecification_logging_matches_wire_mode() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);
    assert_untrusted_overspec_logging(&hashless_bytes, forest.num_nodes(), &[]);

    let mut normal_bytes = Vec::new();
    forest.write_into(&mut normal_bytes);
    assert_untrusted_overspec_logging(&normal_bytes, forest.num_nodes(), &["wire node hashes"]);

    let bytes = forest.to_bytes();
    assert_untrusted_overspec_logging(&bytes, forest.num_nodes(), &["wire node hashes"]);
}

/// Test that untrusted validation in hashless mode recomputes non-external digests without any
/// general wire hash section.
#[test]
fn test_untrusted_hashless_validate_recomputes_without_wire_hash_section() {
    let mut forest = MastForest::new();
    let block1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let block2 = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();
    let join = JoinNodeBuilder::new([block1, block2]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);

    let expected_digests: Vec<_> =
        forest.nodes().iter().map(super::super::node::MastNodeExt::digest).collect();

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    let untrusted = UntrustedMastForest::read_from_bytes(&hashless_bytes).unwrap();

    let validated = untrusted.validate().unwrap();
    let validated_digests: Vec<_> =
        validated.nodes().iter().map(super::super::node::MastNodeExt::digest).collect();
    assert_eq!(validated_digests, expected_digests);
}

#[test]
fn test_mast_forest_serialization_round_trip_without_debug_metadata() {
    let mut forest = MastForest::new();

    let ops = vec![Operation::Noop; 4];
    let block_id = BasicBlockNodeBuilder::new(ops).add_to_forest(&mut forest).unwrap();
    forest.make_root(block_id);

    let bytes = forest.to_bytes();
    let deserialized = MastForest::read_from_bytes(&bytes).unwrap();

    assert_eq!(forest.num_nodes(), deserialized.num_nodes());
    assert_eq!(forest, deserialized);
}

/// Test that untrusted forest validation rejects forward node references.
#[test]
fn test_untrusted_forest_detects_forward_reference() {
    // Create a forest with forward references by swapping node order
    let mut forest = MastForest::new();
    let zero = BasicBlockNodeBuilder::new(vec![Operation::U32div])
        .add_to_forest(&mut forest)
        .unwrap();
    let first = BasicBlockNodeBuilder::new(vec![Operation::U32add])
        .add_to_forest(&mut forest)
        .unwrap();
    let second = BasicBlockNodeBuilder::new(vec![Operation::U32and])
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
fn test_untrusted_forest_rejects_mismatched_wire_root_hash() {
    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);
    let expected_digest = forest[block_id].digest();

    let bytes = forest.to_bytes();
    let view = MastForestWireView::new(&bytes).unwrap();
    let digest_offset = node_hash_digest_offset(&view, block_id.to_usize());
    let bogus_digest: Word = [
        Felt::new_unchecked(9),
        Felt::new_unchecked(8),
        Felt::new_unchecked(7),
        Felt::new_unchecked(6),
    ]
    .into();

    let mut corrupted = bytes.clone();
    bogus_digest.write_into(
        &mut &mut corrupted[digest_offset..digest_offset + Word::min_serialized_size()],
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&corrupted).unwrap();
    let result = untrusted.validate();

    assert_matches!(
        result,
        Err(MastForestError::HashMismatch {
            node_id,
            expected,
            computed,
        }) if node_id == block_id && expected == bogus_digest && computed == expected_digest
    );
}

#[test]
fn test_untrusted_forest_rejects_digest_collision_in_wire_hashes() {
    let mut forest = MastForest::new();
    let left_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let right_root = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(left_root);
    forest.make_root(right_root);

    let left_digest = forest[left_root].digest();
    let right_digest = forest[right_root].digest();

    let bytes = forest.to_bytes();
    let view = MastForestWireView::new(&bytes).unwrap();
    let left_digest_offset = node_hash_digest_offset(&view, left_root.to_usize());

    let mut corrupted = bytes.clone();
    right_digest.write_into(
        &mut &mut corrupted[left_digest_offset..left_digest_offset + Word::min_serialized_size()],
    );

    let untrusted = UntrustedMastForest::read_from_bytes(&corrupted).unwrap();
    let result = untrusted.validate();

    assert_matches!(
        result,
        Err(MastForestError::HashMismatch {
            node_id,
            expected,
            computed,
        }) if node_id == left_root && expected == right_digest && computed == left_digest
    );
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
    let block_id = BasicBlockNodeBuilder::new(vec![
        Operation::Push(push_imm),
        Operation::Noop,
        Operation::Add,
    ])
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

    let internal_node_count: usize = cursor.read().unwrap();
    assert_eq!(internal_node_count, 1);
    let external_node_count: usize = cursor.read().unwrap();
    assert_eq!(external_node_count, 0);

    let _roots: Vec<u32> = Deserializable::read_from(&mut cursor).unwrap();

    // basic block data section: Vec<u8>
    let bb_data_len: usize = cursor.read().unwrap();
    let bb_payload_start = cursor.position();
    let bb_payload_end = bb_payload_start + bb_data_len;
    let view = MastForestWireView::new(bytes).unwrap();
    let node_entries_start = view.node_entry_offset();

    // node entry: MastNodeEntry (8 bytes)
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
    let block_id = BasicBlockNodeBuilder::from_op_batches(op_batches, digest)
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
    let block_id = BasicBlockNodeBuilder::from_op_batches(op_batches, digest)
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
    let block1_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let block2_id = BasicBlockNodeBuilder::new(vec![Operation::Mul])
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

/// Test that UntrustedMastForest::validate rejects excessive node counts before validation.
#[test]
fn test_deserialization_rejects_excessive_node_count() {
    // Craft a malicious payload with node_count exceeding MAX_NODES
    let mut bytes = Vec::new();

    // Write valid header
    MAGIC.write_into(&mut bytes);
    bytes.write_u8(0); // flags
    VERSION.write_into(&mut bytes);

    // Write excessive derived node count (MAX_NODES + 1 internal nodes)
    let excessive_count: usize = MastForest::MAX_NODES + 1;
    excessive_count.write_into(&mut bytes);
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

/// Test that untrusted deserialization rejects node counts that exceed the reader allocation
/// bound before they can drive later allocations.
#[test]
fn test_untrusted_deserialization_rejects_node_count_above_budget_bound() {
    let mut bytes = Vec::new();

    MAGIC.write_into(&mut bytes);
    bytes.write_u8(FLAG_HASHLESS);
    VERSION.write_into(&mut bytes);

    2usize.write_into(&mut bytes);
    0usize.write_into(&mut bytes);

    let result = UntrustedMastForest::read_from_bytes_with_options(
        &bytes,
        UntrustedMastForestReadOptions::new().with_wire_byte_budget(bytes.len()),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("node count 2 exceeds reader allocation bound"),
        "Expected budget-bound node count error, got: {err}"
    );
}

/// Test that custom untrusted budgets also apply to later hashless validation allocations.
#[test]
fn test_untrusted_hashless_validation_respects_custom_allocation_budget() {
    let mut forest = MastForest::new();
    let left = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let root = JoinNodeBuilder::new([left, right]).add_to_forest(&mut forest).unwrap();
    forest.make_root(root);

    let mut bytes = Vec::new();
    forest.write_hashless(&mut bytes);

    let untrusted = UntrustedMastForest::read_from_bytes_with_options(
        &bytes,
        UntrustedMastForestReadOptions::new()
            .with_wire_byte_budget(bytes.len())
            .with_validation_allocation_budget(bytes.len()),
    )
    .unwrap();
    let result = untrusted.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("remaining untrusted allocation budget"),
        "Expected validation-allocation budget error, got: {err}"
    );
}

/// Test that MastForest payloads do not charge legacy debug-info scaffolding.
#[cfg(target_pointer_width = "64")]
#[test]
fn test_untrusted_payload_does_not_allocate_debug_info_scaffolding() {
    let mut forest = MastForest::new();
    let left = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let root = JoinNodeBuilder::new([left, right]).add_to_forest(&mut forest).unwrap();
    forest.make_root(root);

    let mut bytes = Vec::new();
    forest.write_into(&mut bytes);

    let validation_budget =
        (usize::try_from(forest.num_nodes()).unwrap() + 1) * size_of::<usize>() - 1;
    let untrusted = UntrustedMastForest::read_from_bytes_with_options(
        &bytes,
        UntrustedMastForestReadOptions::new()
            .with_wire_byte_budget(bytes.len())
            .with_validation_allocation_budget(validation_budget),
    )
    .expect("normal reads should not allocate debug-info scaffolding");
    untrusted
        .validate()
        .expect("validation should fit the budget previously consumed by debug scaffolding");
}
