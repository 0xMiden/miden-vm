use alloc::string::ToString;

use miden_crypto::{Felt, ONE, Word};
use miden_utils_indexing::Idx;

use super::*;
use crate::{
    AssemblyOp, DebugOptions, Decorator,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForestContributor, MastForestError, MastNodeExt,
        SplitNodeBuilder,
    },
    operations::Operation,
};

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
        Operation::Join => (),
        Operation::Split => (),
        Operation::Loop => (),
        Operation::Call => (),
        Operation::Dyn => (),
        Operation::Dyncall => (),
        Operation::SysCall => (),
        Operation::Span => (),
        Operation::End => (),
        Operation::Repeat => (),
        Operation::Respan => (),
        Operation::Halt => (),
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

    match Decorator::Trace(0) {
        Decorator::AsmOp(_) => (),
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

#[test]
fn serialize_deserialize_all_nodes() {
    let mut mast_forest = MastForest::new();

    let basic_block_id = {
        let operations = vec![
            Operation::Noop,
            Operation::Assert(Felt::from(42u32)),
            Operation::SDepth,
            Operation::Caller,
            Operation::Clk,
            Operation::Join,
            Operation::Split,
            Operation::Loop,
            Operation::Call,
            Operation::Dyn,
            Operation::SysCall,
            Operation::Span,
            Operation::End,
            Operation::Repeat,
            Operation::Respan,
            Operation::Halt,
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
            Operation::U32assert2(Felt::from(222u32)),
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
            Operation::Push(Felt::new(45)),
            Operation::AdvPop,
            Operation::AdvPopW,
            Operation::MLoadW,
            Operation::MStoreW,
            Operation::MLoad,
            Operation::MStore,
            Operation::MStream,
            Operation::Pipe,
            Operation::HPerm,
            Operation::MpVerify(Felt::from(1022u32)),
            Operation::MrUpdate,
            Operation::FriE2F4,
            Operation::HornerBase,
            Operation::HornerExt,
            Operation::Emit,
        ];

        let num_operations = operations.len();

        let decorators = vec![
            (
                0,
                Decorator::AsmOp(AssemblyOp::new(
                    Some(miden_debug_types::Location {
                        uri: "test".into(),
                        start: 42.into(),
                        end: 43.into(),
                    }),
                    "context".to_string(),
                    15,
                    "op".to_string(),
                    false,
                )),
            ),
            (0, Decorator::Debug(DebugOptions::StackAll)),
            (15, Decorator::Debug(DebugOptions::StackTop(255))),
            (15, Decorator::Debug(DebugOptions::MemAll)),
            (15, Decorator::Debug(DebugOptions::MemInterval(0, 16))),
            (17, Decorator::Debug(DebugOptions::LocalInterval(1, 2, 3))),
            (19, Decorator::Debug(DebugOptions::AdvStackTop(255))),
            (num_operations, Decorator::Trace(55)),
        ];

        {
            // Convert raw decorators to decorator list by adding them to the forest first
            let decorator_list: Vec<(usize, crate::mast::DecoratorId)> = decorators
            .into_iter()
            .map(|(idx, decorator)| -> Result<(usize, crate::mast::DecoratorId), MastForestError> {
                let decorator_id = mast_forest.add_decorator(decorator)?;
                Ok((idx, decorator_id))
            })
            .collect::<Result<Vec<_>, MastForestError>>()
            .unwrap();

            BasicBlockNodeBuilder::new(operations, decorator_list)
                .add_to_forest(&mut mast_forest)
                .unwrap()
        }
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
    let deserialized_block =
        if let crate::mast::MastNode::Block(block) = &deserialized[deserialized_root_id] {
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
    use crate::utils::Serializable;

    let mut forest = MastForest::new();
    let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(block_id);

    let serialized = forest.to_bytes();

    use crate::utils::SliceReader;
    let mut reader = SliceReader::new(&serialized);

    let _: [u8; 8] = reader.read_array().unwrap(); // magic + version
    let _node_count: usize = reader.read().unwrap();
    let _decorator_count: usize = reader.read().unwrap();
    let _roots: Vec<u32> = Deserializable::read_from(&mut reader).unwrap();
    let basic_block_data: Vec<u8> = Deserializable::read_from(&mut reader).unwrap();

    // Calculate offset to MastNodeInfo
    let node_info_offset = 5 + 3 + 8 + 8 + 8 + 4 + 8 + basic_block_data.len();

    // Corrupt the ops_offset field with an out-of-bounds value
    let block_discriminant: u64 = 3;
    let corrupted_value = (block_discriminant << 60) | u32::MAX as u64;

    let mut corrupted = serialized;
    corrupted_value.write_into(&mut &mut corrupted[node_info_offset..node_info_offset + 8]);

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
        Operation::Push(Felt::new(100)),
        Operation::Push(Felt::new(200)),
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
    let operations: Vec<_> = (0..80).map(|i| Operation::Push(Felt::new(i))).collect();

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
        Operation::Push(Felt::new(100)), // Will cause padding
        Operation::Drop,
    ];

    // Add decorator at operation index 2 (the PUSH)
    let decorators = vec![(2, decorator_id)];

    let block_id = BasicBlockNodeBuilder::new(operations.clone(), decorators)
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
    let _decorator_id2 = forest2.add_decorator(Decorator::Trace(1)).unwrap();

    let operations =
        vec![Operation::Add, Operation::Mul, Operation::Push(Felt::new(100)), Operation::Drop];

    // Path 1: Raw construction
    let block_id1 = BasicBlockNodeBuilder::new(operations.clone(), vec![(2, decorator_id1)])
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
        Operation::Push(Felt::new(42)),
        Operation::Drop,
        Operation::Dup0,
    ];

    // Construct via Raw path
    let mut forest1 = MastForest::new();
    let block_id1 = BasicBlockNodeBuilder::new(operations.clone(), Vec::new())
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
        Operation::Push(Felt::new(100)),
        Operation::Push(Felt::new(200)),
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

mod proptests {
    use proptest::{prelude::*, strategy::Just};

    use super::*;
    use crate::{
        Decorator,
        mast::{BasicBlockNodeBuilder, MastForest, MastNode, arbitrary::MastForestParams},
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
                let node_id = crate::mast::MastNodeId::new_unchecked(idx as u32);
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
                    crate::Operation::Add,
                    crate::Operation::Mul,
                    crate::Operation::Push(crate::Felt::new(42)),
                    crate::Operation::Drop,
                    crate::Operation::Dup0,
                    crate::Operation::Swap,
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
                        crate::Operation::Add,
                        crate::Operation::Mul,
                        crate::Operation::Push(crate::Felt::new(99)),
                        crate::Operation::Drop,
                        crate::Operation::Dup0,
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
    }
}
