use alloc::string::ToString;

use miden_crypto::{Felt, ONE, Word};

use super::*;
use crate::{
    AssemblyOp, DebugOptions, Decorator, Idx,
    mast::{BasicBlockNode, MastForestError, MastNodeExt, node::MastNodeErrorContext},
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
        Operation::HPerm => (),
        Operation::MpVerify(_) => (),
        Operation::MrUpdate => (),
        Operation::FriE2F4 => (),
        Operation::HornerBase => (),
        Operation::HornerExt => (),
        Operation::EvalCircuit => (),
        Operation::Emit => (),
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

        mast_forest.add_block_with_raw_decorators(operations, decorators).unwrap()
    };

    // Decorators to add to following nodes
    let decorator_id1 = mast_forest.add_decorator(Decorator::Trace(1)).unwrap();
    let decorator_id2 = mast_forest.add_decorator(Decorator::Trace(2)).unwrap();

    // Call node
    let call_node_id = mast_forest.add_call(basic_block_id).unwrap();
    mast_forest[call_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[call_node_id].append_after_exit(&[decorator_id2]);

    // Syscall node
    let syscall_node_id = mast_forest.add_syscall(basic_block_id).unwrap();
    mast_forest[syscall_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[syscall_node_id].append_after_exit(&[decorator_id2]);

    // Loop node
    let loop_node_id = mast_forest.add_loop(basic_block_id).unwrap();
    mast_forest[loop_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[loop_node_id].append_after_exit(&[decorator_id2]);

    // Join node
    let join_node_id = mast_forest.add_join(basic_block_id, call_node_id).unwrap();
    mast_forest[join_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[join_node_id].append_after_exit(&[decorator_id2]);

    // Split node
    let split_node_id = mast_forest.add_split(basic_block_id, call_node_id).unwrap();
    mast_forest[split_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[split_node_id].append_after_exit(&[decorator_id2]);

    // Dyn node
    let dyn_node_id = mast_forest.add_dyn().unwrap();
    mast_forest[dyn_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[dyn_node_id].append_after_exit(&[decorator_id2]);

    // Dyncall node
    let dyncall_node_id = mast_forest.add_dyncall().unwrap();
    mast_forest[dyncall_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[dyncall_node_id].append_after_exit(&[decorator_id2]);

    // External node
    let external_node_id = mast_forest.add_external(Word::default()).unwrap();
    mast_forest[external_node_id].append_before_enter(&[decorator_id1]);
    mast_forest[external_node_id].append_after_exit(&[decorator_id2]);

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
    let zero = forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();
    let first = forest.add_block(vec![Operation::U32add], vec![(0, deco0)]).unwrap();
    let second = forest.add_block(vec![Operation::U32and], vec![(1, deco1)]).unwrap();
    forest.add_join(first, second).unwrap();

    // Move the Join node before its child nodes and remove the temporary zero node.
    forest.nodes.swap_remove(zero.to_usize());

    MastForest::read_from_bytes(&forest.to_bytes()).unwrap();
}

/// Test that a forest with a node whose referenced index is >= the max number of nodes in
/// the forest returns an error during deserialization.
#[test]
fn mast_forest_serialize_deserialize_with_overflowing_ids_fails() {
    let mut overflow_forest = MastForest::new();
    let id0 = overflow_forest.add_block(vec![Operation::Eqz], Vec::new()).unwrap();
    overflow_forest.add_block(vec![Operation::Eqz], Vec::new()).unwrap();
    let id2 = overflow_forest.add_block(vec![Operation::Eqz], Vec::new()).unwrap();
    let id_join = overflow_forest.add_join(id0, id2).unwrap();

    let join_node = overflow_forest[id_join].clone();

    // Add the Join(0, 2) to this forest which does not have a node with index 2.
    let mut forest = MastForest::new();
    let deco0 = forest.add_decorator(Decorator::Trace(0)).unwrap();
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    forest.add_block(vec![Operation::U32add], vec![(0, deco0), (1, deco1)]).unwrap();
    forest.add_node(join_node).unwrap();

    assert_matches!(
        MastForest::read_from_bytes(&forest.to_bytes()),
        Err(DeserializationError::InvalidValue(msg)) if msg.contains("number of nodes")
    );
}

#[test]
fn mast_forest_invalid_node_id() {
    // Hydrate a forest smaller than the second
    let mut forest = MastForest::new();
    let first = forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();
    let second = forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();

    // Hydrate a forest larger than the first to get an overflow MastNodeId
    let mut overflow_forest = MastForest::new();

    overflow_forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();
    overflow_forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();
    overflow_forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();
    let overflow = overflow_forest.add_block(vec![Operation::U32div], Vec::new()).unwrap();

    // Attempt to join with invalid ids
    let join = forest.add_join(overflow, second);
    assert_eq!(join, Err(MastForestError::NodeIdOverflow(overflow, 2)));
    let join = forest.add_join(first, overflow);
    assert_eq!(join, Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Attempt to split with invalid ids
    let split = forest.add_split(overflow, second);
    assert_eq!(split, Err(MastForestError::NodeIdOverflow(overflow, 2)));
    let split = forest.add_split(first, overflow);
    assert_eq!(split, Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Attempt to loop with invalid ids
    assert_eq!(forest.add_loop(overflow), Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Attempt to call with invalid ids
    assert_eq!(forest.add_call(overflow), Err(MastForestError::NodeIdOverflow(overflow, 2)));
    assert_eq!(forest.add_syscall(overflow), Err(MastForestError::NodeIdOverflow(overflow, 2)));

    // Validate normal operations
    forest.add_join(first, second).unwrap();
}

/// Test `MastForest::advice_map` serialization and deserialization.
#[test]
fn mast_forest_serialize_deserialize_advice_map() {
    let mut forest = MastForest::new();
    let deco0 = forest.add_decorator(Decorator::Trace(0)).unwrap();
    let deco1 = forest.add_decorator(Decorator::Trace(1)).unwrap();
    let first = forest.add_block(vec![Operation::U32add], vec![(0, deco0)]).unwrap();
    let second = forest.add_block(vec![Operation::U32and], vec![(1, deco1)]).unwrap();
    forest.add_join(first, second).unwrap();

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

    // Create a basic block with all types of decorators
    let operations = vec![Operation::Add, Operation::Mul];
    let mut block = BasicBlockNode::new(operations, vec![(0, op_deco)]).unwrap();
    block.append_before_enter(&[before_enter_deco]);
    block.append_after_exit(&[after_exit_deco]);

    // Add the block to the forest
    let block_id = forest.add_node(block).unwrap();
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
        deserialized_block.before_enter(),
        &[before_enter_deco],
        "before_enter decorator should appear exactly once"
    );
    assert_eq!(
        deserialized_block.after_exit(),
        &[after_exit_deco],
        "after_exit decorator should appear exactly once"
    );

    // Verify that the op-indexed decorator is only in the indexed decorator list
    let indexed_decorators: Vec<_> = deserialized_block.indexed_decorator_iter().collect();
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

    // Verify that all decorators() method returns all decorators (this is the full iterator)
    let all_decorators: Vec<_> = deserialized_block.decorators().collect();
    assert_eq!(all_decorators.len(), 3, "decorators() should return all 3 decorators");

    // Verify the order: before_enter, op-indexed, after_exit
    assert_eq!(all_decorators[0].1, before_enter_deco, "First decorator should be before_enter");
    assert_eq!(all_decorators[1].1, op_deco, "Second decorator should be op-indexed");
    assert_eq!(all_decorators[2].1, after_exit_deco, "Third decorator should be after_exit");
}
