use core::ops::RangeInclusive;

use proptest::{arbitrary::Arbitrary, prelude::*};

use super::*;
use crate::{Decorator, Operation, mast::DecoratorId};

// Strategy for operations without immediate values (non-control flow)
pub fn op_no_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Add),
        Just(Operation::Mul),
        Just(Operation::Neg),
        Just(Operation::Inv),
        Just(Operation::Incr),
        Just(Operation::And),
        Just(Operation::Or),
        Just(Operation::Not),
        Just(Operation::Eq),
        Just(Operation::Eqz),
        Just(Operation::Drop),
        Just(Operation::Pad),
        Just(Operation::Swap),
        Just(Operation::SwapW),
        Just(Operation::SwapW2),
        Just(Operation::SwapW3),
        Just(Operation::SwapDW),
        Just(Operation::MovUp2),
        Just(Operation::MovUp3),
        Just(Operation::MovUp4),
        Just(Operation::MovUp5),
        Just(Operation::MovUp6),
        Just(Operation::MovUp7),
        Just(Operation::MovUp8),
        Just(Operation::MovDn2),
        Just(Operation::MovDn3),
        Just(Operation::MovDn4),
        Just(Operation::MovDn5),
        Just(Operation::MovDn6),
        Just(Operation::MovDn7),
        Just(Operation::MovDn8),
        Just(Operation::CSwap),
        Just(Operation::CSwapW),
        Just(Operation::Dup0),
        Just(Operation::Dup1),
        Just(Operation::Dup2),
        Just(Operation::Dup3),
        Just(Operation::Dup4),
        Just(Operation::Dup5),
        Just(Operation::Dup6),
        Just(Operation::Dup7),
        Just(Operation::Dup9),
        Just(Operation::Dup11),
        Just(Operation::Dup13),
        Just(Operation::Dup15),
        Just(Operation::MLoad),
        Just(Operation::MStore),
        Just(Operation::MLoadW),
        Just(Operation::MStoreW),
        Just(Operation::MStream),
        Just(Operation::Pipe),
        Just(Operation::AdvPop),
        Just(Operation::AdvPopW),
        Just(Operation::U32split),
        Just(Operation::U32add),
        Just(Operation::U32sub),
        Just(Operation::U32mul),
        Just(Operation::U32div),
        Just(Operation::U32and),
        Just(Operation::U32xor),
        Just(Operation::U32add3),
        Just(Operation::U32madd),
        Just(Operation::FmpAdd),
        Just(Operation::FmpUpdate),
        Just(Operation::SDepth),
        Just(Operation::Caller),
        Just(Operation::Clk),
        Just(Operation::Emit),
        Just(Operation::Ext2Mul),
        Just(Operation::Expacc),
        Just(Operation::HPerm),
        // Note: We exclude Assert here because it has an immediate value (error code)
    ]
}

// Strategy for operations with immediate values
pub fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    use crate::mast::Felt;
    prop_oneof![any::<u64>().prop_map(Felt::new).prop_map(Operation::Push)]
}

// Strategy for all non-control flow operations
pub fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy(),]
}

// Strategy for sequences of operations
pub fn op_non_control_sequence_strategy(
    max_length: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

// ---------- Parameters ----------

/// Parameters for generating BasicBlockNode instances
#[derive(Clone, Debug)]
pub struct BasicBlockNodeParams {
    /// Maximum number of operations in a generated basic block
    pub max_ops_len: usize,
    /// Maximum number of decorator pairs in a generated basic block
    pub max_pairs: usize,
    /// Maximum value for decorator IDs (u32)
    pub max_decorator_id_u32: u32,
}

impl Default for BasicBlockNodeParams {
    fn default() -> Self {
        Self {
            max_ops_len: 32,
            max_pairs: 8,
            max_decorator_id_u32: 10,
        }
    }
}

// ---------- DecoratorId strategy ----------

/// Strategy for generating DecoratorId values
pub fn decorator_id_strategy(max_id: u32) -> impl Strategy<Value = DecoratorId> {
    // max_id == 0 would be degenerate; clamp to at least 1
    let upper = core::cmp::max(1, max_id);
    (0..upper).prop_map(DecoratorId::new_unchecked)
}

// ---------- Decorator pairs strategy ----------

/// Strategy for generating decorator pairs (usize, DecoratorId)
pub fn decorator_pairs_strategy(
    ops_len: usize,
    max_id: u32,
    max_pairs: usize,
) -> impl Strategy<Value = Vec<(usize, DecoratorId)>> {
    // indices in [0, ops_len] inclusive; size 0..=max_pairs
    // Generate, then sort by index to match validation expectations
    prop::collection::vec((0..=ops_len, decorator_id_strategy(max_id)), 0..=max_pairs).prop_map(
        |mut v| {
            v.sort_by_key(|(i, _)| *i);
            v
        },
    )
}

// ---------- Arbitrary for BasicBlockNode ----------

impl Arbitrary for BasicBlockNode {
    type Parameters = BasicBlockNodeParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        // ensure at least 1 op to satisfy BasicBlockNode::new
        (op_non_control_sequence_strategy(p.max_ops_len),)
            .prop_flat_map(move |(ops,)| {
                let ops_len = ops.len().max(1); // defensive; strategy should ensure ≥1
                decorator_pairs_strategy(ops_len, p.max_decorator_id_u32, p.max_pairs)
                    .prop_map(move |decorators| (ops.clone(), decorators))
            })
            .prop_filter_map("non-empty ops", |(ops, decorators)| {
                if ops.is_empty() { None } else { Some((ops, decorators)) }
            })
            .prop_map(|(ops, decorators)| {
                // BasicBlockNode::new will adjust indices for padding and set be/ae empty.
                BasicBlockNode::new(ops, decorators)
                    .expect("non-empty ops; new() only errs on empty ops")
            })
            .boxed()
    }
}

// ---------- Optional: MastForest strategy (behind feature gate) ----------

/// Parameters for generating MastForest instances
#[derive(Clone, Debug)]
pub struct MastForestParams {
    /// Number of decorators to generate
    pub decorators: u32,
    /// Range of number of blocks to generate
    pub blocks: RangeInclusive<usize>,
}

impl Default for MastForestParams {
    fn default() -> Self {
        Self { decorators: 10, blocks: 1..=10 }
    }
}

/// Strategy for generating MastForest instances
pub fn mast_forest_strategy(params: MastForestParams) -> impl Strategy<Value = MastForest> {
    // BasicBlockNode generation must reference decorator IDs in [0, decorators)
    let bb_params = BasicBlockNodeParams {
        max_decorator_id_u32: params.decorators,
        ..Default::default()
    };

    // 1) Generate a Vec<BasicBlockNode> with length in `params.blocks`
    prop::collection::vec(any_with::<BasicBlockNode>(bb_params), params.blocks.clone())
        // 2) Map concrete blocks -> build a concrete MastForest
        .prop_map(move |blocks| {
            let mut forest = MastForest::new();

            // Pre-populate the decorator ID space so referenced IDs are valid.
            // TODO: Replace Decorator::Trace(i) with Arbitrary for Decorator
            for i in 0..params.decorators {
                forest
                    .add_decorator(Decorator::Trace(i))
                    .expect("Failed to add decorator");
            }

            // Insert the generated blocks into the forest
            for block in blocks {
                forest.add_node(block).expect("Failed to add block");
            }

            forest
        })
}

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(p: Self::Parameters) -> Self::Strategy {
        mast_forest_strategy(p).boxed()
    }
}
