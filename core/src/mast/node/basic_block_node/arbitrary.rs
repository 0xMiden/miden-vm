use alloc::{collections::BTreeMap, sync::Arc};
use core::ops::RangeInclusive;

use proptest::{arbitrary::Arbitrary, prelude::*};

use super::*;
use crate::{
    AdviceMap, AssemblyOp, DebugOptions, Decorator, Felt, Kernel, Operation, Program, Word,
    mast::DecoratorId,
};

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

impl Arbitrary for MastForest {
    type Parameters = MastForestParams;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        // BasicBlockNode generation must reference decorator IDs in [0, decorators)
        let bb_params = BasicBlockNodeParams {
            max_decorator_id_u32: params.decorators,
            ..Default::default()
        };

        // 1) Generate a Vec<BasicBlockNode> with length in `params.blocks`
        (
            prop::collection::vec(any_with::<BasicBlockNode>(bb_params), params.blocks.clone()),
            prop::collection::vec(any::<Decorator>(), params.decorators as usize..=params.decorators as usize)
        )
            // 2) Map concrete blocks -> build a concrete MastForest
            .prop_map(move |(blocks, decorators)| {
                let mut forest = MastForest::new();

                // Pre-populate the decorator ID space so referenced IDs are valid.
                // Generate all decorator types for more comprehensive testing
                for decorator in decorators {
                    forest
                        .add_decorator(decorator)
                        .expect("Failed to add decorator");
                }

                // Insert the generated blocks into the forest
                for block in blocks {
                    let node_id = forest.add_node(block).expect("Failed to add block");
                    forest.make_root(node_id);
                }

                forest
            }).boxed()
    }
}

// ---------- Arbitrary implementations for missing types ----------

impl Arbitrary for DebugOptions {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(DebugOptions::StackAll),
            any::<u8>().prop_map(DebugOptions::StackTop),
            Just(DebugOptions::MemAll),
            (any::<u32>(), any::<u32>())
                .prop_map(|(start, end)| DebugOptions::MemInterval(start, end)),
            (any::<u16>(), any::<u16>(), any::<u16>()).prop_map(|(start, end, num_locals)| {
                DebugOptions::LocalInterval(start, end, num_locals)
            }),
            any::<u16>().prop_map(DebugOptions::AdvStackTop),
        ]
        .boxed()
    }
}

impl Arbitrary for AssemblyOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<bool>(),
            prop::collection::vec(any::<char>(), 1..=20)
                .prop_map(|chars| chars.into_iter().collect()),
            prop::collection::vec(any::<char>(), 1..=20)
                .prop_map(|chars| chars.into_iter().collect()),
            any::<u8>(),
            any::<bool>(),
        )
            .prop_map(|(has_location, context_name, op, num_cycles, should_break)| {
                use miden_debug_types::{ByteIndex, Location, Uri};

                let location = if has_location {
                    Some(Location::new(Uri::new("dummy.rs"), ByteIndex(0), ByteIndex(0)))
                } else {
                    None
                };

                AssemblyOp::new(location, context_name, num_cycles, op, should_break)
            })
            .boxed()
    }
}

impl Arbitrary for Decorator {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any_with::<AssemblyOp>(()).prop_map(Decorator::AsmOp),
            any_with::<DebugOptions>(()).prop_map(Decorator::Debug),
            any::<u32>().prop_map(Decorator::Trace),
        ]
        .boxed()
    }
}

impl Arbitrary for AdviceMap {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Strategy for generating Word keys
        let word_strategy = prop_oneof![
            Just(Word::default()),
            any::<[u64; 4]>().prop_map(|[a, b, c, d]| Word::new([
                Felt::new(a),
                Felt::new(b),
                Felt::new(c),
                Felt::new(d)
            ])),
        ];

        // Strategy for generating Arc<[Felt]> values
        let felt_array_strategy = prop::collection::vec(any::<u64>(), 1..=4).prop_map(|vals| {
            let felts: Arc<[Felt]> = vals.into_iter().map(Felt::new).collect();
            felts
        });

        // Strategy for generating map entries
        let entry_strategy = (word_strategy, felt_array_strategy);

        // Strategy for generating the map itself (0 to 10 entries)
        prop::collection::vec(entry_strategy, 0..=10)
            .prop_map(|entries| {
                let mut map = BTreeMap::new();
                for (key, value) in entries {
                    map.insert(key, value);
                }
                AdviceMap::from(map)
            })
            .boxed()
    }
}

impl Arbitrary for Program {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Create a simple strategy that generates a basic block and creates a program from it
        any_with::<BasicBlockNode>(BasicBlockNodeParams {
            max_ops_len: 5, // Keep it small
            max_pairs: 2,   // Fewer decorators
            max_decorator_id_u32: 5,
        })
        .prop_map(|node| {
            use alloc::sync::Arc;

            use crate::Program;

            // Create a new MastForest
            let mut forest = MastForest::new();

            // Add some basic decorators
            for i in 0..5 {
                let decorator = Decorator::Trace(i as u32);
                forest.add_decorator(decorator).expect("Failed to add decorator");
            }

            // Add the node to the forest
            let node_id = forest.add_node(node).expect("Failed to add node");

            // Since we added a node, it should be available as a procedure root
            // If not, we need to make it a root manually
            let entrypoint = if forest.num_procedures() > 0 {
                forest.procedure_roots()[0]
            } else {
                // Make the node a root manually
                forest.make_root(node_id);
                // After making it a root, it should be a procedure
                if forest.num_procedures() == 0 {
                    panic!("Failed to create a valid procedure from node");
                }
                forest.procedure_roots()[0]
            };

            Program::new(Arc::new(forest), entrypoint)
        })
        .prop_filter("valid entrypoint", |program| {
            // Ensure the generated program has a valid procedure entrypoint
            program.mast_forest().is_procedure_root(program.entrypoint())
        })
        .boxed()
    }
}

impl Arbitrary for Kernel {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Strategy for generating Word vectors
        let word_strategy = any::<[u64; 4]>().prop_map(|[a, b, c, d]| {
            Word::new([Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)])
        });

        // Strategy for generating kernel (0 to 3 words to avoid hitting MAX_NUM_PROCEDURES limit)
        prop::collection::vec(word_strategy, 0..=3)
            .prop_map(|words: Vec<Word>| {
                Kernel::new(&words).expect("Generated kernel should be valid")
            })
            .boxed()
    }
}
